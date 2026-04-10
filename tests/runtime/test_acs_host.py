from __future__ import annotations

import json
import time
from typing import cast

import honey_native
from honey_acs.host_bridge import PersistentAcsHost, build_persistent_acs_host
from honey_acs.messages import ProtocolEnvelope
from honey_acs.subprotocols.provable_reliable_broadcast import (
    deserialize_prbc_proof,
    validate_prbc_proof,
)


def _drain_until_round_complete(
    hosts: list[PersistentAcsHost],
    *,
    round_id: int,
    expected_proposals_per_host: int | None = None,
    timeout: float = 20.0,
) -> tuple[list[tuple[str, ...]], list[dict[str, dict[str, object]]]]:
    decisions: list[tuple[str, ...] | None] = [None] * len(hosts)
    proposals_by_host: list[dict[str, dict[str, object]]] = [{} for _ in hosts]
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        progressed = False
        for pid, host in enumerate(hosts):
            host.begin_pull_outbound_wire_batch(512)
            for event in host.finish_pull_outbound_wire_batch():
                progressed = True
                kind = str(event["kind"])
                if kind in {"send", "broadcast"}:
                    sender, envelope = cast(
                        tuple[int, ProtocolEnvelope],
                        honey_native.decode_protocol_envelope_py(cast(bytes, event["payload"])),
                    )
                    assert sender == pid
                    assert envelope.round_id == round_id
                    payload = cast(bytes, event["payload"])
                    if kind == "send":
                        recipient = cast(int, event["recipient"])
                        hosts[recipient].push_inbound_wire_batch([payload])
                    else:
                        include_self = bool(event.get("include_self", True))
                        recipients = (
                            range(len(hosts))
                            if include_self
                            else (
                                recipient for recipient in range(len(hosts)) if recipient != sender
                            )
                        )
                        for recipient in recipients:
                            hosts[recipient].push_inbound_wire_batch([payload])
                    continue
                if kind == "proposal_ready":
                    proposal_id = cast(str, event["proposal_id"])
                    proposals_by_host[pid][proposal_id] = event
                    continue
                if kind == "decision":
                    decisions[pid] = tuple(cast(list[str], event["selected_proposal_ids"]))
                    continue
                if kind == "failure":
                    raise AssertionError(
                        f"ACS host {pid} failed in round {round_id}: "
                        f"{event['exception_type']}: {event['error']}"
                    )
                raise AssertionError(f"unexpected ACS host event kind: {kind}")

        enough_proposals = expected_proposals_per_host is None or all(
            len(proposals) >= expected_proposals_per_host for proposals in proposals_by_host
        )
        if all(decision is not None for decision in decisions) and enough_proposals:
            return cast(list[tuple[str, ...]], decisions), proposals_by_host
        if not progressed:
            time.sleep(0.001)

    raise AssertionError(f"timed out waiting for ACS host round {round_id} completion")


def _selected_proposers(
    selected_proposal_ids: tuple[str, ...],
    proposals: dict[str, dict[str, object]],
) -> tuple[int, ...]:
    return tuple(
        cast(int, proposals[proposal_id]["proposer"]) for proposal_id in selected_proposal_ids
    )


def _build_hosts(
    protocol: str,
    num_nodes: int,
    faulty: int,
    *,
    config: dict[str, object] | None = None,
) -> list[PersistentAcsHost]:
    payloads = (
        honey_native.generate_dumbo_crypto_payloads_json(num_nodes, faulty)
        if protocol == "dumbo"
        else honey_native.generate_hb_crypto_payloads_json(num_nodes, faulty)
    )
    return _build_hosts_from_payloads(
        protocol,
        payloads,
        num_nodes=num_nodes,
        faulty=faulty,
        config=config,
    )


def _build_hosts_from_payloads(
    protocol: str,
    payloads: list[str],
    *,
    num_nodes: int,
    faulty: int,
    config: dict[str, object] | None = None,
) -> list[PersistentAcsHost]:
    hosts: list[PersistentAcsHost] = []
    for pid, payload in enumerate(payloads):
        decoded = cast(dict[str, object], json.loads(payload))
        hosts.append(
            build_persistent_acs_host(
                protocol=cast(str, protocol),
                pid=pid,
                nodes=num_nodes,
                faulty=faulty,
                sig_pk=bytes.fromhex(cast(str, decoded["sig_pk"])),
                sig_sk=bytes.fromhex(cast(str, decoded["sig_sk"])),
                ecdsa_pks=[bytes.fromhex(value) for value in cast(list[str], decoded["ecdsa_pks"])],
                ecdsa_sk=bytes.fromhex(cast(str, decoded["ecdsa_sk"])),
                proof_sig_pk=(
                    bytes.fromhex(cast(str, decoded["proof_sig_pk"]))
                    if protocol == "dumbo"
                    else None
                ),
                proof_sig_sk=(
                    bytes.fromhex(cast(str, decoded["proof_sig_sk"]))
                    if protocol == "dumbo"
                    else None
                ),
                config_json=json.dumps(config) if config is not None else None,
            )
        )
    return hosts


def test_persistent_hb_acs_host_reuses_worker_threads_across_rounds() -> None:
    num_nodes = 4
    faulty = 1
    hosts = _build_hosts("hb", num_nodes, faulty)

    try:
        worker_idents = [cast(int, host.stats()["worker_ident"]) for host in hosts]
        assert len(set(worker_idents)) == num_nodes

        for round_id in range(2):
            for pid, host in enumerate(hosts):
                host.start_round(
                    round_id=round_id,
                    sid=f"test:acs-host:hb:{round_id}:",
                    proposal_input=f"hb-round-{round_id}-node-{pid}".encode(),
                )

            decisions, proposals_by_host = _drain_until_round_complete(hosts, round_id=round_id)
            assert len(set(decisions)) == 1
            assert _selected_proposers(decisions[0], proposals_by_host[0]) == tuple(
                range(num_nodes)
            )
            assert [cast(int, host.stats()["worker_ident"]) for host in hosts] == worker_idents
    finally:
        for host in hosts:
            host.shutdown()


def test_persistent_dumbo_acs_host_reaches_consistent_decision() -> None:
    num_nodes = 4
    faulty = 1
    hosts = _build_hosts("dumbo", num_nodes, faulty)

    try:
        for pid, host in enumerate(hosts):
            host.start_round(
                round_id=0,
                sid="test:acs-host:dumbo:",
                proposal_input=f"dumbo-node-{pid}".encode(),
            )

        decisions, proposals_by_host = _drain_until_round_complete(hosts, round_id=0)
        assert len(set(decisions)) == 1
        decided = decisions[0]
        selected_proposers = _selected_proposers(decided, proposals_by_host[0])
        assert len(selected_proposers) >= num_nodes - faulty
        assert all(0 <= pid < num_nodes for pid in selected_proposers)
    finally:
        for host in hosts:
            host.shutdown()


def test_persistent_hb_acs_host_ignores_legacy_output_mode_in_config_json() -> None:
    num_nodes = 4
    faulty = 1
    hosts = _build_hosts("hb", num_nodes, faulty, config={"output_mode": "payloads"})

    try:
        for pid, host in enumerate(hosts):
            host.start_round(
                round_id=0,
                sid="test:acs-host:hb:legacy-output-mode:",
                proposal_input=f"hb-round-0-node-{pid}".encode(),
            )

        decisions, proposals_by_host = _drain_until_round_complete(hosts, round_id=0)
        assert len(set(decisions)) == 1
        assert _selected_proposers(decisions[0], proposals_by_host[0]) == tuple(range(num_nodes))
    finally:
        for host in hosts:
            host.shutdown()


def test_persistent_hb_acs_host_emits_proposal_ready_events_on_main_event_stream() -> None:
    num_nodes = 4
    faulty = 1
    hosts = _build_hosts(
        "hb",
        num_nodes,
        faulty,
        config={"broadcast_mempool_backend": "rust", "pool_mempool_max": 64},
    )

    try:
        for pid, host in enumerate(hosts):
            host.start_round(
                round_id=0,
                sid="test:acs-host:hb:proposal-ready-main-event-stream:",
                proposal_input=f"hb-round-0-node-{pid}".encode(),
            )

        decisions, proposals_by_host = _drain_until_round_complete(
            hosts,
            round_id=0,
            expected_proposals_per_host=num_nodes,
        )
        assert len(set(decisions)) == 1
        assert _selected_proposers(decisions[0], proposals_by_host[0]) == tuple(range(num_nodes))

        for proposals in proposals_by_host:
            assert len(proposals) == num_nodes
            assert {cast(int, event["proposer"]) for event in proposals.values()} == set(
                range(num_nodes)
            )
            assert all(cast(bytes, event["payload"]) for event in proposals.values())
            assert all(len(cast(bytes, event["digest"])) == 32 for event in proposals.values())
            assert all(len(cast(bytes, event["certificate"])) == 32 for event in proposals.values())
    finally:
        for host in hosts:
            host.shutdown()


def test_persistent_hb_acs_host_supports_prbc_broadcast_mode() -> None:
    num_nodes = 4
    faulty = 1
    round_sid = "test:acs-host:hb:prbc:"
    payloads = honey_native.generate_hb_crypto_payloads_json(num_nodes, faulty)
    decoded_payloads = [cast(dict[str, object], json.loads(payload)) for payload in payloads]
    ecdsa_pks = [
        bytes.fromhex(value) for value in cast(list[str], decoded_payloads[0]["ecdsa_pks"])
    ]
    hosts = _build_hosts_from_payloads(
        "hb",
        payloads,
        num_nodes=num_nodes,
        faulty=faulty,
        config={"hb_broadcast_protocol": "prbc"},
    )

    try:
        for pid, host in enumerate(hosts):
            host.start_round(
                round_id=0,
                sid=round_sid,
                proposal_input=f"hb-prbc-round-0-node-{pid}".encode(),
            )

        decisions, proposals_by_host = _drain_until_round_complete(
            hosts,
            round_id=0,
            expected_proposals_per_host=num_nodes,
        )
        assert len(set(decisions)) == 1
        assert _selected_proposers(decisions[0], proposals_by_host[0]) == tuple(range(num_nodes))

        for proposals in proposals_by_host:
            assert len(proposals) == num_nodes
            for event in proposals.values():
                proposer = cast(int, event["proposer"])
                digest = cast(bytes, event["digest"])
                certificate = cast(bytes, event["certificate"])
                assert len(certificate) > len(digest)
                proof = deserialize_prbc_proof(certificate)
                assert proof.roothash == digest
                assert validate_prbc_proof(
                    f"{round_sid}CSRBC{proposer}",
                    num_nodes,
                    faulty,
                    ecdsa_pks,
                    proof,
                )
    finally:
        for host in hosts:
            host.shutdown()


def test_persistent_dumbo_acs_host_exposes_selected_proposals_via_proposal_ready_events() -> None:
    num_nodes = 4
    faulty = 1
    proposals = [f"dumbo-payload-node-{pid}".encode() for pid in range(num_nodes)]
    hosts = _build_hosts("dumbo", num_nodes, faulty)

    try:
        for pid, host in enumerate(hosts):
            host.start_round(
                round_id=0,
                sid="test:acs-host:dumbo:proposal-ready:",
                proposal_input=proposals[pid],
            )

        decisions, proposals_by_host = _drain_until_round_complete(hosts, round_id=0)
        assert len(set(decisions)) == 1
        decided = decisions[0]
        selected = [
            (
                cast(int, proposals_by_host[0][proposal_id]["proposer"]),
                cast(bytes, proposals_by_host[0][proposal_id]["payload"]),
            )
            for proposal_id in decided
        ]
        assert len(selected) >= num_nodes - faulty
        assert all(payload == proposals[pid] for pid, payload in selected)
    finally:
        for host in hosts:
            host.shutdown()
