from __future__ import annotations

import time
from typing import Literal, cast

import honey_native
from honey_acs.host_bridge import (
    PersistentAcsHost,
    build_persistent_acs_host_from_json,
)
from honey_acs.host_crypto import (
    serialize_dumbo_crypto_payloads_json,
    serialize_hb_crypto_payloads_json,
)
from honey_acs.messages import ProtocolEnvelope


def _drain_until_decisions(
    hosts: list[PersistentAcsHost],
    *,
    round_id: int,
    decision_key: Literal["selected_pids", "selected_payloads"] = "selected_pids",
    timeout: float = 20.0,
) -> list[tuple[object, ...]]:
    decisions: list[tuple[object, ...] | None] = [None] * len(hosts)
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        progressed = False
        for pid, host in enumerate(hosts):
            host.begin_pull_outbound_wire_batch(512)
            for event in host.finish_pull_outbound_wire_batch():
                progressed = True
                kind = str(event["kind"])
                if kind == "send":
                    recipient = int(event["recipient"])
                    sender, envelope = cast(
                        tuple[int, ProtocolEnvelope],
                        honey_native.decode_protocol_envelope_py(cast(bytes, event["payload"])),
                    )
                    assert sender == pid
                    assert envelope.round_id == round_id
                    hosts[recipient].push_inbound_wire_batch([cast(bytes, event["payload"])])
                    continue
                if kind == "decision":
                    decisions[pid] = tuple(cast(list[object], event[decision_key]))
                    continue
                if kind == "carryovers":
                    continue
                if kind == "failure":
                    raise AssertionError(
                        f"ACS host {pid} failed in round {round_id}: "
                        f"{event['exception_type']}: {event['error']}"
                    )
                raise AssertionError(f"unexpected ACS host event kind: {kind}")

        if all(decision is not None for decision in decisions):
            return cast(list[tuple[object, ...]], decisions)
        if not progressed:
            time.sleep(0.001)

    raise AssertionError(f"timed out waiting for ACS host decisions in round {round_id}")


def _build_hosts(
    protocol: Literal["hb", "dumbo"],
    num_nodes: int,
    faulty: int,
    *,
    output_mode: Literal["selected_pids", "payloads"] = "selected_pids",
) -> list[PersistentAcsHost]:
    payloads = (
        serialize_dumbo_crypto_payloads_json(num_nodes, faulty)
        if protocol == "dumbo"
        else serialize_hb_crypto_payloads_json(num_nodes, faulty)
    )
    return [
        build_persistent_acs_host_from_json(
            protocol=protocol,
            pid=pid,
            nodes=num_nodes,
            faulty=faulty,
            crypto_json=payload,
            output_mode=output_mode,
        )
        for pid, payload in enumerate(payloads)
    ]


def test_persistent_hb_acs_host_reuses_worker_threads_across_rounds() -> None:
    num_nodes = 4
    faulty = 1
    hosts = _build_hosts("hb", num_nodes, faulty)

    try:
        worker_idents = [int(host.stats()["worker_ident"]) for host in hosts]
        assert len(set(worker_idents)) == num_nodes

        for round_id in range(2):
            for pid, host in enumerate(hosts):
                host.start_round(
                    round_id=round_id,
                    sid=f"test:acs-host:hb:{round_id}:",
                    proposal_input=f"hb-round-{round_id}-node-{pid}".encode(),
                )

            decisions = cast(
                list[tuple[int, ...]], _drain_until_decisions(hosts, round_id=round_id)
            )
            assert len(set(decisions)) == 1
            assert decisions[0] == tuple(range(num_nodes))
            assert [int(host.stats()["worker_ident"]) for host in hosts] == worker_idents
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

        decisions = cast(list[tuple[int, ...]], _drain_until_decisions(hosts, round_id=0))
        assert len(set(decisions)) == 1
        decided = decisions[0]
        assert len(decided) >= num_nodes - faulty
        assert all(0 <= pid < num_nodes for pid in decided)
    finally:
        for host in hosts:
            host.shutdown()


def test_persistent_hb_acs_host_can_emit_payload_decisions() -> None:
    num_nodes = 4
    faulty = 1
    proposals = [f"hb-payload-node-{pid}".encode() for pid in range(num_nodes)]
    hosts = _build_hosts("hb", num_nodes, faulty, output_mode="payloads")

    try:
        for pid, host in enumerate(hosts):
            host.start_round(
                round_id=0,
                sid="test:acs-host:hb:payloads:",
                proposal_input=proposals[pid],
            )

        decisions = cast(
            list[tuple[bytes | None, ...]],
            _drain_until_decisions(hosts, round_id=0, decision_key="selected_payloads"),
        )
        assert len(set(decisions)) == 1
        assert decisions[0] == tuple(proposals)
    finally:
        for host in hosts:
            host.shutdown()


def test_persistent_dumbo_acs_host_can_emit_payload_decisions() -> None:
    num_nodes = 4
    faulty = 1
    proposals = [f"dumbo-payload-node-{pid}".encode() for pid in range(num_nodes)]
    hosts = _build_hosts("dumbo", num_nodes, faulty, output_mode="payloads")

    try:
        for pid, host in enumerate(hosts):
            host.start_round(
                round_id=0,
                sid="test:acs-host:dumbo:payloads:",
                proposal_input=proposals[pid],
            )

        decisions = cast(
            list[tuple[bytes | None, ...]],
            _drain_until_decisions(hosts, round_id=0, decision_key="selected_payloads"),
        )
        assert len(set(decisions)) == 1
        decided = decisions[0]
        selected = [(pid, payload) for pid, payload in enumerate(decided) if payload is not None]
        assert len(selected) >= num_nodes - faulty
        assert all(payload == proposals[pid] for pid, payload in selected)
    finally:
        for host in hosts:
            host.shutdown()
