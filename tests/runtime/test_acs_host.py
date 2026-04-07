from __future__ import annotations

import time
from typing import Literal, cast

from honey_runtime.drivers.crypto_material import (
    serialize_dumbo_crypto_payloads_json,
    serialize_hb_crypto_payloads_json,
)
from honey_runtime.drivers.python_acs_bridge import (
    PersistentAcsHost,
    build_persistent_acs_host_from_json,
)


def _drain_until_decisions(
    hosts: list[PersistentAcsHost],
    *,
    round_id: int,
    timeout: float = 20.0,
) -> list[tuple[int, ...]]:
    decisions: list[tuple[int, ...] | None] = [None] * len(hosts)
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        progressed = False
        for pid, host in enumerate(hosts):
            for event in host.pull_outbound_batch(512):
                progressed = True
                kind = str(event["kind"])
                if kind == "send":
                    recipient = int(event["recipient"])
                    hosts[recipient].push_inbound_batch(
                        [
                            (
                                pid,
                                round_id,
                                cast(str, event["channel"]),
                                cast(int | None, event["instance_id"]),
                                event["message"],
                            )
                        ]
                    )
                    continue
                if kind == "decision":
                    decisions[pid] = tuple(cast(list[int], event["selected_pids"]))
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
            return cast(list[tuple[int, ...]], decisions)
        if not progressed:
            time.sleep(0.001)

    raise AssertionError(f"timed out waiting for ACS host decisions in round {round_id}")


def _build_hosts(
    protocol: Literal["hb", "dumbo"], num_nodes: int, faulty: int
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

            decisions = _drain_until_decisions(hosts, round_id=round_id)
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

        decisions = _drain_until_decisions(hosts, round_id=0)
        assert len(set(decisions)) == 1
        decided = decisions[0]
        assert len(decided) >= num_nodes - faulty
        assert all(0 <= pid < num_nodes for pid in decided)
    finally:
        for host in hosts:
            host.shutdown()
