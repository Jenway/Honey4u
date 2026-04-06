from __future__ import annotations

import time
from typing import Literal, cast

from honey.runtime.acs_host import PersistentAcsHost, build_persistent_acs_host_from_json
from honey.runtime.launch.crypto_material import (
    serialize_dumbo_crypto_payloads_json,
    serialize_hb_crypto_payloads_json,
)


def _drain_until_decisions(
    hosts: list[PersistentAcsHost],
    *,
    round_id: int,
    timeout: float = 20.0,
) -> list[tuple[bytes | None, ...]]:
    decisions: list[tuple[bytes | None, ...] | None] = [None] * len(hosts)
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        progressed = False
        for pid, host in enumerate(hosts):
            for event in host.drain_events(512):
                progressed = True
                kind = str(event["kind"])
                if kind == "send":
                    recipient = int(event["recipient"])
                    hosts[recipient].deliver_decoded(
                        sender=pid,
                        round_id=round_id,
                        channel=cast(str, event["channel"]),
                        instance_id=cast(int | None, event["instance_id"]),
                        message=event["message"],
                    )
                    continue
                if kind == "decision":
                    decisions[pid] = tuple(cast(list[bytes | None], event["values"]))
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
            return cast(list[tuple[bytes | None, ...]], decisions)
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
            values = [f"hb-round-{round_id}-node-{pid}".encode() for pid in range(num_nodes)]
            for pid, host in enumerate(hosts):
                host.start_round(
                    round_id=round_id,
                    sid=f"test:acs-host:hb:{round_id}:",
                    local_input=values[pid],
                )

            decisions = _drain_until_decisions(hosts, round_id=round_id)
            assert len(set(decisions)) == 1
            decided = decisions[0]
            assert tuple(value for value in decided if value is not None) == tuple(values)
            assert [int(host.stats()["worker_ident"]) for host in hosts] == worker_idents
    finally:
        for host in hosts:
            host.shutdown()


def test_persistent_dumbo_acs_host_reaches_consistent_decision() -> None:
    num_nodes = 4
    faulty = 1
    values = [f"dumbo-node-{pid}".encode() for pid in range(num_nodes)]
    hosts = _build_hosts("dumbo", num_nodes, faulty)

    try:
        for pid, host in enumerate(hosts):
            host.start_round(
                round_id=0,
                sid="test:acs-host:dumbo:",
                local_input=values[pid],
            )

        decisions = _drain_until_decisions(hosts, round_id=0)
        assert len(set(decisions)) == 1
        decided = decisions[0]
        assert sum(value is not None for value in decided) >= num_nodes - faulty
        assert all(value is None or value in values for value in decided)
    finally:
        for host in hosts:
            host.shutdown()
