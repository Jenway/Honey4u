from __future__ import annotations

import argparse
import asyncio
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from honey.consensus.dumbo.core import DumboBFT
from honey.crypto import ecdsa, pke, sig
from honey.network.transport import QueueTransport
from honey.support.params import CommonParams, CryptoParams, HBConfig


@dataclass(frozen=True)
class Point:
    batch_size: int
    rounds: int
    warmup_rounds: int
    measured_elapsed_seconds: float
    measured_tps: float
    measured_delivery_ratio: float
    measured_delivered_transactions: int
    measured_proposed_transactions: int
    measured_round_latency_p95_ms: float
    reusable_entries_max: int
    consumed_entries_max: int


class RecordingDumbo(DumboBFT):
    pass


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    rank = (percentile / 100.0) * (len(values) - 1)
    lower = int(rank)
    upper = min(lower + 1, len(values) - 1)
    weight = rank - lower
    return values[lower] * (1.0 - weight) + values[upper] * weight


async def _run_once(
    *,
    sid: str,
    num_nodes: int,
    faulty: int,
    batch_size: int,
    rounds: int,
    round_timeout: float,
    pool_reuse: bool,
    pool_refs: bool,
    pool_fetch: bool,
    pool_grace_ms: int,
) -> Point:
    coin_pk, coin_sks = sig.generate(num_nodes, faulty + 1)
    proof_pk, proof_sks = sig.generate(num_nodes, num_nodes - faulty)
    enc_pk, enc_sks = pke.generate(num_nodes, faulty + 1)
    ecdsa_pks, ecdsa_sks = ecdsa.generate(num_nodes)

    transports = [QueueTransport() for _ in range(num_nodes)]
    nodes: list[RecordingDumbo] = []
    tx_per_node = batch_size * rounds

    for pid in range(num_nodes):
        common = CommonParams(sid=sid, pid=pid, N=num_nodes, f=faulty, leader=0)
        crypto = CryptoParams(
            sig_pk=coin_pk,
            sig_sk=coin_sks[pid],
            enc_pk=enc_pk,
            enc_sk=enc_sks[pid],
            ecdsa_pks=ecdsa_pks,
            ecdsa_sk=ecdsa_sks[pid],
            proof_sig_pk=proof_pk,
            proof_sig_sk=proof_sks[pid],
        )
        config = HBConfig(
            batch_size=batch_size,
            max_rounds=rounds,
            round_timeout=round_timeout,
            log_level="ERROR",
            enable_broadcast_pool_reuse=pool_reuse,
            enable_pool_reference_proposals=pool_refs,
            enable_pool_fetch_fallback=pool_fetch,
            pool_grace_ms=pool_grace_ms,
        )
        node = RecordingDumbo(common, crypto, transports[pid], config=config)
        for tx_index in range(tx_per_node):
            node.submit_tx_json_str(
                f"Dummy TX node-{pid}-tx-{tx_index}",
                track_latency=True,
                submitted_at_ns=time.time_ns(),
            )
        nodes.append(node)

    async def router() -> None:
        while True:
            pending = []
            for pid in range(num_nodes):
                try:
                    while True:
                        outbound = transports[pid].outbound.get_nowait()
                        pending.append((pid, outbound.recipient, outbound.envelope))
                except asyncio.QueueEmpty:
                    pass
            for sender, recipient, envelope in pending:
                transports[recipient].deliver_nowait(sender, envelope)
            await asyncio.sleep(0.0005)

    router_task = asyncio.create_task(router())
    start = time.perf_counter()
    try:
        await asyncio.wait_for(
            asyncio.gather(*(node.run() for node in nodes)), timeout=round_timeout * rounds * 2
        )
    finally:
        router_task.cancel()
        try:
            await router_task
        except asyncio.CancelledError:
            pass
    _elapsed = time.perf_counter() - start

    warmup_rounds = 1 if rounds > 1 else 0
    measured_round_latencies = [
        lat for node in nodes for lat in node.round_latencies[warmup_rounds:]
    ]
    measured_elapsed_seconds = max(
        (sum(node.round_latencies[warmup_rounds:]) for node in nodes), default=0.0
    )
    measured_proposed_transactions = num_nodes * min(
        sum(node.round_proposed_counts[warmup_rounds:]) for node in nodes
    )
    measured_delivered_transactions = min(
        sum(node.round_delivered_counts[warmup_rounds:]) for node in nodes
    )
    measured_delivery_ratio = (
        measured_delivered_transactions / measured_proposed_transactions
        if measured_proposed_transactions
        else 0.0
    )
    measured_tps = (
        measured_delivered_transactions / measured_elapsed_seconds
        if measured_elapsed_seconds
        else 0.0
    )
    reusable_entries_max = max(node.mempool.stats().get("reusable", 0) for node in nodes)
    consumed_entries_max = max(node.mempool.stats().get("consumed", 0) for node in nodes)

    return Point(
        batch_size=batch_size,
        rounds=rounds,
        warmup_rounds=warmup_rounds,
        measured_elapsed_seconds=measured_elapsed_seconds,
        measured_tps=measured_tps,
        measured_delivery_ratio=measured_delivery_ratio,
        measured_delivered_transactions=measured_delivered_transactions,
        measured_proposed_transactions=measured_proposed_transactions,
        measured_round_latency_p95_ms=_percentile(
            sorted(x * 1000.0 for x in measured_round_latencies), 95
        ),
        reusable_entries_max=reusable_entries_max,
        consumed_entries_max=consumed_entries_max,
    )


async def _main_async(args: argparse.Namespace) -> dict:
    batches = [int(part.strip()) for part in args.sweep_batches.split(",") if part.strip()]
    protocols = {
        "baseline": dict(pool_reuse=False, pool_refs=False, pool_fetch=False),
        "pool_reuse": dict(pool_reuse=True, pool_refs=True, pool_fetch=True),
    }
    payload = {
        "meta": {
            "num_nodes": args.nodes,
            "faulty": args.faulty,
            "rounds": args.rounds,
            "round_timeout": args.round_timeout,
            "sweep_batches": batches,
            "mode": "queue_transport_single_process",
        },
        "protocols": {},
    }
    for label, cfg in protocols.items():
        points = []
        for batch_size in batches:
            point = await _run_once(
                sid=f"bench:queue:{label}:{args.nodes}:{batch_size}:{int(time.time())}",
                num_nodes=args.nodes,
                faulty=args.faulty,
                batch_size=batch_size,
                rounds=args.rounds,
                round_timeout=args.round_timeout,
                pool_reuse=cfg["pool_reuse"],
                pool_refs=cfg["pool_refs"],
                pool_fetch=cfg["pool_fetch"],
                pool_grace_ms=args.pool_grace_ms,
            )
            points.append(asdict(point))
        payload["protocols"][label] = {"points": points}
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Queue-transport Dumbo benchmark for pool reuse")
    parser.add_argument("--nodes", type=int, default=4)
    parser.add_argument("--faulty", type=int, default=1)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--round-timeout", type=float, default=15.0)
    parser.add_argument("--sweep-batches", type=str, default="1,2,4,8,16")
    parser.add_argument("--pool-grace-ms", type=int, default=50)
    parser.add_argument("--output-json", type=str, default=None)
    args = parser.parse_args()

    payload = asyncio.run(_main_async(args))
    if args.output_json:
        Path(args.output_json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
