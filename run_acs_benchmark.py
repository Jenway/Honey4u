from __future__ import annotations

import argparse
import asyncio
import json
import logging
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import fmean
from typing import Any

from honey.acs.bkr93 import CSParams, run_bkr93_acs
from honey.acs.dumbo_acs import DumboACSParams, dumbo_acs
from honey.data.broadcast_mempool import BroadcastMempool
from honey.runtime.router import RoundProtocolRouter
from network.crypto_material import build_dumbo_materials, build_materials
from network.transport import QueueTransport


@dataclass(frozen=True)
class LatencyStats:
    sample_count: int
    mean_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float


@dataclass(frozen=True)
class ACSBenchmarkSummary:
    protocol: str
    num_nodes: int
    faulty: int
    batch_size: int
    rounds: int
    warmup_rounds: int
    payload_bytes_per_node: int
    measured_rounds: int
    measured_elapsed_seconds: float
    measured_selected_proposals: int
    measured_proposed_proposals: int
    measured_delivery_ratio: float
    measured_tps: float
    measured_offered_tps: float
    measured_round_latency: LatencyStats
    measured_decision_latency: LatencyStats


@dataclass(frozen=True)
class ACSRoundResult:
    elapsed_seconds: float
    selected_proposals: int
    proposed_proposals: int
    decision_latencies_seconds: tuple[float, ...]
    payload_bytes_per_node: int


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark BKR93 ACS vs DumboACS")
    parser.add_argument("--protocol", choices=("bkr93", "dumbo", "both"), default="both")
    parser.add_argument("--nodes", type=int, default=10)
    parser.add_argument("--faulty", type=int, default=None)
    parser.add_argument("--batch-size", type=int, default=8, help="transactions per node per round")
    parser.add_argument(
        "--sweep-batches",
        type=str,
        default=None,
        help="comma-separated batch sizes, e.g. 4,8,16,32",
    )
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--warmup-rounds", type=int, default=1)
    parser.add_argument(
        "--tx-bytes",
        type=int,
        default=32,
        help="approximate bytes per synthetic transaction payload",
    )
    parser.add_argument("--round-timeout", type=float, default=20.0)
    parser.add_argument("--output-json", type=str, default=None)
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def _parse_batch_values(raw: str | None, fallback: int) -> list[int]:
    if not raw:
        return [fallback]
    values = [int(part.strip()) for part in raw.split(",") if part.strip()]
    if not values:
        raise ValueError("--sweep-batches must contain at least one positive integer")
    if any(value <= 0 for value in values):
        raise ValueError("--sweep-batches only accepts positive integers")
    return values


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


def _build_latency_stats(samples_seconds: list[float]) -> LatencyStats:
    if not samples_seconds:
        return LatencyStats(0, 0.0, 0.0, 0.0, 0.0, 0.0)

    samples_ms = sorted(sample * 1000.0 for sample in samples_seconds)
    return LatencyStats(
        sample_count=len(samples_ms),
        mean_ms=fmean(samples_ms),
        p50_ms=_percentile(samples_ms, 50),
        p95_ms=_percentile(samples_ms, 95),
        p99_ms=_percentile(samples_ms, 99),
        max_ms=samples_ms[-1],
    )


def _encode_batch(pid: int, round_id: int, batch_size: int, tx_bytes: int) -> bytes:
    pad_width = max(0, tx_bytes)
    txs = [
        {
            "node": pid,
            "round": round_id,
            "tx": tx_index,
            "pad": ("x" * pad_width),
        }
        for tx_index in range(batch_size)
    ]
    return json.dumps(txs, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _cancel_tasks(
    tasks: list[asyncio.Task[Any]], keep: set[asyncio.Task[Any]] | None = None
) -> None:
    keep = keep or set()
    for task in tasks:
        if task in keep or task.done():
            continue
        task.cancel()


async def _await_cancelled(
    tasks: list[asyncio.Task[Any]], keep: set[asyncio.Task[Any]] | None = None
) -> None:
    keep = keep or set()
    for task in tasks:
        if task in keep:
            continue
        try:
            await task
        except asyncio.CancelledError:
            pass


def _assert_decisions_agree(decisions: list[tuple[bytes | None, ...]], protocol: str) -> None:
    if not decisions:
        return
    first = decisions[0]
    for decision in decisions[1:]:
        if decision != first:
            raise RuntimeError(
                f"{protocol} benchmark observed divergent ACS decisions across nodes"
            )


async def _run_bkr93_round(
    *,
    sid: str,
    num_nodes: int,
    faulty: int,
    batch_size: int,
    tx_bytes: int,
    round_timeout: float,
    materials: tuple[Any, ...],
) -> ACSRoundResult:
    sig_pk, sig_shares, _enc_pk, _enc_shares, _ecdsa_pks, _ecdsa_sks = materials
    transports = [QueueTransport() for _ in range(num_nodes)]
    payloads = [_encode_batch(pid, 0, batch_size, tx_bytes) for pid in range(num_nodes)]
    payload_bytes_per_node = len(payloads[0]) if payloads else 0

    async def pump() -> None:
        try:
            while True:
                moved = 0
                for sender, transport in enumerate(transports):
                    try:
                        while True:
                            outbound = transport.outbound.get_nowait()
                            transports[outbound.recipient].deliver_nowait(sender, outbound.envelope)
                            moved += 1
                    except asyncio.QueueEmpty:
                        pass
                if moved == 0:
                    await asyncio.sleep(0)
        except asyncio.CancelledError:
            pass

    async def run_node(pid: int, started_at: float) -> tuple[bytes | None, ...]:
        logger = logging.LoggerAdapter(logging.getLogger("bench.bkr93"), extra={"node": pid})
        coin_recvs = [asyncio.Queue() for _ in range(num_nodes)]
        aba_recvs = [asyncio.Queue() for _ in range(num_nodes)]
        rbc_recvs = [asyncio.Queue() for _ in range(num_nodes)]
        tpke_recv: asyncio.Queue = asyncio.Queue()
        output_queue: asyncio.Queue[tuple[bytes | None, ...]] = asyncio.Queue(1)
        my_rbc_input: asyncio.Queue[bytes] = asyncio.Queue(1)
        my_rbc_input.put_nowait(payloads[pid])
        router = RoundProtocolRouter(
            round_id=0,
            num_nodes=num_nodes,
            transport=transports[pid],
            inbound_queue=transports[pid].inbound,
            coin_recvs=coin_recvs,
            aba_recvs=aba_recvs,
            rbc_recvs=rbc_recvs,
            tpke_recv=tpke_recv,
            logger=logger,
        )
        mempool = BroadcastMempool(max_size=num_nodes * 4, expire_rounds=2)
        spawned: list[asyncio.Task[Any]] = []

        async with asyncio.TaskGroup() as task_group:

            def spawn(coro: Any) -> asyncio.Task[Any]:
                task = task_group.create_task(coro)
                spawned.append(task)
                return task

            router_task = spawn(router.recv_dispatcher())
            acs_task = spawn(
                run_bkr93_acs(
                    params=CSParams(sid=sid, pid=pid, N=num_nodes, f=faulty, leader=pid),
                    crypto=type(
                        "BenchCrypto",
                        (),
                        {
                            "sig_pk": sig_pk,
                            "sig_sk": sig_shares[pid],
                        },
                    )(),
                    task_group=task_group,
                    spawn=spawn,
                    router=router,
                    coin_recvs=coin_recvs,
                    aba_recvs=aba_recvs,
                    rbc_recvs=rbc_recvs,
                    mempool=mempool,
                    round_id=0,
                    my_rbc_input=my_rbc_input,
                    output_queue=output_queue,
                    logger=logger,
                )
            )

            decision = await asyncio.wait_for(output_queue.get(), timeout=round_timeout)
            decision_latencies[pid] = time.perf_counter() - started_at
            await acs_task
            _cancel_tasks(spawned, keep={acs_task})
            _cancel_tasks([router_task], keep=set())

        await _await_cancelled(spawned, keep={acs_task})
        return decision

    decision_latencies = [0.0] * num_nodes
    start = time.perf_counter()
    pump_task = asyncio.create_task(pump())
    try:
        decisions = await asyncio.wait_for(
            asyncio.gather(*(run_node(pid, start) for pid in range(num_nodes))),
            timeout=round_timeout,
        )
    finally:
        pump_task.cancel()
        try:
            await pump_task
        except asyncio.CancelledError:
            pass

    _assert_decisions_agree(list(decisions), "bkr93")
    elapsed = time.perf_counter() - start
    selected = sum(value is not None for value in decisions[0]) if decisions else 0
    return ACSRoundResult(
        elapsed_seconds=elapsed,
        selected_proposals=selected,
        proposed_proposals=num_nodes,
        decision_latencies_seconds=tuple(decision_latencies),
        payload_bytes_per_node=payload_bytes_per_node,
    )


async def _run_dumbo_round(
    *,
    sid: str,
    num_nodes: int,
    faulty: int,
    batch_size: int,
    tx_bytes: int,
    round_timeout: float,
    materials: tuple[Any, ...],
) -> ACSRoundResult:
    coin_pk, coin_shares, proof_pk, proof_shares, _enc_pk, _enc_shares, ecdsa_pks, ecdsa_sks = (
        materials
    )
    recv_queues = [asyncio.Queue() for _ in range(num_nodes)]
    input_queues = [asyncio.Queue(1) for _ in range(num_nodes)]
    decide_queues = [asyncio.Queue(1) for _ in range(num_nodes)]
    payloads = [_encode_batch(pid, 0, batch_size, tx_bytes) for pid in range(num_nodes)]
    payload_bytes_per_node = len(payloads[0]) if payloads else 0

    for pid in range(num_nodes):
        input_queues[pid].put_nowait(payloads[pid])

    async def send(sender: int, recipient: int, message: object) -> None:
        await recv_queues[recipient].put((sender, message))

    async def run_node(pid: int, started_at: float) -> tuple[bytes | None, ...]:
        task = asyncio.create_task(
            dumbo_acs(
                DumboACSParams(
                    sid=sid,
                    pid=pid,
                    N=num_nodes,
                    f=faulty,
                    leader=pid,
                    coin_pk=coin_pk,
                    coin_sk=coin_shares[pid],
                    proof_pk=proof_pk,
                    proof_sk=proof_shares[pid],
                    ecdsa_pks=ecdsa_pks,
                    ecdsa_sk=ecdsa_sks[pid],
                ),
                input_queues[pid],
                decide_queues[pid],
                recv_queues[pid],
                lambda recipient, message, sender_id=pid: send(sender_id, recipient, message),
            )
        )
        decision = await asyncio.wait_for(decide_queues[pid].get(), timeout=round_timeout)
        decision_latencies[pid] = time.perf_counter() - started_at
        await task
        return decision

    decision_latencies = [0.0] * num_nodes
    start = time.perf_counter()
    decisions = await asyncio.wait_for(
        asyncio.gather(*(run_node(pid, start) for pid in range(num_nodes))),
        timeout=round_timeout,
    )
    _assert_decisions_agree(list(decisions), "dumbo")
    elapsed = time.perf_counter() - start
    selected = sum(value is not None for value in decisions[0]) if decisions else 0
    return ACSRoundResult(
        elapsed_seconds=elapsed,
        selected_proposals=selected,
        proposed_proposals=num_nodes,
        decision_latencies_seconds=tuple(decision_latencies),
        payload_bytes_per_node=payload_bytes_per_node,
    )


def _build_summary(
    *,
    protocol: str,
    num_nodes: int,
    faulty: int,
    batch_size: int,
    rounds: int,
    warmup_rounds: int,
    results: list[ACSRoundResult],
) -> ACSBenchmarkSummary:
    measured = results[warmup_rounds:]
    measured_elapsed = sum(result.elapsed_seconds for result in measured)
    measured_selected = sum(result.selected_proposals for result in measured)
    measured_proposed = sum(result.proposed_proposals for result in measured)
    measured_round_latencies = [result.elapsed_seconds for result in measured]
    measured_decision_latencies = [
        latency for result in measured for latency in result.decision_latencies_seconds
    ]
    measured_delivery_ratio = (measured_selected / measured_proposed) if measured_proposed else 0.0
    tx_multiplier = batch_size
    delivered_transactions = measured_selected * tx_multiplier
    proposed_transactions = measured_proposed * tx_multiplier

    return ACSBenchmarkSummary(
        protocol=protocol,
        num_nodes=num_nodes,
        faulty=faulty,
        batch_size=batch_size,
        rounds=rounds,
        warmup_rounds=warmup_rounds,
        payload_bytes_per_node=results[0].payload_bytes_per_node if results else 0,
        measured_rounds=len(measured),
        measured_elapsed_seconds=measured_elapsed,
        measured_selected_proposals=measured_selected,
        measured_proposed_proposals=measured_proposed,
        measured_delivery_ratio=measured_delivery_ratio,
        measured_tps=(delivered_transactions / measured_elapsed) if measured_elapsed else 0.0,
        measured_offered_tps=(proposed_transactions / measured_elapsed)
        if measured_elapsed
        else 0.0,
        measured_round_latency=_build_latency_stats(measured_round_latencies),
        measured_decision_latency=_build_latency_stats(measured_decision_latencies),
    )


async def _run_protocol_sweep(
    *,
    protocol: str,
    num_nodes: int,
    faulty: int,
    batch_values: list[int],
    rounds: int,
    warmup_rounds: int,
    tx_bytes: int,
    round_timeout: float,
) -> dict[str, Any]:
    runner = _run_bkr93_round if protocol == "bkr93" else _run_dumbo_round
    materials = (
        build_materials(num_nodes, faulty)
        if protocol == "bkr93"
        else build_dumbo_materials(num_nodes, faulty)
    )
    points: list[dict[str, Any]] = []

    for batch_size in batch_values:
        round_results: list[ACSRoundResult] = []
        for round_id in range(rounds):
            round_results.append(
                await runner(
                    sid=f"bench:acs:{protocol}:{num_nodes}:{batch_size}:{round_id}:{int(time.time())}",
                    num_nodes=num_nodes,
                    faulty=faulty,
                    batch_size=batch_size,
                    tx_bytes=tx_bytes,
                    round_timeout=round_timeout,
                    materials=materials,
                )
            )
        summary = _build_summary(
            protocol=protocol,
            num_nodes=num_nodes,
            faulty=faulty,
            batch_size=batch_size,
            rounds=rounds,
            warmup_rounds=warmup_rounds,
            results=round_results,
        )
        points.append(asdict(summary))

    return {
        "meta": {
            "protocol": protocol,
            "num_nodes": num_nodes,
            "faulty": faulty,
            "rounds": rounds,
            "warmup_rounds": warmup_rounds,
            "tx_bytes": tx_bytes,
            "x_axis": "batch_size",
        },
        "points": points,
    }


def _print_compare(payload: dict[str, Any]) -> None:
    protocols = payload["protocols"]
    bkr93_points = {point["batch_size"]: point for point in protocols["bkr93"]["points"]}
    dumbo_points = {point["batch_size"]: point for point in protocols["dumbo"]["points"]}
    batches = sorted(set(bkr93_points) & set(dumbo_points))
    print(
        "batch  bkr93_tps  dumbo_tps  speedup  bkr93_ratio  dumbo_ratio  "
        "bkr93_offered  dumbo_offered"
    )
    for batch in batches:
        left = bkr93_points[batch]
        right = dumbo_points[batch]
        speedup = right["measured_tps"] / left["measured_tps"] if left["measured_tps"] else 0.0
        print(
            f"{batch:<6}"
            f"{left['measured_tps']:<11.1f}"
            f"{right['measured_tps']:<11.1f}"
            f"{speedup:<9.2f}"
            f"{left['measured_delivery_ratio']:<13.3f}"
            f"{right['measured_delivery_ratio']:<13.3f}"
            f"{left['measured_offered_tps']:<15.1f}"
            f"{right['measured_offered_tps']:<15.1f}"
        )


def _write_text(path_str: str, content: str) -> None:
    path = Path(path_str)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


async def _main_async(args: argparse.Namespace) -> dict[str, Any]:
    faulty = args.faulty if args.faulty is not None else (args.nodes - 1) // 3
    batch_values = _parse_batch_values(args.sweep_batches, args.batch_size)
    protocol_list = ["bkr93", "dumbo"] if args.protocol == "both" else [args.protocol]
    results: dict[str, Any] = {}

    for protocol in protocol_list:
        results[protocol] = await _run_protocol_sweep(
            protocol=protocol,
            num_nodes=args.nodes,
            faulty=faulty,
            batch_values=batch_values,
            rounds=args.rounds,
            warmup_rounds=args.warmup_rounds,
            tx_bytes=args.tx_bytes,
            round_timeout=args.round_timeout,
        )

    if args.protocol == "both":
        return {"meta": {"compare": True}, "protocols": results}
    return results[protocol_list[0]]


def main() -> None:
    args = _parse_args()
    payload = asyncio.run(_main_async(args))

    if args.output_json:
        _write_text(args.output_json, json.dumps(payload, indent=2, sort_keys=True))

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return

    if args.protocol == "both":
        _print_compare(payload)
    else:
        for point in payload["points"]:
            print(
                f"batch={point['batch_size']} "
                f"tps={point['measured_tps']:.1f} "
                f"offered_tps={point['measured_offered_tps']:.1f} "
                f"ratio={point['measured_delivery_ratio']:.3f} "
                f"round_p95={point['measured_round_latency']['p95_ms']:.1f}ms"
            )


if __name__ == "__main__":
    main()
