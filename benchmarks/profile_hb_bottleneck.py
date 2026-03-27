#!/usr/bin/env python
# ruff: noqa: E402

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from honey.network.hbbft_runner import (
    benchmark_local_honeybadger_nodes_multiprocess,
    run_local_honeybadger_nodes_deterministic,
)
from honey.support.telemetry import METRICS


def _summarize_multiprocess(results: list[Any], outer_elapsed: float) -> dict[str, Any]:
    delivered = min(result.delivered for result in results)
    protocol_elapsed = max(sum(result.round_latencies) for result in results)
    wall_elapsed = max(sum(result.round_wall_latencies) for result in results)

    timings: dict[str, list[float | int]] = defaultdict(lambda: [0, 0.0, 0.0])
    for result in results:
        for name, summary in result.subprotocol_timings.items():
            timings[name][0] += summary.sample_count
            timings[name][1] += summary.total_seconds
            timings[name][2] = max(timings[name][2], summary.max_seconds)

    return {
        "delivered": delivered,
        "protocol_elapsed_seconds": protocol_elapsed,
        "wall_elapsed_seconds": wall_elapsed,
        "outer_elapsed_seconds": outer_elapsed,
        "protocol_tps": delivered / protocol_elapsed if protocol_elapsed else 0.0,
        "wall_tps": delivered / wall_elapsed if wall_elapsed else 0.0,
        "queue_peaks": {
            "raw_inbound_messages": [result.queue_peaks.raw_inbound_messages for result in results],
            "raw_outbound_messages": [
                result.queue_peaks.raw_outbound_messages for result in results
            ],
            "transport_inbound": [result.queue_peaks.transport_inbound for result in results],
            "transport_outbound": [result.queue_peaks.transport_outbound for result in results],
            "mailbox_round_inbox": [result.queue_peaks.mailbox_round_inbox for result in results],
        },
        "timings": {
            name: {"count": count, "total": total, "max": max_value}
            for name, (count, total, max_value) in timings.items()
        },
    }


async def _run_deterministic(args: argparse.Namespace) -> dict[str, Any]:
    METRICS.reset()
    start = time.perf_counter()
    nodes = await run_local_honeybadger_nodes_deterministic(
        sid=f"{args.sid}:det",
        num_nodes=args.nodes,
        faulty=args.faulty,
        seed=args.seed,
        batch_size=args.batch_size,
        max_rounds=args.rounds,
        round_timeout=args.round_timeout,
        min_delay_steps=0,
        max_delay_steps=0,
        transactions_per_node=args.transactions_per_node,
        tx_input=args.tx_input,
        log_level=args.log_level,
        use_rust_tx_pool=args.use_rust_tx_pool,
        rust_tx_pool_max_bytes=args.rust_tx_pool_max_bytes,
    )
    outer_elapsed = time.perf_counter() - start

    delivered = min(node.txcnt for node in nodes)
    protocol_elapsed = max(sum(node.round_latencies) for node in nodes)
    wall_elapsed = max(sum(node.round_wall_latencies) for node in nodes)

    return {
        "delivered": delivered,
        "protocol_elapsed_seconds": protocol_elapsed,
        "wall_elapsed_seconds": wall_elapsed,
        "outer_elapsed_seconds": outer_elapsed,
        "protocol_tps": delivered / protocol_elapsed if protocol_elapsed else 0.0,
        "wall_tps": delivered / wall_elapsed if wall_elapsed else 0.0,
        "mailbox_round_inbox": [node.mailboxes.peak_inbox_size for node in nodes],
        "timings": METRICS.snapshot()["timings"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Profile HoneyBadger bottlenecks locally.")
    parser.add_argument("--sid", default="bench:hb:bottleneck")
    parser.add_argument("--nodes", type=int, default=10)
    parser.add_argument("--faulty", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--rounds", type=int, default=4)
    parser.add_argument("--transactions-per-node", type=int)
    parser.add_argument(
        "--tx-input", choices=("python_json", "json_str", "bytes"), default="json_str"
    )
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--round-timeout", type=float, default=20.0)
    parser.add_argument("--global-timeout", type=float, default=180.0)
    parser.add_argument("--log-level", default="ERROR")
    parser.add_argument("--use-rust-tx-pool", action="store_true")
    parser.add_argument("--rust-tx-pool-max-bytes", type=int, default=0)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.transactions_per_node is None:
        args.transactions_per_node = args.batch_size * args.rounds

    start = time.perf_counter()
    multiprocess = benchmark_local_honeybadger_nodes_multiprocess(
        sid=f"{args.sid}:socket",
        num_nodes=args.nodes,
        faulty=args.faulty,
        batch_size=args.batch_size,
        max_rounds=args.rounds,
        round_timeout=args.round_timeout,
        global_timeout=args.global_timeout,
        transactions_per_node=args.transactions_per_node,
        tx_input=args.tx_input,
        log_level=args.log_level,
        use_rust_tx_pool=args.use_rust_tx_pool,
        rust_tx_pool_max_bytes=args.rust_tx_pool_max_bytes,
    )
    multiprocess_summary = _summarize_multiprocess(multiprocess, time.perf_counter() - start)

    deterministic_summary = asyncio.run(_run_deterministic(args))

    payload = {
        "config": {
            "nodes": args.nodes,
            "faulty": args.faulty,
            "batch_size": args.batch_size,
            "rounds": args.rounds,
            "transactions_per_node": args.transactions_per_node,
            "tx_input": args.tx_input,
            "use_rust_tx_pool": args.use_rust_tx_pool,
            "rust_tx_pool_max_bytes": args.rust_tx_pool_max_bytes,
        },
        "multiprocess_socket": multiprocess_summary,
        "deterministic_inprocess": deterministic_summary,
    }
    encoded = json.dumps(payload, indent=2)
    if args.output is not None:
        args.output.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)


if __name__ == "__main__":
    main()
