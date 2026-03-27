#!/usr/bin/env python
# ruff: noqa: E402

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from honey.network.hbbft_runner import (  # noqa: E402
    MultiprocessNodeResult,
    benchmark_local_dumbo_nodes_multiprocess,
    benchmark_local_honeybadger_nodes_multiprocess,
)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Profile local benchmark timing distribution for HoneyBadger or Dumbo."
    )
    parser.add_argument("--protocol", choices=("hb", "dumbo"), required=True)
    parser.add_argument("--sid", default="bench:profile")
    parser.add_argument("--nodes", type=int, default=10)
    parser.add_argument("--faulty", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=16384)
    parser.add_argument("--rounds", type=int, default=4)
    parser.add_argument("--round-timeout", type=float, default=360.0)
    parser.add_argument("--global-timeout", type=float, default=14400.0)
    parser.add_argument("--tx-input", choices=("python_json", "json_str", "bytes"), default="bytes")
    parser.add_argument("--transactions-per-node", type=int, default=None)
    parser.add_argument("--log-level", default="ERROR")
    parser.add_argument("--output", type=Path, default=None)
    return parser.parse_args()


def _aggregate_timings(results: list[MultiprocessNodeResult]) -> dict[str, dict[str, float | int]]:
    timings: dict[str, list[float | int]] = defaultdict(lambda: [0, 0.0, 0.0])
    for result in results:
        for name, summary in result.subprotocol_timings.items():
            bucket = timings[name]
            bucket[0] += summary.sample_count
            bucket[1] += summary.total_seconds
            bucket[2] = max(bucket[2], summary.max_seconds)
    return {
        name: {"count": count, "total_seconds": total, "max_seconds": max_value}
        for name, (count, total, max_value) in timings.items()
    }


def _queue_peaks(results: list[MultiprocessNodeResult]) -> dict[str, dict[str, float | int]]:
    metrics = (
        "raw_inbound_messages",
        "raw_outbound_messages",
        "transport_inbound",
        "transport_outbound",
        "mailbox_round_inbox",
    )
    summary: dict[str, dict[str, float | int]] = {}
    for metric in metrics:
        values = [getattr(result.queue_peaks, metric) for result in results]
        summary[metric] = {
            "min": min(values, default=0),
            "mean": (sum(values) / len(values)) if values else 0.0,
            "max": max(values, default=0),
        }
    return summary


def _time_breakdown(timings: dict[str, dict[str, float | int]]) -> list[dict[str, float | str]]:
    node_total = float(timings.get("node.run.seconds", {}).get("total_seconds", 0.0))
    round_total = float(timings.get("hb.round.seconds", {}).get("total_seconds", 0.0))
    rows: list[dict[str, float | str]] = []
    for name, payload in timings.items():
        total = float(payload["total_seconds"])
        rows.append(
            {
                "name": name,
                "total_seconds": total,
                "share_of_node_run": (total / node_total) if node_total else 0.0,
                "share_of_hb_round": (total / round_total) if round_total else 0.0,
            }
        )
    rows.sort(key=lambda item: float(item["total_seconds"]), reverse=True)
    return rows


def _run_profile(args: argparse.Namespace) -> dict[str, Any]:
    transactions_per_node = args.transactions_per_node
    if transactions_per_node is None:
        transactions_per_node = args.batch_size * args.rounds

    runner = (
        benchmark_local_dumbo_nodes_multiprocess
        if args.protocol == "dumbo"
        else benchmark_local_honeybadger_nodes_multiprocess
    )

    start = time.perf_counter()
    results = runner(
        sid=f"{args.sid}:{args.protocol}:{args.nodes}:{args.batch_size}",
        num_nodes=args.nodes,
        faulty=args.faulty,
        batch_size=args.batch_size,
        max_rounds=args.rounds,
        round_timeout=args.round_timeout,
        global_timeout=args.global_timeout,
        transactions_per_node=transactions_per_node,
        tx_input=args.tx_input,
        log_level=args.log_level,
    )
    outer_elapsed = time.perf_counter() - start
    timings = _aggregate_timings(results)
    return {
        "config": {
            "protocol": args.protocol,
            "nodes": args.nodes,
            "faulty": args.faulty,
            "batch_size": args.batch_size,
            "rounds": args.rounds,
            "round_timeout": args.round_timeout,
            "global_timeout": args.global_timeout,
            "tx_input": args.tx_input,
            "transactions_per_node": transactions_per_node,
        },
        "elapsed_seconds": outer_elapsed,
        "delivered_transactions_min": min((result.delivered for result in results), default=0),
        "completed_rounds_min": min((result.rounds for result in results), default=0),
        "queue_peaks": _queue_peaks(results),
        "timings": timings,
        "time_breakdown": _time_breakdown(timings),
    }


def main() -> None:
    args = _parse_args()
    payload = _run_profile(args)
    encoded = json.dumps(payload, ensure_ascii=False, indent=2)
    if args.output is not None:
        args.output.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)


if __name__ == "__main__":
    main()
