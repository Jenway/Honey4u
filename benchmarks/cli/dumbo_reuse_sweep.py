from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from statistics import fmean
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks.plotting.svg import (
    MODE_ORDER,
    build_comparison_svg_chart,
    collect_series,
    render_png,
    round_ms,
)
from benchmarks.support.runners import run_local_dumbo_new_driver


def _parse_int_list(raw: str) -> list[int]:
    values = [int(part.strip()) for part in raw.split(",") if part.strip()]
    if not values:
        raise ValueError("expected at least one integer")
    if any(value <= 0 for value in values):
        raise ValueError("values must be positive integers")
    return values


def _default_output_dir() -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return Path("benchmarks/results") / f"dumbo-reuse-sweep-{stamp}"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a broad multiprocess local-TCP Dumbo reuse benchmark sweep"
    )
    parser.add_argument("--sid-prefix", default="bench:dumbo:reuse")
    parser.add_argument("--nodes", default="4,8,12,16")
    parser.add_argument("--batches", default="1,2,4,8,16,32")
    parser.add_argument("--rounds", type=int, default=4)
    parser.add_argument("--repeats", type=int, default=2)
    parser.add_argument("--global-timeout", type=float, default=180.0)
    parser.add_argument("--pool-grace-ms", type=int, default=100)
    parser.add_argument("--pool-reuse-limit-per-round", type=int, default=4)
    parser.add_argument("--pool-expire-rounds", type=int, default=10)
    parser.add_argument("--pool-mempool-max", type=int, default=1024)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument(
        "--skip-png",
        action="store_true",
        help="only emit SVG plots; do not attempt SVG->PNG conversion",
    )
    return parser.parse_args()


def _run_one_case(
    *,
    sid: str,
    nodes: int,
    faulty: int,
    batch_size: int,
    rounds: int,
    global_timeout: float,
    enable_reuse: bool,
    pool_grace_ms: int,
    pool_reuse_limit_per_round: int,
    pool_expire_rounds: int,
    pool_mempool_max: int,
) -> dict[str, Any]:
    started = time.perf_counter()
    result = run_local_dumbo_new_driver(
        sid=sid,
        num_nodes=nodes,
        faulty=faulty,
        batch_size=batch_size,
        max_rounds=rounds,
        global_timeout=global_timeout,
        enable_broadcast_pool_reuse=enable_reuse,
        enable_pool_reference_proposals=True,
        pool_grace_ms=pool_grace_ms,
        pool_reuse_limit_per_round=pool_reuse_limit_per_round,
        pool_expire_rounds=pool_expire_rounds,
        pool_mempool_max=pool_mempool_max,
    )
    elapsed_seconds = time.perf_counter() - started

    delivered_total = sum(round_data.delivered_count for round_data in result.rounds)
    wall_total_seconds = sum(round_data.wall_seconds for round_data in result.rounds)
    acs_total_seconds = sum(round_data.acs_seconds for round_data in result.rounds)
    block_resolve_total_seconds = sum(
        round_data.block_resolve_seconds for round_data in result.rounds
    )
    reused_reference_total = sum(round_data.reused_reference_count for round_data in result.rounds)
    fetch_requests_sent_total = sum(round_data.fetch_requests_sent for round_data in result.rounds)
    fetch_responses_served_total = sum(
        round_data.fetch_responses_served for round_data in result.rounds
    )
    fetch_responses_received_total = sum(
        round_data.fetch_responses_received for round_data in result.rounds
    )
    fetched_reference_total = sum(
        round_data.fetched_reference_count for round_data in result.rounds
    )

    return {
        "status": "ok",
        "mode": "reuse_on" if enable_reuse else "reuse_off",
        "nodes": nodes,
        "faulty": faulty,
        "batch_size": batch_size,
        "rounds": rounds,
        "elapsed_seconds": elapsed_seconds,
        "delivered_total": delivered_total,
        "wall_total_seconds": wall_total_seconds,
        "acs_total_seconds": acs_total_seconds,
        "block_resolve_total_seconds": block_resolve_total_seconds,
        "tps_wall": (delivered_total / wall_total_seconds) if wall_total_seconds else 0.0,
        "tps_acs": (delivered_total / acs_total_seconds) if acs_total_seconds else 0.0,
        "mean_round_wall_seconds": (
            fmean(round_data.wall_seconds for round_data in result.rounds) if result.rounds else 0.0
        ),
        "mean_round_acs_seconds": (
            fmean(round_data.acs_seconds for round_data in result.rounds) if result.rounds else 0.0
        ),
        "mean_round_block_resolve_seconds": (
            fmean(round_data.block_resolve_seconds for round_data in result.rounds)
            if result.rounds
            else 0.0
        ),
        "reused_reference_total": reused_reference_total,
        "fetch_requests_sent_total": fetch_requests_sent_total,
        "fetch_responses_served_total": fetch_responses_served_total,
        "fetch_responses_received_total": fetch_responses_received_total,
        "fetched_reference_total": fetched_reference_total,
        "node_mempool_sizes": [node.mempool_size for node in result.nodes],
        "result": asdict(result),
    }


def _aggregate_runs(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[int, int, int, str], list[dict[str, Any]]] = {}
    for record in records:
        if record["status"] != "ok":
            continue
        key = (
            int(record["nodes"]),
            int(record["faulty"]),
            int(record["batch_size"]),
            str(record["mode"]),
        )
        grouped.setdefault(key, []).append(record)

    summaries: list[dict[str, Any]] = []
    for (nodes, faulty, batch_size, mode), runs in sorted(grouped.items()):
        summaries.append(
            {
                "nodes": nodes,
                "faulty": faulty,
                "batch_size": batch_size,
                "mode": mode,
                "run_count": len(runs),
                "delivered_total_mean": fmean(run["delivered_total"] for run in runs),
                "wall_total_seconds_mean": fmean(run["wall_total_seconds"] for run in runs),
                "acs_total_seconds_mean": fmean(run["acs_total_seconds"] for run in runs),
                "tps_wall_mean": fmean(run["tps_wall"] for run in runs),
                "tps_acs_mean": fmean(run["tps_acs"] for run in runs),
                "mean_round_wall_seconds_mean": fmean(
                    run["mean_round_wall_seconds"] for run in runs
                ),
                "mean_round_acs_seconds_mean": fmean(run["mean_round_acs_seconds"] for run in runs),
                "mean_round_block_resolve_seconds_mean": fmean(
                    run["mean_round_block_resolve_seconds"] for run in runs
                ),
                "reused_reference_total_mean": fmean(run["reused_reference_total"] for run in runs),
                "fetch_requests_sent_total_mean": fmean(
                    run["fetch_requests_sent_total"] for run in runs
                ),
                "fetch_responses_served_total_mean": fmean(
                    run["fetch_responses_served_total"] for run in runs
                ),
                "fetch_responses_received_total_mean": fmean(
                    run["fetch_responses_received_total"] for run in runs
                ),
                "fetched_reference_total_mean": fmean(
                    run["fetched_reference_total"] for run in runs
                ),
                "node_mempool_size_mean": fmean(
                    size for run in runs for size in run["node_mempool_sizes"]
                ),
                "node_mempool_size_max": max(
                    size for run in runs for size in run["node_mempool_sizes"]
                ),
            }
        )
    return summaries


def _build_deltas(summaries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    indexed = {
        (int(item["nodes"]), int(item["batch_size"]), str(item["mode"])): item for item in summaries
    }
    deltas: list[dict[str, Any]] = []
    keys = sorted({(int(item["nodes"]), int(item["batch_size"])) for item in summaries})
    for nodes, batch_size in keys:
        off = indexed.get((nodes, batch_size, "reuse_off"))
        on = indexed.get((nodes, batch_size, "reuse_on"))
        if off is None or on is None:
            continue

        def pct_change(new_value: float, old_value: float) -> float:
            if old_value == 0.0:
                return 0.0
            return ((new_value / old_value) - 1.0) * 100.0

        deltas.append(
            {
                "nodes": nodes,
                "faulty": int(off["faulty"]),
                "batch_size": batch_size,
                "tps_wall_delta_pct": pct_change(
                    float(on["tps_wall_mean"]), float(off["tps_wall_mean"])
                ),
                "tps_acs_delta_pct": pct_change(
                    float(on["tps_acs_mean"]), float(off["tps_acs_mean"])
                ),
                "mean_round_wall_delta_pct": pct_change(
                    float(on["mean_round_wall_seconds_mean"]),
                    float(off["mean_round_wall_seconds_mean"]),
                ),
                "mean_round_acs_delta_pct": pct_change(
                    float(on["mean_round_acs_seconds_mean"]),
                    float(off["mean_round_acs_seconds_mean"]),
                ),
                "delivered_total_delta_pct": pct_change(
                    float(on["delivered_total_mean"]), float(off["delivered_total_mean"])
                ),
                "reused_reference_total_mean": float(on["reused_reference_total_mean"]),
                "fetch_requests_sent_total_mean": float(on["fetch_requests_sent_total_mean"]),
                "fetch_responses_served_total_mean": float(on["fetch_responses_served_total_mean"]),
                "fetch_responses_received_total_mean": float(
                    on["fetch_responses_received_total_mean"]
                ),
                "fetched_reference_total_mean": float(on["fetched_reference_total_mean"]),
            }
        )
    return deltas


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _build_chart_payloads(
    *,
    summaries: list[dict[str, Any]],
    nodes: list[int],
    batches: list[int],
    repeats: int,
    rounds: int,
) -> dict[str, str]:
    subtitle = (
        f"bench-driver TOML config, real multiprocess local TCP, repeats={repeats}, rounds={rounds}, "
        "pool refs enabled"
    )
    chart_specs = [
        ("tps_wall", "TPS (wall)", "tps_wall_mean", "transactions / second"),
        (
            "mean_round_wall_ms",
            "Mean Round Wall Latency (ms)",
            "mean_round_wall_seconds_mean",
            "milliseconds",
        ),
        (
            "mean_round_acs_ms",
            "Mean ACS Latency (ms)",
            "mean_round_acs_seconds_mean",
            "milliseconds",
        ),
        (
            "delivered_total",
            "Delivered Transactions Per Run",
            "delivered_total_mean",
            "transactions",
        ),
    ]

    payloads: dict[str, str] = {}
    for file_stem, title, metric_key, metric_label in chart_specs:
        panels: list[dict[str, Any]] = []
        for node_count in nodes:
            series = collect_series(
                summaries,
                nodes=node_count,
                batches=batches,
                metric_key=metric_key,
            )
            if metric_key.endswith("_seconds_mean"):
                for item in series:
                    item["values"] = [
                        (round_ms(value) if value is not None else None) for value in item["values"]
                    ]
            panels.append(
                {
                    "label": f"N={node_count}, f={(node_count - 1) // 3}",
                    "series": series,
                    "ymin": 0.0,
                }
            )
        payloads[file_stem] = build_comparison_svg_chart(
            title=title,
            subtitle=subtitle,
            node_panels=panels,
            x_labels=[str(batch_size) for batch_size in batches],
            output_metric_label=metric_label,
        )
    return payloads


def main() -> None:
    args = _parse_args()
    nodes = _parse_int_list(args.nodes)
    batches = _parse_int_list(args.batches)
    if args.rounds <= 0:
        raise ValueError("--rounds must be positive")
    if args.repeats <= 0:
        raise ValueError("--repeats must be positive")

    output_dir = Path(args.output_dir) if args.output_dir else _default_output_dir()
    output_dir.mkdir(parents=True, exist_ok=True)

    records: list[dict[str, Any]] = []
    total_cases = len(nodes) * len(batches) * len(MODE_ORDER) * args.repeats
    case_index = 0
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")

    for node_count in nodes:
        faulty = (node_count - 1) // 3
        for batch_size in batches:
            for repeat_index in range(args.repeats):
                for mode in MODE_ORDER:
                    case_index += 1
                    enable_reuse = mode == "reuse_on"
                    sid = (
                        f"{args.sid_prefix}:n{node_count}:b{batch_size}:rep{repeat_index}:"
                        f"{mode}:{stamp}"
                    )
                    print(
                        (
                            f"[{case_index}/{total_cases}] "
                            f"n={node_count} f={faulty} batch={batch_size} "
                            f"repeat={repeat_index + 1}/{args.repeats} mode={mode}"
                        ),
                        file=sys.stderr,
                        flush=True,
                    )
                    try:
                        record = _run_one_case(
                            sid=sid,
                            nodes=node_count,
                            faulty=faulty,
                            batch_size=batch_size,
                            rounds=args.rounds,
                            global_timeout=args.global_timeout,
                            enable_reuse=enable_reuse,
                            pool_grace_ms=args.pool_grace_ms,
                            pool_reuse_limit_per_round=args.pool_reuse_limit_per_round,
                            pool_expire_rounds=args.pool_expire_rounds,
                            pool_mempool_max=args.pool_mempool_max,
                        )
                    except Exception as exc:
                        record = {
                            "status": "error",
                            "mode": mode,
                            "nodes": node_count,
                            "faulty": faulty,
                            "batch_size": batch_size,
                            "rounds": args.rounds,
                            "error": f"{type(exc).__name__}: {exc}",
                        }
                    record["repeat"] = repeat_index
                    records.append(record)

                    payload = {
                        "meta": {
                            "sid_prefix": args.sid_prefix,
                            "nodes": nodes,
                            "batches": batches,
                            "rounds": args.rounds,
                            "repeats": args.repeats,
                            "global_timeout": args.global_timeout,
                            "pool_grace_ms": args.pool_grace_ms,
                            "pool_reuse_limit_per_round": args.pool_reuse_limit_per_round,
                            "pool_expire_rounds": args.pool_expire_rounds,
                            "pool_mempool_max": args.pool_mempool_max,
                            "generated_at_utc": datetime.now(UTC).isoformat(),
                            "driver": "bench-driver:dumbo",
                            "transport": "local-tcp",
                            "multiprocess": True,
                        },
                        "records": records,
                        "summaries": _aggregate_runs(records),
                        "deltas": _build_deltas(_aggregate_runs(records)),
                    }
                    _write_text(
                        output_dir / "dumbo_reuse_sweep.json",
                        json.dumps(payload, indent=2, sort_keys=True),
                    )

    summaries = _aggregate_runs(records)
    deltas = _build_deltas(summaries)
    payload = {
        "meta": {
            "sid_prefix": args.sid_prefix,
            "nodes": nodes,
            "batches": batches,
            "rounds": args.rounds,
            "repeats": args.repeats,
            "global_timeout": args.global_timeout,
            "pool_grace_ms": args.pool_grace_ms,
            "pool_reuse_limit_per_round": args.pool_reuse_limit_per_round,
            "pool_expire_rounds": args.pool_expire_rounds,
            "pool_mempool_max": args.pool_mempool_max,
            "generated_at_utc": datetime.now(UTC).isoformat(),
            "driver": "bench-driver:dumbo",
            "transport": "local-tcp",
            "multiprocess": True,
        },
        "records": records,
        "summaries": summaries,
        "deltas": deltas,
    }
    json_path = output_dir / "dumbo_reuse_sweep.json"
    _write_text(json_path, json.dumps(payload, indent=2, sort_keys=True))

    plot_dir = output_dir / "plots"
    plot_payloads = _build_chart_payloads(
        summaries=summaries,
        nodes=nodes,
        batches=batches,
        repeats=args.repeats,
        rounds=args.rounds,
    )
    png_paths: list[str] = []
    for file_stem, svg in plot_payloads.items():
        svg_path = plot_dir / f"{file_stem}.svg"
        _write_text(svg_path, svg)
        if not args.skip_png:
            png_path = render_png(svg_path)
            if png_path is not None:
                png_paths.append(str(png_path))

    manifest = {
        "json": str(json_path),
        "plot_dir": str(plot_dir),
        "png_plots": png_paths,
    }
    _write_text(output_dir / "manifest.json", json.dumps(manifest, indent=2, sort_keys=True))
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
