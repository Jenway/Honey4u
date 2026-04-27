from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from statistics import fmean
from typing import Any
from xml.sax.saxutils import escape

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks.support.runners import run_local_dumbo_new_driver

MODE_ORDER = ("reuse_off", "reuse_on")
MODE_LABELS = {
    "reuse_off": "Reuse Off",
    "reuse_on": "Reuse On",
}
MODE_COLORS = {
    "reuse_off": "#0f766e",
    "reuse_on": "#c2410c",
}


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


def _round_ms(value_seconds: float) -> float:
    return value_seconds * 1000.0


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


def _format_number(value: float) -> str:
    if abs(value) >= 1000.0:
        return f"{value:,.0f}"
    if abs(value) >= 100.0:
        return f"{value:.0f}"
    if abs(value) >= 10.0:
        return f"{value:.1f}"
    return f"{value:.2f}"


def _collect_series(
    summaries: list[dict[str, Any]],
    *,
    nodes: int,
    batches: list[int],
    metric_key: str,
) -> list[dict[str, Any]]:
    indexed = {
        (int(item["nodes"]), int(item["batch_size"]), str(item["mode"])): item for item in summaries
    }
    series: list[dict[str, Any]] = []
    for mode in MODE_ORDER:
        values: list[float | None] = []
        for batch_size in batches:
            item = indexed.get((nodes, batch_size, mode))
            values.append(float(item[metric_key]) if item is not None else None)
        series.append(
            {
                "label": MODE_LABELS[mode],
                "color": MODE_COLORS[mode],
                "values": values,
            }
        )
    return series


def _split_segments(
    xs: list[float],
    values: list[float | None],
    *,
    y0: float,
    height: float,
    ymin: float,
    ymax: float,
) -> tuple[list[str], list[tuple[float, float, float, str]]]:
    def map_y(value: float) -> float:
        return y0 + height - ((value - ymin) / (ymax - ymin)) * height

    segments: list[str] = []
    points: list[tuple[float, float, float, str]] = []
    current: list[tuple[float, float]] = []

    for x, value in zip(xs, values, strict=True):
        if value is None:
            if len(current) >= 2:
                segments.append(" ".join(f"{px:.1f},{py:.1f}" for px, py in current))
            current = []
            continue
        y = map_y(float(value))
        current.append((x, y))
        points.append((x, y, float(value), f"{float(value):.6f}"))

    if len(current) >= 2:
        segments.append(" ".join(f"{px:.1f},{py:.1f}" for px, py in current))

    return segments, points


def _build_svg_chart(
    *,
    title: str,
    subtitle: str,
    node_panels: list[dict[str, Any]],
    x_labels: list[str],
    output_metric_label: str,
    width: int = 1480,
    height_per_panel: int = 220,
) -> str:
    left = 96
    right = width - 40
    top = 118
    panel_gap = 40
    plot_width = right - left
    panel_height = height_per_panel
    height = top + len(node_panels) * panel_height + max(0, len(node_panels) - 1) * panel_gap + 88
    bottom = height - 68

    def x_positions() -> list[float]:
        if len(x_labels) == 1:
            return [left + plot_width / 2]
        step = plot_width / (len(x_labels) - 1)
        return [left + step * idx for idx in range(len(x_labels))]

    xs = x_positions()
    lines = [
        f"<svg xmlns='http://www.w3.org/2000/svg' width='{width}' height='{height}' viewBox='0 0 {width} {height}'>",
        f"<rect width='{width}' height='{height}' fill='#f8fafc'/>",
        f"<text x='{left}' y='46' font-size='30' font-family='Segoe UI, Arial, sans-serif' fill='#0f172a' font-weight='700'>{escape(title)}</text>",
        f"<text x='{left}' y='74' font-size='14' font-family='Segoe UI, Arial, sans-serif' fill='#475569'>{escape(subtitle)}</text>",
    ]

    legend_x = left
    legend_y = 98
    for mode in MODE_ORDER:
        color = MODE_COLORS[mode]
        label = MODE_LABELS[mode]
        lines.append(
            f"<line x1='{legend_x}' y1='{legend_y}' x2='{legend_x + 28}' y2='{legend_y}' stroke='{color}' stroke-width='4' stroke-linecap='round'/>"
        )
        lines.append(f"<circle cx='{legend_x + 14}' cy='{legend_y}' r='4.5' fill='{color}'/>")
        lines.append(
            f"<text x='{legend_x + 38}' y='{legend_y + 5}' font-size='13' font-family='Segoe UI, Arial, sans-serif' fill='#1e293b'>{escape(label)}</text>"
        )
        legend_x += 150

    lines.append(
        f"<text x='{width - 42}' y='98' text-anchor='end' font-size='13' font-family='Segoe UI, Arial, sans-serif' fill='#475569'>{escape(output_metric_label)}</text>"
    )

    for panel_index, panel in enumerate(node_panels):
        y0 = top + panel_index * (panel_height + panel_gap)
        y1 = y0 + panel_height
        flat_values = [
            float(value)
            for series in panel["series"]
            for value in series["values"]
            if value is not None
        ]
        ymin = float(panel.get("ymin", 0.0))
        ymax = float(panel.get("ymax", max(flat_values) if flat_values else 1.0))
        if ymax <= ymin:
            ymax = ymin + 1.0
        if ymax > ymin:
            ymax = ymax * 1.08

        lines.append(
            f"<text x='{left}' y='{y0 - 14}' font-size='19' font-family='Segoe UI, Arial, sans-serif' fill='#0f172a' font-weight='600'>{escape(panel['label'])}</text>"
        )
        lines.append(
            f"<rect x='{left}' y='{y0}' width='{plot_width}' height='{panel_height}' fill='white' stroke='#cbd5e1'/>"
        )

        for tick in range(6):
            ratio = tick / 5
            y = y1 - ratio * panel_height
            tick_value = ymin + ratio * (ymax - ymin)
            lines.append(
                f"<line x1='{left}' y1='{y:.1f}' x2='{right}' y2='{y:.1f}' stroke='#e2e8f0' stroke-dasharray='4 4'/>"
            )
            lines.append(
                f"<text x='{left - 12}' y='{y + 5:.1f}' text-anchor='end' font-size='12' font-family='Segoe UI, Arial, sans-serif' fill='#64748b'>{escape(_format_number(tick_value))}</text>"
            )

        for x, label in zip(xs, x_labels, strict=True):
            lines.append(
                f"<line x1='{x:.1f}' y1='{y0}' x2='{x:.1f}' y2='{y1}' stroke='#f1f5f9' stroke-dasharray='3 6'/>"
            )
            if panel_index == len(node_panels) - 1:
                lines.append(
                    f"<text x='{x:.1f}' y='{bottom + 20}' text-anchor='middle' font-size='12' font-family='Segoe UI, Arial, sans-serif' fill='#64748b'>{escape(label)}</text>"
                )

        for series in panel["series"]:
            segments, points = _split_segments(
                xs,
                list(series["values"]),
                y0=y0,
                height=panel_height,
                ymin=ymin,
                ymax=ymax,
            )
            for segment in segments:
                lines.append(
                    f"<polyline points='{segment}' fill='none' stroke='{series['color']}' stroke-width='4' stroke-linecap='round' stroke-linejoin='round'/>"
                )
            for x, y, _value, _ in points:
                lines.append(
                    f"<circle cx='{x:.1f}' cy='{y:.1f}' r='4.5' fill='{series['color']}'/>"
                )
            if points:
                x, y, value, _ = points[-1]
                lines.append(
                    f"<text x='{x + 8:.1f}' y='{y - 8:.1f}' font-size='12' font-family='Segoe UI, Arial, sans-serif' fill='#1e293b'>{escape(_format_number(value))}</text>"
                )

    lines.append(
        f"<text x='{left + plot_width / 2:.1f}' y='{bottom + 48}' text-anchor='middle' font-size='14' font-family='Segoe UI, Arial, sans-serif' fill='#0f172a'>Batch size per node per round</text>"
    )
    lines.append("</svg>")
    return "\n".join(lines)


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _render_png(svg_path: Path) -> Path | None:
    png_path = svg_path.with_suffix(".png")
    try:
        subprocess.run(
            ["rsvg-convert", "-o", str(png_path), str(svg_path)],
            check=True,
            capture_output=True,
            text=True,
        )
    except OSError, subprocess.CalledProcessError:
        return None
    return png_path


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
            series = _collect_series(
                summaries,
                nodes=node_count,
                batches=batches,
                metric_key=metric_key,
            )
            if metric_key.endswith("_seconds_mean"):
                for item in series:
                    item["values"] = [
                        (_round_ms(value) if value is not None else None)
                        for value in item["values"]
                    ]
            panels.append(
                {
                    "label": f"N={node_count}, f={(node_count - 1) // 3}",
                    "series": series,
                    "ymin": 0.0,
                }
            )
        payloads[file_stem] = _build_svg_chart(
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
            png_path = _render_png(svg_path)
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
