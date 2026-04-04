from __future__ import annotations

import argparse
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import fmean
from typing import Any

from honey.network.hbbft_runner import (
    benchmark_local_dumbo_nodes_multiprocess,
    benchmark_local_dumbo_nodes_rust_hosted,
    benchmark_local_dumbo_nodes_single_process,
    benchmark_local_honeybadger_nodes_multiprocess,
    benchmark_local_honeybadger_nodes_rust_hosted,
    benchmark_local_honeybadger_nodes_single_process,
)


@dataclass(frozen=True)
class LatencyStats:
    sample_count: int
    coverage: float
    mean_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float


@dataclass(frozen=True)
class TimingStats:
    sample_count: int
    mean_ms: float
    max_ms: float


@dataclass(frozen=True)
class PeakStats:
    mean: float
    p95: float
    max: int


@dataclass(frozen=True)
class BenchmarkSummary:
    sid: str
    num_nodes: int
    faulty: int
    batch_size: int
    tx_input: str
    transport_backend: str
    max_rounds: int
    warmup_rounds: int
    transactions_per_node: int
    submitted_transactions: int
    delivered_transactions: int
    delivery_ratio: float
    elapsed_seconds: float
    tps: float
    min_rounds_completed: int
    max_rounds_completed: int
    tx_latency: LatencyStats
    round_latency: LatencyStats
    measured_rounds: int
    measured_proposed_transactions: int
    measured_delivered_transactions: int
    measured_delivery_ratio: float
    measured_elapsed_seconds: float
    measured_tps: float
    measured_build_elapsed_seconds: float
    measured_build_tps: float
    measured_protocol_elapsed_seconds: float
    measured_protocol_tps: float
    measured_wall_elapsed_seconds: float
    measured_wall_tps: float
    measured_tx_latency: LatencyStats
    measured_build_round_latency: LatencyStats
    measured_round_latency: LatencyStats
    measured_protocol_round_latency: LatencyStats
    measured_wall_round_latency: LatencyStats
    subprotocol_timings: dict[str, TimingStats]
    queue_backlog: dict[str, PeakStats]
    node_runtime: str = "bridge"
    all_nodes_agree: bool = True
    consensus_chain_digest: str | None = None
    diverged_pids: tuple[int, ...] = ()
    ledger_root: str | None = None


_QUEUE_PEAK_FIELDS = (
    "raw_inbound_messages",
    "raw_outbound_messages",
    "transport_inbound",
    "transport_outbound",
    "mailbox_round_inbox",
)


_SUBPROTOCOL_LABELS = {
    "hb.round.seconds": "hb_round",
    "rbc.encode.seconds": "rbc_encode",
    "rbc.decode.seconds": "rbc_decode",
    "tpke.encrypt.seconds": "tpke_encrypt",
    "tpke.partial_open.seconds": "tpke_partial_open",
    "tpke.combine.seconds": "tpke_combine",
    "node.run.seconds": "node_run",
}


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark local HoneyBadgerBFT TPS")
    parser.add_argument("--sid", type=str, default="bench:local:hb")
    parser.add_argument("--protocol", type=str, choices=("hb", "dumbo"), default="hb")
    parser.add_argument("--nodes", type=int, default=10, help="number of nodes")
    parser.add_argument(
        "--faulty",
        type=int,
        default=None,
        help="fault tolerance, default=floor((N-1)/3)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=8,
        help="transactions proposed by each node per round",
    )
    parser.add_argument(
        "--sweep-batches",
        type=str,
        default=None,
        help="comma-separated batch sizes for sweep mode, e.g. 128,256,512,1024",
    )
    parser.add_argument("--rounds", type=int, default=3, help="number of rounds")
    parser.add_argument(
        "--warmup-rounds", type=int, default=0, help="rounds to exclude from measured stats"
    )
    parser.add_argument(
        "--transactions-per-node",
        type=int,
        default=None,
        help="transactions queued per node before the run, default=batch-size*rounds",
    )
    parser.add_argument(
        "--tx-input",
        type=str,
        choices=("json_str", "bytes"),
        default="json_str",
        help="how benchmark workers submit dummy transactions into the local node",
    )
    parser.add_argument(
        "--transport-backend",
        type=str,
        choices=("tcp", "quic"),
        default="tcp",
        help="which real socket transport backend to use for multiprocess runs",
    )
    parser.add_argument(
        "--node-runtime",
        type=str,
        choices=("bridge", "embedded", "python", "rust"),
        default="rust",
        help="node runtime mode: python (queue), rust (native), or explicit bridge/embedded",
    )
    parser.add_argument(
        "--round-timeout", type=float, default=20.0, help="per-round timeout seconds"
    )
    parser.add_argument(
        "--global-timeout", type=float, default=120.0, help="overall timeout seconds"
    )
    parser.add_argument("--log-level", type=str, default="ERROR", help="process log level")
    parser.add_argument(
        "--enable-pool-reuse", action="store_true", help="enable Dumbo broadcast pool reuse"
    )
    parser.add_argument(
        "--enable-pool-reference-proposals",
        action="store_true",
        help="allow Dumbo to propose pool references",
    )
    parser.add_argument(
        "--enable-pool-fetch",
        action="store_true",
        help="allow Dumbo to fetch missing pool references",
    )
    parser.add_argument(
        "--pool-grace-ms",
        type=int,
        default=200,
        help="grace period for collecting Dumbo carry-over PRBC outputs",
    )
    parser.add_argument(
        "--rust-tx-pool-max-bytes",
        type=int,
        default=0,
        help="optional byte cap for each Rust tx pool batch; 0 means unlimited",
    )
    parser.add_argument(
        "--output-json", type=str, default=None, help="write JSON output to this path"
    )
    parser.add_argument(
        "--ledger-dir",
        type=str,
        default=None,
        help="persist each node's decided blocks as SQLite ledgers under this directory",
    )
    parser.add_argument(
        "--fail-on-divergence",
        action="store_true",
        help="exit with an error if node chain digests diverge",
    )
    parser.add_argument(
        "--output-svg", type=str, default=None, help="write SVG plot to this path in sweep mode"
    )
    parser.add_argument("--json", action="store_true", help="print the result as JSON only")
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


def _build_latency_stats(samples_seconds: list[float], expected_count: int) -> LatencyStats:
    coverage = (len(samples_seconds) / expected_count) if expected_count else 0.0
    if not samples_seconds:
        return LatencyStats(
            sample_count=0,
            coverage=coverage,
            mean_ms=0.0,
            p50_ms=0.0,
            p95_ms=0.0,
            p99_ms=0.0,
            max_ms=0.0,
        )

    samples_ms = sorted(sample * 1000.0 for sample in samples_seconds)
    return LatencyStats(
        sample_count=len(samples_ms),
        coverage=coverage,
        mean_ms=fmean(samples_ms),
        p50_ms=_percentile(samples_ms, 50),
        p95_ms=_percentile(samples_ms, 95),
        p99_ms=_percentile(samples_ms, 99),
        max_ms=samples_ms[-1],
    )


def _build_timing_stats(results: list[Any]) -> dict[str, TimingStats]:
    aggregated: dict[str, TimingStats] = {}
    for metric_name, label in _SUBPROTOCOL_LABELS.items():
        sample_count = 0
        total_seconds = 0.0
        max_seconds = 0.0
        for result in results:
            summary = result.subprotocol_timings.get(metric_name)
            if summary is None:
                continue
            sample_count += summary.sample_count
            total_seconds += summary.total_seconds
            if summary.max_seconds > max_seconds:
                max_seconds = summary.max_seconds
        aggregated[label] = TimingStats(
            sample_count=sample_count,
            mean_ms=((total_seconds / sample_count) * 1000.0) if sample_count else 0.0,
            max_ms=max_seconds * 1000.0,
        )
    return aggregated


def _build_peak_stats(values: list[int]) -> PeakStats:
    if not values:
        return PeakStats(mean=0.0, p95=0.0, max=0)
    values_float = sorted(float(value) for value in values)
    return PeakStats(
        mean=fmean(values_float),
        p95=_percentile(values_float, 95),
        max=max(values),
    )


def _build_queue_backlog_stats(results: list[Any]) -> dict[str, PeakStats]:
    return {
        field: _build_peak_stats([getattr(result.queue_peaks, field) for result in results])
        for field in _QUEUE_PEAK_FIELDS
    }


def _build_consistency_summary(results: list[Any]) -> tuple[bool, str | None, tuple[int, ...]]:
    if not results:
        return True, None, ()

    groups: dict[str | None, list[int]] = {}
    for result in results:
        groups.setdefault(result.chain_digest, []).append(result.pid)

    if len(groups) == 1:
        return True, results[0].chain_digest, ()

    reference_digest, _ = max(groups.items(), key=lambda item: len(item[1]))
    diverged_pids = tuple(
        sorted(pid for digest, pids in groups.items() if digest != reference_digest for pid in pids)
    )
    return False, None, diverged_pids


def _build_summary(args: argparse.Namespace, *, batch_size: int) -> BenchmarkSummary:
    faulty = args.faulty if args.faulty is not None else (args.nodes - 1) // 3
    transactions_per_node = (
        args.transactions_per_node
        if args.transactions_per_node is not None
        else batch_size * args.rounds
    )
    sid = f"{args.sid}:{args.nodes}:{batch_size}:{args.rounds}:{int(time.time())}"
    warmup_rounds = max(0, min(args.warmup_rounds, args.rounds))

    runtime_alias = {
        "python": "bridge",
        "rust": "rust",
    }
    effective_runtime = runtime_alias.get(args.node_runtime, args.node_runtime)
    use_single_process = args.node_runtime == "python"
    use_rust_hosted = args.node_runtime == "rust"

    if args.protocol == "dumbo":
        benchmark_fn = (
            benchmark_local_dumbo_nodes_single_process
            if use_single_process
            else benchmark_local_dumbo_nodes_rust_hosted
            if use_rust_hosted
            else benchmark_local_dumbo_nodes_multiprocess
        )
    else:
        benchmark_fn = (
            benchmark_local_honeybadger_nodes_single_process
            if use_single_process
            else benchmark_local_honeybadger_nodes_rust_hosted
            if use_rust_hosted
            else benchmark_local_honeybadger_nodes_multiprocess
        )

    start = time.perf_counter()
    benchmark_kwargs = {
        "sid": sid,
        "num_nodes": args.nodes,
        "faulty": faulty,
        "batch_size": batch_size,
        "max_rounds": args.rounds,
        "round_timeout": args.round_timeout,
        "global_timeout": args.global_timeout,
        "transactions_per_node": transactions_per_node,
        "tx_input": args.tx_input,
        "transport_backend": args.transport_backend,
        "node_runtime": effective_runtime,
        "log_level": args.log_level,
        "ledger_dir": getattr(args, "ledger_dir", None),
    }
    if use_single_process:
        benchmark_kwargs.pop("global_timeout")
        benchmark_kwargs.pop("node_runtime")
    if use_rust_hosted:
        benchmark_kwargs.pop("node_runtime")
    if args.protocol == "dumbo":
        benchmark_kwargs.update(
            enable_broadcast_pool_reuse=args.enable_pool_reuse,
            enable_pool_reference_proposals=args.enable_pool_reference_proposals,
            enable_pool_fetch_fallback=args.enable_pool_fetch,
            pool_grace_ms=args.pool_grace_ms,
        )
    else:
        benchmark_kwargs.update(rust_tx_pool_max_bytes=args.rust_tx_pool_max_bytes)
    results = benchmark_fn(**benchmark_kwargs)
    elapsed_seconds = time.perf_counter() - start
    all_nodes_agree, consensus_chain_digest, diverged_pids = _build_consistency_summary(results)

    delivered_counts = [result.delivered for result in results]
    round_counts = [result.rounds for result in results]
    delivered_transactions = min(delivered_counts)
    submitted_transactions = args.nodes * transactions_per_node
    tx_latency_samples = [latency for result in results for latency in result.origin_tx_latencies]
    round_latency_samples = [latency for result in results for latency in result.round_latencies]

    measured_rounds = max(0, args.rounds - warmup_rounds)
    measured_local_proposed_transactions = (
        min(sum(result.round_proposed_counts[warmup_rounds:]) for result in results)
        if results
        else 0
    )
    measured_proposed_transactions = args.nodes * measured_local_proposed_transactions
    measured_delivered_transactions = (
        min(sum(result.round_delivered_counts[warmup_rounds:]) for result in results)
        if results
        else 0
    )
    measured_build_elapsed_seconds = max(
        (sum(result.round_build_latencies[warmup_rounds:]) for result in results),
        default=0.0,
    )
    measured_protocol_elapsed_seconds = max(
        (sum(result.round_latencies[warmup_rounds:]) for result in results),
        default=0.0,
    )
    measured_wall_elapsed_seconds = max(
        (sum(result.round_wall_latencies[warmup_rounds:]) for result in results),
        default=0.0,
    )
    measured_elapsed_seconds = measured_protocol_elapsed_seconds
    measured_tx_latency_samples = [
        latency
        for result in results
        for round_samples in result.origin_tx_latencies_by_round[warmup_rounds:]
        for latency in round_samples
    ]
    measured_build_round_latency_samples = [
        latency for result in results for latency in result.round_build_latencies[warmup_rounds:]
    ]
    measured_protocol_round_latency_samples = [
        latency for result in results for latency in result.round_latencies[warmup_rounds:]
    ]
    measured_wall_round_latency_samples = [
        latency for result in results for latency in result.round_wall_latencies[warmup_rounds:]
    ]
    measured_round_latency_samples = measured_protocol_round_latency_samples

    return BenchmarkSummary(
        sid=sid,
        num_nodes=args.nodes,
        faulty=faulty,
        batch_size=batch_size,
        tx_input=args.tx_input,
        transport_backend=args.transport_backend,
        node_runtime=args.node_runtime,
        max_rounds=args.rounds,
        warmup_rounds=warmup_rounds,
        transactions_per_node=transactions_per_node,
        submitted_transactions=submitted_transactions,
        delivered_transactions=delivered_transactions,
        delivery_ratio=(delivered_transactions / submitted_transactions)
        if submitted_transactions
        else 0.0,
        elapsed_seconds=elapsed_seconds,
        tps=delivered_transactions / elapsed_seconds if elapsed_seconds else 0.0,
        min_rounds_completed=min(round_counts),
        max_rounds_completed=max(round_counts),
        tx_latency=_build_latency_stats(tx_latency_samples, submitted_transactions),
        round_latency=_build_latency_stats(round_latency_samples, args.nodes * args.rounds),
        measured_rounds=measured_rounds,
        measured_proposed_transactions=measured_proposed_transactions,
        measured_delivered_transactions=measured_delivered_transactions,
        measured_delivery_ratio=(
            measured_delivered_transactions / measured_proposed_transactions
            if measured_proposed_transactions
            else 0.0
        ),
        measured_elapsed_seconds=measured_elapsed_seconds,
        measured_tps=(
            measured_delivered_transactions / measured_elapsed_seconds
            if measured_elapsed_seconds
            else 0.0
        ),
        measured_build_elapsed_seconds=measured_build_elapsed_seconds,
        measured_build_tps=(
            measured_proposed_transactions / measured_build_elapsed_seconds
            if measured_build_elapsed_seconds
            else 0.0
        ),
        measured_protocol_elapsed_seconds=measured_protocol_elapsed_seconds,
        measured_protocol_tps=(
            measured_delivered_transactions / measured_protocol_elapsed_seconds
            if measured_protocol_elapsed_seconds
            else 0.0
        ),
        measured_wall_elapsed_seconds=measured_wall_elapsed_seconds,
        measured_wall_tps=(
            measured_delivered_transactions / measured_wall_elapsed_seconds
            if measured_wall_elapsed_seconds
            else 0.0
        ),
        measured_tx_latency=_build_latency_stats(
            measured_tx_latency_samples,
            measured_proposed_transactions,
        ),
        measured_build_round_latency=_build_latency_stats(
            measured_build_round_latency_samples,
            args.nodes * measured_rounds,
        ),
        measured_round_latency=_build_latency_stats(
            measured_round_latency_samples,
            args.nodes * measured_rounds,
        ),
        measured_protocol_round_latency=_build_latency_stats(
            measured_protocol_round_latency_samples,
            args.nodes * measured_rounds,
        ),
        measured_wall_round_latency=_build_latency_stats(
            measured_wall_round_latency_samples,
            args.nodes * measured_rounds,
        ),
        subprotocol_timings=_build_timing_stats(results),
        queue_backlog=_build_queue_backlog_stats(results),
        all_nodes_agree=all_nodes_agree,
        consensus_chain_digest=consensus_chain_digest,
        diverged_pids=diverged_pids,
        ledger_root=getattr(args, "ledger_dir", None),
    )


def _format_number(value: float) -> str:
    if abs(value) >= 1000:
        return f"{value:,.0f}"
    if value >= 100:
        return f"{value:.0f}"
    if value >= 10:
        return f"{value:.1f}"
    return f"{value:.2f}"


def _build_svg_line_chart(
    *,
    title: str,
    subtitle: str,
    x_labels: list[str],
    panels: list[dict[str, Any]],
    width: int = 1280,
    height: int = 980,
) -> str:
    left = 90
    right = width - 40
    top = 90
    panel_gap = 30
    panel_height = 180
    plot_width = right - left
    chart_height = len(panels) * panel_height + (len(panels) - 1) * panel_gap
    bottom = top + chart_height

    def x_positions() -> list[float]:
        if len(x_labels) == 1:
            return [left + plot_width / 2]
        step = plot_width / (len(x_labels) - 1)
        return [left + idx * step for idx in range(len(x_labels))]

    xs = x_positions()
    lines: list[str] = [
        f"<svg xmlns='http://www.w3.org/2000/svg' width='{width}' height='{height}' viewBox='0 0 {width} {height}'>",
        f"<rect width='{width}' height='{height}' fill='#f7f4ea'/>",
        f"<text x='{left}' y='42' font-size='28' font-family='Segoe UI, Arial, sans-serif' fill='#1f2937' font-weight='700'>{title}</text>",
        f"<text x='{left}' y='68' font-size='14' font-family='Segoe UI, Arial, sans-serif' fill='#6b7280'>{subtitle}</text>",
    ]

    for panel_idx, panel in enumerate(panels):
        y0 = top + panel_idx * (panel_height + panel_gap)
        y1 = y0 + panel_height
        values = [float(value) for value in panel["values"]]
        ymin = float(panel.get("ymin", min(values) if values else 0.0))
        ymax = float(panel.get("ymax", max(values) if values else 1.0))
        if ymax <= ymin:
            ymax = ymin + 1.0

        lines.append(
            f"<text x='{left}' y='{y0 - 12}' font-size='18' font-family='Segoe UI, Arial, sans-serif' fill='#1f2937' font-weight='600'>{panel['label']}</text>"
        )
        lines.append(
            f"<rect x='{left}' y='{y0}' width='{plot_width}' height='{panel_height}' fill='white' stroke='#d6d3d1'/>"
        )

        for tick in range(6):
            ratio = tick / 5
            y = y1 - ratio * panel_height
            tick_value = ymin + ratio * (ymax - ymin)
            lines.append(
                f"<line x1='{left}' y1='{y:.1f}' x2='{right}' y2='{y:.1f}' stroke='#d6d3d1' stroke-dasharray='4 4'/>"
            )
            lines.append(
                f"<text x='{left - 12}' y='{y + 5:.1f}' text-anchor='end' font-size='12' font-family='Segoe UI, Arial, sans-serif' fill='#6b7280'>{_format_number(tick_value)}</text>"
            )

        for x, label in zip(xs, x_labels, strict=True):
            lines.append(
                f"<line x1='{x:.1f}' y1='{y0}' x2='{x:.1f}' y2='{y1}' stroke='#e7e5e4' stroke-dasharray='3 6'/>"
            )
            if panel_idx == len(panels) - 1:
                lines.append(
                    f"<text x='{x:.1f}' y='{bottom + 24}' text-anchor='middle' font-size='12' font-family='Segoe UI, Arial, sans-serif' fill='#6b7280'>{label}</text>"
                )

        def map_y(
            value: float,
            *,
            _y1: float = y1,
            _ymin: float = ymin,
            _ymax: float = ymax,
        ) -> float:
            return _y1 - ((value - _ymin) / (_ymax - _ymin)) * panel_height

        points = " ".join(
            f"{x:.1f},{map_y(value):.1f}" for x, value in zip(xs, values, strict=True)
        )
        color = panel["color"]
        lines.append(
            f"<polyline points='{points}' fill='none' stroke='{color}' stroke-width='4' stroke-linecap='round' stroke-linejoin='round'/>"
        )
        for idx, (x, value) in enumerate(zip(xs, values, strict=True)):
            y = map_y(value)
            lines.append(f"<circle cx='{x:.1f}' cy='{y:.1f}' r='4.5' fill='{color}'/>")
            if idx == len(values) - 1:
                lines.append(
                    f"<text x='{x + 8:.1f}' y='{y - 8:.1f}' font-size='12' font-family='Segoe UI, Arial, sans-serif' fill='#1f2937'>{_format_number(value)}</text>"
                )

    lines.append(
        f"<text x='{left + plot_width / 2:.1f}' y='{bottom + 52}' text-anchor='middle' font-size='14' font-family='Segoe UI, Arial, sans-serif' fill='#1f2937'>Batch size per node per round</text>"
    )
    lines.append("</svg>")
    return "\n".join(lines)


def _build_sweep_payload(
    args: argparse.Namespace, summaries: list[BenchmarkSummary]
) -> dict[str, Any]:
    return {
        "meta": {
            "sid_prefix": args.sid,
            "num_nodes": summaries[0].num_nodes if summaries else args.nodes,
            "faulty": summaries[0].faulty
            if summaries
            else (args.faulty if args.faulty is not None else (args.nodes - 1) // 3),
            "rounds": args.rounds,
            "warmup_rounds": args.warmup_rounds,
            "round_timeout_seconds": args.round_timeout,
            "global_timeout_seconds": args.global_timeout,
            "log_level": args.log_level,
            "tx_input": args.tx_input,
            "transport_backend": args.transport_backend,
            "node_runtime": args.node_runtime,
            "x_axis": "batch_size",
        },
        "points": [asdict(summary) for summary in summaries],
    }


def _write_text(path_str: str, content: str) -> None:
    path = Path(path_str)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _run_single_mode(args: argparse.Namespace) -> dict[str, Any]:
    summary = _build_summary(args, batch_size=args.batch_size)
    payload = asdict(summary)

    if args.output_json:
        _write_text(args.output_json, json.dumps(payload, indent=2, sort_keys=True))

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return payload

    print(
        "Benchmark completed: "
        f"nodes={summary.num_nodes} f={summary.faulty} "
        f"batch={summary.batch_size} rounds={summary.max_rounds} "
        f"tx_input={summary.tx_input} "
        f"submitted={summary.submitted_transactions} delivered={summary.delivered_transactions} "
        f"delivery_ratio={summary.delivery_ratio:.3f} "
        f"elapsed={summary.elapsed_seconds:.3f}s tps={summary.tps:.2f}"
    )
    print(
        "Measured window: "
        f"warmup_rounds={summary.warmup_rounds} measured_rounds={summary.measured_rounds} "
        f"proposed={summary.measured_proposed_transactions} "
        f"delivered={summary.measured_delivered_transactions} "
        f"delivery_ratio={summary.measured_delivery_ratio:.3f}"
    )
    print(
        "Measured timing: "
        f"build_elapsed={summary.measured_build_elapsed_seconds:.3f}s "
        f"build_tps={summary.measured_build_tps:.2f} "
        f"protocol_elapsed={summary.measured_protocol_elapsed_seconds:.3f}s "
        f"protocol_tps={summary.measured_protocol_tps:.2f} "
        f"wall_elapsed={summary.measured_wall_elapsed_seconds:.3f}s "
        f"wall_tps={summary.measured_wall_tps:.2f}"
    )
    print(
        "Consistency: "
        f"agree={'yes' if summary.all_nodes_agree else 'no'} "
        f"chain_digest={summary.consensus_chain_digest or 'n/a'}"
    )
    if summary.ledger_root:
        print(f"Ledger root: {summary.ledger_root}")
    print(json.dumps(payload, indent=2, sort_keys=True))
    if args.fail_on_divergence and not summary.all_nodes_agree:
        raise RuntimeError(f"Node chain digests diverged: {summary.diverged_pids}")
    return payload


def _run_sweep_mode(args: argparse.Namespace) -> dict[str, Any]:
    batch_values = _parse_batch_values(args.sweep_batches, args.batch_size)
    summaries: list[BenchmarkSummary] = []
    for batch_size in batch_values:
        summary = _build_summary(args, batch_size=batch_size)
        summaries.append(summary)
        if args.fail_on_divergence and not summary.all_nodes_agree:
            raise RuntimeError(
                f"Node chain digests diverged for batch={batch_size}: {summary.diverged_pids}"
            )
        if not args.json:
            print(
                f"batch={summary.batch_size} protocol_tps={summary.measured_protocol_tps:.2f} "
                f"wall_tps={summary.measured_wall_tps:.2f} "
                f"measured_ratio={summary.measured_delivery_ratio:.3f} "
                f"p95_tx_latency={summary.measured_tx_latency.p95_ms:.2f}ms "
                f"raw_inbound_peak={summary.queue_backlog['raw_inbound_messages'].max}"
            )

    payload = _build_sweep_payload(args, summaries)
    if args.output_json:
        _write_text(args.output_json, json.dumps(payload, indent=2, sort_keys=True))

    if args.output_svg:
        svg = _build_svg_line_chart(
            title="Local HoneyBadger sweep",
            subtitle=(
                f"N={args.nodes}, f={payload['meta']['faulty']}, rounds={args.rounds}, warmup={args.warmup_rounds}, "
                f"protocol={args.protocol}, local socket transport"
                f", tx_input={args.tx_input}"
            ),
            x_labels=[str(summary.batch_size) for summary in summaries],
            panels=[
                {
                    "label": "Measured Protocol TPS",
                    "values": [summary.measured_protocol_tps for summary in summaries],
                    "color": "#0f766e",
                    "ymin": 0.0,
                },
                {
                    "label": "Measured Wall TPS",
                    "values": [summary.measured_wall_tps for summary in summaries],
                    "color": "#7c3aed",
                    "ymin": 0.0,
                },
                {
                    "label": "Measured Delivery Ratio",
                    "values": [summary.measured_delivery_ratio for summary in summaries],
                    "color": "#b91c1c",
                    "ymin": min(0.0, min(summary.measured_delivery_ratio for summary in summaries)),
                    "ymax": 1.05,
                },
                {
                    "label": "Measured Tx Latency P95 (ms)",
                    "values": [summary.measured_tx_latency.p95_ms for summary in summaries],
                    "color": "#2563eb",
                    "ymin": 0.0,
                },
                {
                    "label": "Raw Inbound Queue Peak",
                    "values": [
                        summary.queue_backlog["raw_inbound_messages"].max for summary in summaries
                    ],
                    "color": "#c2410c",
                    "ymin": 0.0,
                },
            ],
            height=1160,
        )
        _write_text(args.output_svg, svg)

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif args.output_json or args.output_svg:
        outputs = []
        if args.output_json:
            outputs.append(f"json={args.output_json}")
        if args.output_svg:
            outputs.append(f"svg={args.output_svg}")
        print("Sweep artifacts: " + " ".join(outputs))

    return payload


def main() -> None:
    args = _parse_args()
    if args.sweep_batches:
        _run_sweep_mode(args)
        return
    _run_single_mode(args)


if __name__ == "__main__":
    main()
