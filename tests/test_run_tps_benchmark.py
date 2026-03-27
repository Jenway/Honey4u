from __future__ import annotations

import argparse

from run_tps_benchmark import (
    BenchmarkSummary,
    LatencyStats,
    PeakStats,
    TimingStats,
    _build_svg_line_chart,
    _build_sweep_payload,
)


def _latency_stats(*, sample_count: int, coverage: float, p95_ms: float) -> LatencyStats:
    return LatencyStats(
        sample_count=sample_count,
        coverage=coverage,
        mean_ms=p95_ms / 2,
        p50_ms=p95_ms / 2,
        p95_ms=p95_ms,
        p99_ms=p95_ms,
        max_ms=p95_ms,
    )


def _summary(batch_size: int, measured_tps: float, measured_ratio: float) -> BenchmarkSummary:
    return BenchmarkSummary(
        sid=f"bench:{batch_size}",
        num_nodes=10,
        faulty=3,
        batch_size=batch_size,
        tx_input="json_str",
        max_rounds=4,
        warmup_rounds=1,
        transactions_per_node=batch_size * 4,
        submitted_transactions=batch_size * 40,
        delivered_transactions=int(batch_size * 40 * measured_ratio),
        delivery_ratio=measured_ratio,
        elapsed_seconds=4.0,
        tps=100.0,
        min_rounds_completed=4,
        max_rounds_completed=4,
        tx_latency=_latency_stats(sample_count=100, coverage=measured_ratio, p95_ms=10.0),
        round_latency=_latency_stats(sample_count=40, coverage=1.0, p95_ms=20.0),
        measured_rounds=3,
        measured_proposed_transactions=batch_size * 30,
        measured_delivered_transactions=int(batch_size * 30 * measured_ratio),
        measured_delivery_ratio=measured_ratio,
        measured_elapsed_seconds=1.5,
        measured_tps=measured_tps,
        measured_build_elapsed_seconds=0.3,
        measured_build_tps=(batch_size * 30) / 0.3,
        measured_protocol_elapsed_seconds=1.5,
        measured_protocol_tps=measured_tps,
        measured_wall_elapsed_seconds=1.8,
        measured_wall_tps=(batch_size * 30 * measured_ratio) / 1.8,
        measured_tx_latency=_latency_stats(
            sample_count=int(batch_size * 30 * measured_ratio),
            coverage=measured_ratio,
            p95_ms=25.0 + batch_size,
        ),
        measured_build_round_latency=_latency_stats(sample_count=30, coverage=1.0, p95_ms=5.0),
        measured_round_latency=_latency_stats(sample_count=30, coverage=1.0, p95_ms=30.0),
        measured_protocol_round_latency=_latency_stats(sample_count=30, coverage=1.0, p95_ms=30.0),
        measured_wall_round_latency=_latency_stats(sample_count=30, coverage=1.0, p95_ms=36.0),
        subprotocol_timings={
            "hb_round": TimingStats(sample_count=30, mean_ms=12.0, max_ms=18.0),
        },
        queue_backlog={
            "raw_inbound_messages": PeakStats(mean=20.0, p95=30.0, max=batch_size * 2),
        },
    )


def test_sweep_payload_includes_benchmark_points() -> None:
    args = argparse.Namespace(
        nodes=10,
        faulty=3,
        rounds=4,
        warmup_rounds=1,
        round_timeout=20.0,
        global_timeout=180.0,
        log_level="ERROR",
        sid="bench:local:hb",
        tx_input="json_str",
    )

    summaries = [
        _summary(batch_size=128, measured_tps=1200.0, measured_ratio=1.0),
        _summary(batch_size=256, measured_tps=1800.0, measured_ratio=0.8),
    ]
    payload = _build_sweep_payload(args, summaries)

    assert payload["meta"]["x_axis"] == "batch_size"
    assert payload["meta"]["num_nodes"] == 10
    assert payload["meta"]["tx_input"] == "json_str"
    assert len(payload["points"]) == 2
    assert payload["points"][0]["batch_size"] == 128
    assert payload["points"][0]["tx_input"] == "json_str"
    assert payload["points"][1]["measured_tps"] == 1800.0
    assert payload["points"][1]["measured_protocol_tps"] == 1800.0
    assert payload["points"][1]["measured_delivery_ratio"] == 0.8


def test_svg_line_chart_renders_expected_labels() -> None:
    svg = _build_svg_line_chart(
        title="Local HoneyBadger sweep",
        subtitle="N=10, f=3",
        x_labels=["128", "256"],
        panels=[
            {
                "label": "Measured TPS",
                "values": [1200.0, 1800.0],
                "color": "#0f766e",
                "ymin": 0.0,
            },
            {
                "label": "Measured Delivery Ratio",
                "values": [1.0, 0.8],
                "color": "#b91c1c",
                "ymin": 0.0,
                "ymax": 1.05,
            },
        ],
        height=520,
    )

    assert "Local HoneyBadger sweep" in svg
    assert "Measured TPS" in svg
    assert "Measured Delivery Ratio" in svg
    assert ">128<" in svg
    assert ">256<" in svg
    assert "Batch size per node per round" in svg
