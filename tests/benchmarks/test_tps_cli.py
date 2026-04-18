from __future__ import annotations

import argparse
from types import SimpleNamespace

import pytest

from benchmarks.cli import tps as benchmark_module
from benchmarks.cli.tps import (
    BenchmarkSummary,
    CommunicationStats,
    LatencyStats,
    PeakStats,
    ReuseStats,
    TimingStats,
    _build_benchmark_kwargs,
    _build_consistency_summary,
    _build_svg_line_chart,
    _build_sweep_payload,
    _select_benchmark_runner,
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
        transport_backend="tcp",
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
        communication=CommunicationStats(
            send_events=120,
            send_payload_bytes=2400,
            proposal_ready_events=30,
            proposal_ready_payload_bytes=1800,
            proposal_ready_certificate_bytes=900,
            total_tracked_bytes=5100,
            bytes_per_delivered_transaction=4.25,
        ),
        measured_communication=CommunicationStats(
            send_events=90,
            send_payload_bytes=1800,
            proposal_ready_events=24,
            proposal_ready_payload_bytes=1440,
            proposal_ready_certificate_bytes=720,
            total_tracked_bytes=3960,
            bytes_per_delivered_transaction=3.30,
        ),
        reuse=ReuseStats(
            reused_reference_count=12,
            references_per_delivered_transaction=0.01,
        ),
        measured_reuse=ReuseStats(
            reused_reference_count=9,
            references_per_delivered_transaction=0.01,
        ),
        subprotocol_timings={
            "hb_round": TimingStats(sample_count=30, mean_ms=12.0, max_ms=18.0),
        },
        queue_backlog={
            "raw_inbound_messages": PeakStats(mean=20.0, p95=30.0, max=batch_size * 2),
        },
        node_runtime="rust-driver",
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
        transport_backend="tcp",
        node_runtime="rust-driver",
    )

    summaries = [
        _summary(batch_size=128, measured_tps=1200.0, measured_ratio=1.0),
        _summary(batch_size=256, measured_tps=1800.0, measured_ratio=0.8),
    ]
    payload = _build_sweep_payload(args, summaries)

    assert payload["meta"]["x_axis"] == "batch_size"
    assert payload["meta"]["num_nodes"] == 10
    assert payload["meta"]["tx_input"] == "json_str"
    assert payload["meta"]["transport_backend"] == "tcp"
    assert payload["meta"]["node_runtime"] == "rust-driver"
    assert len(payload["points"]) == 2
    assert payload["points"][0]["batch_size"] == 128
    assert payload["points"][0]["tx_input"] == "json_str"
    assert payload["points"][0]["transport_backend"] == "tcp"
    assert payload["points"][0]["node_runtime"] == "rust-driver"
    assert payload["points"][0]["measured_fetch"]["fetch_requests_sent"] == 0
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


def test_build_consistency_summary_flags_divergence() -> None:
    agree, digest, diverged = _build_consistency_summary(
        [
            SimpleNamespace(pid=0, chain_digest="abc"),
            SimpleNamespace(pid=1, chain_digest="abc"),
            SimpleNamespace(pid=2, chain_digest="xyz"),
        ]
    )

    assert agree is False
    assert digest is None
    assert diverged == (2,)


def _args(*, protocol: str, node_runtime: str) -> argparse.Namespace:
    return argparse.Namespace(
        sid="bench:local:test",
        protocol=protocol,
        acs_protocol="hb",
        nodes=4,
        faulty=1,
        batch_size=8,
        sweep_batches=None,
        rounds=3,
        warmup_rounds=0,
        transactions_per_node=24,
        tx_input="json_str",
        transport_backend="tcp",
        node_runtime=node_runtime,
        round_timeout=20.0,
        global_timeout=120.0,
        log_level="ERROR",
        enable_pool_reuse=True,
        enable_pool_reference_proposals=True,
        enable_pool_fetch=True,
        pool_grace_ms=250,
        rust_tx_pool_max_bytes=4096,
        network_fixed_delay_ms=0,
        network_jitter_ms=0,
        network_seed=0,
        slow_honest_pids=None,
        slow_honest_extra_delay_ms=0,
        output_json=None,
        ledger_dir="/tmp/ledger",
        fail_on_divergence=False,
        output_svg=None,
        json=False,
    )


def test_select_benchmark_runner_matches_protocol_and_runtime() -> None:
    assert _select_benchmark_runner("hb", "rust-driver") is (
        benchmark_module.benchmark_local_honeybadger_nodes_rust_driven
    )
    assert _select_benchmark_runner("dumbo", "rust-driver") is (
        benchmark_module.benchmark_local_dumbo_nodes_rust_driven
    )


def test_build_benchmark_kwargs_for_rust_driver_runtime_omits_node_runtime() -> None:
    kwargs = _build_benchmark_kwargs(
        _args(protocol="hb", node_runtime="rust-driver"),
        sid="bench:test:rust-driver",
        faulty=1,
        batch_size=8,
        transactions_per_node=24,
    )

    assert kwargs["global_timeout"] == 120.0
    assert "node_runtime" not in kwargs
    assert kwargs["rust_tx_pool_max_bytes"] == 4096
    assert kwargs["acs_protocol"] == "hb"


def test_build_benchmark_kwargs_includes_network_faults_when_configured() -> None:
    args = _args(protocol="dumbo", node_runtime="rust-driver")
    args.network_fixed_delay_ms = 5
    args.network_jitter_ms = 7
    args.network_seed = 42
    args.slow_honest_pids = "1,3"
    args.slow_honest_extra_delay_ms = 20

    kwargs = _build_benchmark_kwargs(
        args,
        sid="bench:test:dumbo:network-faults",
        faulty=1,
        batch_size=8,
        transactions_per_node=24,
    )

    assert kwargs["network_faults"] == {
        "enabled": True,
        "seed": 42,
        "fixed_delay_ms": 5,
        "jitter_ms": 7,
        "slow_honest": {"pids": [1, 3], "extra_delay_ms": 20},
    }


def test_build_benchmark_kwargs_rejects_slow_honest_delay_without_pids() -> None:
    args = _args(protocol="dumbo", node_runtime="rust-driver")
    args.slow_honest_extra_delay_ms = 20

    with pytest.raises(ValueError, match="--slow-honest-pids"):
        _build_benchmark_kwargs(
            args,
            sid="bench:test:dumbo:invalid-network-faults",
            faulty=1,
            batch_size=8,
            transactions_per_node=24,
        )


def test_build_benchmark_kwargs_for_rust_driver_with_dumbo_acs_includes_provider_config() -> None:
    args = _args(protocol="hb", node_runtime="rust-driver")
    args.acs_protocol = "dumbo"

    kwargs = _build_benchmark_kwargs(
        args,
        sid="bench:test:rust-driver:dumbo-acs",
        faulty=1,
        batch_size=8,
        transactions_per_node=24,
    )

    assert kwargs["acs_protocol"] == "dumbo"
    assert kwargs["enable_broadcast_pool_reuse"] is True
    assert kwargs["pool_grace_ms"] == 250


def test_build_benchmark_kwargs_for_dumbo_rust_driver_omits_pool_fetch_only_flags() -> None:
    kwargs = _build_benchmark_kwargs(
        _args(protocol="dumbo", node_runtime="rust-driver"),
        sid="bench:test:dumbo:rust-driver",
        faulty=1,
        batch_size=8,
        transactions_per_node=24,
    )

    assert kwargs["enable_broadcast_pool_reuse"] is True
    assert kwargs["pool_grace_ms"] == 250
    assert "enable_pool_reference_proposals" not in kwargs
    assert "enable_pool_fetch_fallback" not in kwargs


def test_select_benchmark_runner_rejects_removed_embedded_runtime() -> None:
    with pytest.raises(ValueError, match="embedded"):
        _select_benchmark_runner("hb", "embedded")


def test_select_benchmark_runner_rejects_removed_bridge_runtime() -> None:
    with pytest.raises(ValueError, match="bridge"):
        _select_benchmark_runner("hb", "bridge")


def test_select_benchmark_runner_rejects_removed_hosted_runtime() -> None:
    with pytest.raises(ValueError, match="rust"):
        _select_benchmark_runner("hb", "rust")
