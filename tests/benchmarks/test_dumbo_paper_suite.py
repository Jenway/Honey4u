from __future__ import annotations

from benchmarks.cli.dumbo_paper_suite import (
    _build_run_record,
    _expand_experiment,
    _render_config,
)


def test_render_config_supports_nested_network_faults_inline_tables() -> None:
    rendered = _render_config(
        sid="bench:test:paper",
        nodes=4,
        faulty=1,
        rounds=3,
        batch_size=8,
        global_timeout=90.0,
        config_payload={
            "acs_host_backend": "rust_fin",
            "network_faults": {
                "enabled": True,
                "fixed_delay_ms": 5,
                "slow_honest": {
                    "pids": [3],
                    "extra_delay_ms": 20,
                },
            },
        },
    )

    assert (
        "network_faults = { enabled = true, fixed_delay_ms = 5, slow_honest = { pids = [3], extra_delay_ms = 20 } }"
        in rendered
    )


def test_render_config_supports_byzantine_nodes_inline_tables() -> None:
    rendered = _render_config(
        sid="bench:test:paper:byzantine",
        nodes=4,
        faulty=1,
        rounds=3,
        batch_size=8,
        global_timeout=90.0,
        config_payload={
            "acs_host_backend": "rust_fin",
            "byzantine_nodes": [
                {"pid": 3, "behavior": "silent"},
            ],
        },
    )

    assert 'byzantine_nodes = [{ pid = 3, behavior = "silent" }]' in rendered


def test_expand_experiment_generates_network_fault_labels() -> None:
    metadata, cases = _expand_experiment(
        {
            "name": "network_fault_labels",
            "backend": ["rust_fin"],
            "nodes": [4],
            "batch_size": [8],
            "rounds": [3],
            "global_timeout": [90.0],
            "network_faults": [
                {"enabled": False},
                {"label": "Fixed 5ms", "enabled": True, "fixed_delay_ms": 5},
            ],
        },
        defaults={},
    )

    assert metadata["case_count"] == 2
    assert [case["network_fault_label"] for case in cases] == ["none", "fixed-5ms"]


def test_build_run_record_includes_network_fault_and_transport_metrics() -> None:
    case = {
        "backend": "rust_fin",
        "reuse_enabled": True,
        "nodes": 4,
        "faulty": 1,
        "batch_size": 8,
        "rounds": 3,
        "global_timeout": 90.0,
        "pool_grace_ms": 100,
        "pool_reuse_limit_per_round": 4,
        "pool_expire_rounds": 5,
        "pool_mempool_max": 512,
        "enable_pool_reference_proposals": True,
        "enable_pool_fetch_fallback": True,
        "network_faults": {
            "label": "fixed5",
            "enabled": True,
            "seed": 42,
            "fixed_delay_ms": 5,
            "slow_honest": {"pids": [3], "extra_delay_ms": 20},
        },
        "network_fault_label": "fixed5",
        "byzantine_nodes": [{"pid": 3, "behavior": "silent"}],
        "byzantine_label": "silent-p3",
    }
    result = {
        "chain_digest": "abc",
        "rounds": [
            {
                "delivered_count": 16,
                "wall_seconds": 0.5,
                "acs_seconds": 0.4,
                "reused_reference_count": 2,
                "fetch_requests_sent": 1,
                "fetch_responses_served": 1,
                "fetch_responses_received": 1,
                "fetched_reference_count": 1,
                "acs_drive_stats": {
                    "send_events": 10,
                    "send_payload_bytes": 100,
                    "proposal_ready_events": 4,
                    "proposal_ready_payload_bytes": 20,
                    "proposal_ready_certificate_bytes": 8,
                },
            }
        ],
        "nodes": [
            {
                "transport_sent_frames": 20,
                "transport_recv_frames": 18,
                "transport_connect_retries": 0,
                "transport_delayed_frames": 6,
                "transport_total_injected_delay_ms": 30,
            },
            {
                "transport_sent_frames": 22,
                "transport_recv_frames": 19,
                "transport_connect_retries": 1,
                "transport_delayed_frames": 7,
                "transport_total_injected_delay_ms": 35,
                "byzantine_empty_proposal_rounds": 1,
                "byzantine_batch_broadcast_suppressed": 1,
            },
        ],
    }

    record = _build_run_record(
        experiment="network_fixed_delay_n12",
        case=case,
        repeat_index=0,
        elapsed_seconds=0.75,
        result=result,
    )

    assert record["network_fault_label"] == "fixed5"
    assert record["network_fixed_delay_ms"] == 5
    assert record["network_seed"] == 42
    assert record["network_slow_honest_pids"] == (3,)
    assert record["byzantine_label"] == "silent-p3"
    assert record["byzantine_nodes"] == ((3, "silent"),)
    assert record["transport_delayed_frames_total"] == 13
    assert record["transport_injected_delay_ms_total"] == 65
    assert record["transport_max_injected_delay_ms_per_node"] == 35
    assert record["byzantine_empty_proposal_rounds_total"] == 1
    assert record["byzantine_batch_broadcast_suppressed_total"] == 1
