from typing import Any

import pytest

from benchmarks.support.runners import (
    benchmark_local_dumbo_nodes_rust_driven,
    benchmark_local_honeybadger_nodes_rust_driven,
    run_local_dumbo_acs_rust_driven,
    run_local_dumbo_rust_driven,
    run_local_honeybadger_acs_rust_driven,
    run_local_honeybadger_rust_driven,
)


def _assert_transport_stats_populated(results: list[Any]) -> None:
    assert all(result.transport_stats.sent_frames > 0 for result in results)
    assert all(result.transport_stats.recv_frames > 0 for result in results)


def test_local_honeybadger_acs_can_be_rust_driven_with_persistent_python_hosts() -> None:
    result = run_local_honeybadger_acs_rust_driven(
        sid="test:drive-acs:hb",
        num_nodes=4,
        faulty=1,
        max_rounds=2,
        global_timeout=10.0,
    )

    assert result.protocol == "hb"
    assert len(result.nodes) == 4
    assert len(result.rounds) == 2
    assert len({node.worker_ident for node in result.nodes}) == 4
    assert all(node.worker_running is True for node in result.nodes)
    assert all(node.worker_error is None for node in result.nodes)
    assert all(node.rounds_started == 2 for node in result.nodes)
    assert all(node.rounds_finished == 2 for node in result.nodes)
    assert all(node.processed_commands > 0 for node in result.nodes)
    assert all(node.bridge_queue_size == 0 for node in result.nodes)
    assert [round_data.selected_count for round_data in result.rounds] == [4, 4]
    assert all(round_data.selected_pids == (0, 1, 2, 3) for round_data in result.rounds)
    assert all(round_data.send_events > 0 for round_data in result.rounds)
    assert all(round_data.drive_stats.sweep_count > 0 for round_data in result.rounds)
    assert all(len(round_data.drive_stats.host_stats) == 4 for round_data in result.rounds)
    assert all(round_data.drive_stats.total_pulled_events > 0 for round_data in result.rounds)


def test_local_honeybadger_outer_can_be_rust_driven_with_persistent_python_hosts() -> None:
    result = run_local_honeybadger_rust_driven(
        sid="test:drive-hb:outer",
        num_nodes=4,
        faulty=1,
        batch_size=2,
        max_rounds=2,
        global_timeout=10.0,
    )

    assert result.protocol == "hb"
    assert result.acs_protocol == "hb"
    assert len(result.nodes) == 4
    assert len(result.rounds) == 2
    assert len({node.worker_ident for node in result.nodes}) == 4
    assert all(node.worker_running is True for node in result.nodes)
    assert all(node.worker_error is None for node in result.nodes)
    assert all(node.rounds_started == 2 for node in result.nodes)
    assert all(node.rounds_finished == 2 for node in result.nodes)
    assert all(node.processed_commands > 0 for node in result.nodes)
    assert all(node.bridge_queue_size == 0 for node in result.nodes)
    assert [round_data.selected_count for round_data in result.rounds] == [4, 4]
    assert all(round_data.acs_send_events > 0 for round_data in result.rounds)
    assert all(round_data.tpke_bundle_events == 4 for round_data in result.rounds)
    assert all(round_data.delivered_count == 8 for round_data in result.rounds)
    assert all(round_data.block_size > 0 for round_data in result.rounds)
    assert all(round_data.acs_drive_stats.sweep_count > 0 for round_data in result.rounds)
    assert all(len(round_data.acs_drive_stats.host_stats) == 4 for round_data in result.rounds)
    assert all(round_data.acs_drive_stats.total_pull_seconds >= 0.0 for round_data in result.rounds)


@pytest.mark.parametrize("broadcast_mempool_backend", ["none", "rust"])
def test_local_honeybadger_outer_supports_non_python_broadcast_pools(
    broadcast_mempool_backend: str,
) -> None:
    result = run_local_honeybadger_rust_driven(
        sid=f"test:drive-hb:outer:{broadcast_mempool_backend}",
        num_nodes=4,
        faulty=1,
        batch_size=1,
        max_rounds=1,
        global_timeout=10.0,
        broadcast_mempool_backend=broadcast_mempool_backend,
    )

    assert result.protocol == "hb"
    assert result.acs_protocol == "hb"
    assert len(result.nodes) == 4
    assert len(result.rounds) == 1
    assert all(node.worker_error is None for node in result.nodes)
    assert result.rounds[0].selected_count == 4
    assert result.rounds[0].delivered_count == 4


def test_local_honeybadger_outer_can_be_rust_driven_with_dumbo_acs_provider() -> None:
    result = run_local_honeybadger_rust_driven(
        sid="test:drive-hb:outer:dumbo-acs",
        num_nodes=4,
        faulty=1,
        batch_size=1,
        max_rounds=1,
        global_timeout=10.0,
        acs_protocol="dumbo",
    )

    assert result.protocol == "hb"
    assert result.acs_protocol == "dumbo"
    assert len(result.nodes) == 4
    assert len(result.rounds) == 1
    assert result.rounds[0].selected_count >= 3
    assert result.rounds[0].delivered_count >= 3
    assert result.rounds[0].block_size > 0


def test_local_honeybadger_benchmark_rust_driven_reports_round_stats() -> None:
    results = benchmark_local_honeybadger_nodes_rust_driven(
        sid="test:drive-hb:benchmark",
        num_nodes=4,
        faulty=1,
        batch_size=2,
        max_rounds=2,
        global_timeout=10.0,
        transactions_per_node=4,
        log_level="ERROR",
    )

    assert len(results) == 4
    assert all(result.rounds == 2 for result in results)
    assert all(result.delivered == 16 for result in results)
    assert all(result.round_proposed_counts == (2, 2) for result in results)
    assert all(result.round_delivered_counts == (8, 8) for result in results)
    assert all(len(result.round_build_latencies) == 2 for result in results)
    assert all(len(result.round_latencies) == 2 for result in results)
    assert all(len(result.round_wall_latencies) == 2 for result in results)
    assert all(all(latency > 0.0 for latency in result.round_wall_latencies) for result in results)
    assert all("hb.round.seconds" in result.subprotocol_timings for result in results)
    assert all("tpke.partial_open.seconds" in result.subprotocol_timings for result in results)
    assert len({result.chain_digest for result in results}) == 1
    _assert_transport_stats_populated(results)


def test_local_dumbo_outer_can_be_rust_driven_with_persistent_python_hosts() -> None:
    result = run_local_dumbo_rust_driven(
        sid="test:drive-dumbo:outer",
        num_nodes=4,
        faulty=1,
        batch_size=1,
        max_rounds=1,
        global_timeout=10.0,
    )

    assert result.protocol == "dumbo"
    assert result.nodes_count == 4
    assert result.faulty == 1
    assert len(result.nodes) == 4
    assert len(result.rounds) == 1
    assert len({node.worker_ident for node in result.nodes}) == 4
    assert all(node.worker_running is True for node in result.nodes)
    assert all(node.worker_error is None for node in result.nodes)
    assert all(node.rounds_started == 1 for node in result.nodes)
    assert all(node.rounds_finished == 1 for node in result.nodes)
    assert result.rounds[0].selected_count >= 3
    assert result.rounds[0].delivered_count >= 3
    assert result.rounds[0].block_size > 0


def test_local_dumbo_benchmark_rust_driven_reports_round_stats() -> None:
    results = benchmark_local_dumbo_nodes_rust_driven(
        sid="test:drive-dumbo:benchmark",
        num_nodes=4,
        faulty=1,
        batch_size=2,
        max_rounds=2,
        global_timeout=10.0,
        transactions_per_node=4,
        log_level="ERROR",
    )

    assert len(results) == 4
    assert all(result.rounds == 2 for result in results)
    assert all(result.delivered >= 12 for result in results)
    assert all(result.round_proposed_counts == (2, 2) for result in results)
    assert all(len(result.round_delivered_counts) == 2 for result in results)
    assert all(all(count >= 6 for count in result.round_delivered_counts) for result in results)
    assert all(len(result.round_build_latencies) == 2 for result in results)
    assert all(len(result.round_latencies) == 2 for result in results)
    assert all(len(result.round_wall_latencies) == 2 for result in results)
    assert all(all(latency > 0.0 for latency in result.round_wall_latencies) for result in results)
    assert all("hb.round.seconds" in result.subprotocol_timings for result in results)
    assert all("tpke.partial_open.seconds" in result.subprotocol_timings for result in results)
    assert len({result.chain_digest for result in results}) == 1
    _assert_transport_stats_populated(results)


def test_local_dumbo_acs_can_be_rust_driven_with_persistent_python_hosts() -> None:
    result = run_local_dumbo_acs_rust_driven(
        sid="test:drive-acs:dumbo",
        num_nodes=4,
        faulty=1,
        max_rounds=1,
        global_timeout=10.0,
    )

    assert result.protocol == "dumbo"
    assert len(result.nodes) == 4
    assert len(result.rounds) == 1
    assert len({node.worker_ident for node in result.nodes}) == 4
    assert all(node.worker_running is True for node in result.nodes)
    assert all(node.worker_error is None for node in result.nodes)
    assert all(node.rounds_started == 1 for node in result.nodes)
    assert all(node.rounds_finished == 1 for node in result.nodes)
    assert all(node.processed_commands > 0 for node in result.nodes)
    assert all(node.bridge_queue_size == 0 for node in result.nodes)
    assert result.rounds[0].selected_count >= 3
    assert result.rounds[0].send_events > 0
