from honey.network.hbbft_runner import (
    benchmark_local_dumbo_nodes_multiprocess,
    benchmark_local_honeybadger_nodes_multiprocess,
    run_local_dumbo_nodes_multiprocess,
    run_local_honeybadger_nodes_multiprocess,
)


def test_local_honeybadger_nodes_multiprocess_single_round() -> None:
    rounds = run_local_honeybadger_nodes_multiprocess(
        sid="test:local:multi",
        num_nodes=4,
        faulty=1,
        batch_size=1,
        max_rounds=1,
        round_timeout=5.0,
        global_timeout=30.0,
    )

    assert len(rounds) == 4
    assert all(round_id == 1 for round_id in rounds)


def test_local_honeybadger_benchmark_returns_delivery_and_latency_stats() -> None:
    results = benchmark_local_honeybadger_nodes_multiprocess(
        sid="test:local:benchmark",
        num_nodes=4,
        faulty=1,
        batch_size=1,
        max_rounds=1,
        round_timeout=5.0,
        global_timeout=30.0,
        transactions_per_node=1,
        log_level="ERROR",
    )

    assert len(results) == 4
    assert all(result.rounds == 1 for result in results)
    assert len({result.delivered for result in results}) == 1
    assert results[0].delivered > 0
    assert all(len(result.round_build_latencies) == 1 for result in results)
    assert all(len(result.round_latencies) == 1 for result in results)
    assert all(len(result.round_wall_latencies) == 1 for result in results)
    assert all(result.round_build_latencies[0] >= 0.0 for result in results)
    assert all(result.round_latencies[0] >= 0.0 for result in results)
    assert all(
        result.round_wall_latencies[0] >= result.round_build_latencies[0] for result in results
    )
    assert all(result.round_proposed_counts == (1,) for result in results)
    assert all(result.round_delivered_counts[0] > 0 for result in results)
    assert 0 < sum(len(result.origin_tx_latencies) for result in results) <= 4
    assert all(latency >= 0.0 for result in results for latency in result.origin_tx_latencies)
    assert all(len(result.origin_tx_latencies_by_round) == 1 for result in results)
    assert all("hb.round.seconds" in result.subprotocol_timings for result in results)
    assert all(
        result.subprotocol_timings["hb.round.seconds"].sample_count == 1 for result in results
    )
    assert all(result.queue_peaks.raw_inbound_messages >= 0 for result in results)
    assert all(result.queue_peaks.transport_inbound >= 0 for result in results)


def test_local_dumbo_nodes_multiprocess_single_round() -> None:
    rounds = run_local_dumbo_nodes_multiprocess(
        sid="test:local:dumbo:multi",
        num_nodes=4,
        faulty=1,
        batch_size=1,
        max_rounds=1,
        round_timeout=8.0,
        global_timeout=40.0,
    )

    assert len(rounds) == 4
    assert all(round_id == 1 for round_id in rounds)


def test_local_dumbo_benchmark_returns_delivery_and_latency_stats() -> None:
    results = benchmark_local_dumbo_nodes_multiprocess(
        sid="test:local:dumbo:benchmark",
        num_nodes=4,
        faulty=1,
        batch_size=1,
        max_rounds=1,
        round_timeout=8.0,
        global_timeout=40.0,
        transactions_per_node=1,
        log_level="ERROR",
    )

    assert len(results) == 4
    assert all(result.rounds == 1 for result in results)
    assert len({result.delivered for result in results}) == 1
    assert results[0].delivered > 0
    assert all(len(result.round_build_latencies) == 1 for result in results)
    assert all(len(result.round_latencies) == 1 for result in results)
    assert all(len(result.round_wall_latencies) == 1 for result in results)
    assert all(result.round_build_latencies[0] >= 0.0 for result in results)
    assert all(result.round_latencies[0] >= 0.0 for result in results)
    assert all(
        result.round_wall_latencies[0] >= result.round_build_latencies[0] for result in results
    )
    assert all(result.round_proposed_counts == (1,) for result in results)
    assert all(result.round_delivered_counts[0] > 0 for result in results)
    assert 0 < sum(len(result.origin_tx_latencies) for result in results) <= 4
    assert all(latency >= 0.0 for result in results for latency in result.origin_tx_latencies)
    assert all(len(result.origin_tx_latencies_by_round) == 1 for result in results)
    assert all("hb.round.seconds" in result.subprotocol_timings for result in results)
    assert all(
        result.subprotocol_timings["hb.round.seconds"].sample_count == 1 for result in results
    )
    assert all(result.queue_peaks.raw_inbound_messages >= 0 for result in results)
    assert all(result.queue_peaks.transport_inbound >= 0 for result in results)
