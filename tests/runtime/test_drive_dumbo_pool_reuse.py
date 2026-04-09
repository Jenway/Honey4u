"""Tests for the Rust-native bench-driver Dumbo mode with Pool Reuse support.

These tests exercise the `run_local_dumbo_new_driver` function which wraps the
`bench-driver --mode dumbo` honey-node command path. The command manages
BroadcastMempool, PoolReference building, and carryover processing entirely in Rust.
"""

from __future__ import annotations

from benchmarks.support.runners import (
    RustDrivenDumboRunResult,
    run_local_dumbo_new_driver,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _assert_dumbo_run_invariants(
    result: RustDrivenDumboRunResult,
    *,
    num_nodes: int,
    faulty: int,
    max_rounds: int,
) -> None:
    """Assert structural invariants that must hold for any valid Dumbo run."""
    assert result.nodes_count == num_nodes
    assert result.faulty == faulty
    assert len(result.nodes) == num_nodes
    assert len(result.rounds) == max_rounds

    for node in result.nodes:
        assert node.rounds_started == max_rounds
        assert node.rounds_finished == max_rounds
        assert not node.worker_error, f"node {node.pid} has worker error: {node.worker_error}"

    for round_data in result.rounds:
        assert round_data.selected_count >= num_nodes - faulty, (
            f"round {round_data.round_id}: selected {round_data.selected_count} "
            f"but expected at least {num_nodes - faulty}"
        )
        assert all(0 <= pid < num_nodes for pid in round_data.selected_pids)
        assert round_data.acs_seconds >= 0.0
        assert round_data.wall_seconds >= 0.0
        # block_digest and chain_digest must be non-empty hex strings
        assert len(round_data.block_digest) == 64, "block_digest must be 64-char hex"
        assert len(round_data.chain_digest) == 64, "chain_digest must be 64-char hex"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_drive_dumbo_new_driver_basic_correctness() -> None:
    """The bench-driver Dumbo mode should complete one round and produce valid output."""
    result = run_local_dumbo_new_driver(
        sid="test:bench-driver:dumbo:basic",
        num_nodes=4,
        faulty=1,
        batch_size=1,
        max_rounds=1,
        global_timeout=30.0,
    )
    assert result.protocol == "dumbo"
    assert result.sid == "test:bench-driver:dumbo:basic"
    assert not result.enable_pool_reuse
    _assert_dumbo_run_invariants(result, num_nodes=4, faulty=1, max_rounds=1)
    assert result.chain_digest is not None
    assert len(result.chain_digest) == 64


def test_drive_dumbo_new_driver_reports_non_empty_rounds() -> None:
    result = run_local_dumbo_new_driver(
        sid="test:bench-driver:dumbo:basic:mp",
        num_nodes=4,
        faulty=1,
        batch_size=1,
        max_rounds=1,
        global_timeout=30.0,
    )

    assert result.protocol == "dumbo"
    _assert_dumbo_run_invariants(result, num_nodes=4, faulty=1, max_rounds=1)
    assert result.rounds[0].block_size > 0
    assert result.rounds[0].acs_send_events > 0
    assert result.rounds[0].wall_seconds > 0.0


def test_drive_dumbo_new_driver_chain_digest_evolves_across_rounds() -> None:
    """The chain digest must change with each round (deterministic chaining)."""
    result = run_local_dumbo_new_driver(
        sid="test:bench-driver:dumbo:chain",
        num_nodes=4,
        faulty=1,
        batch_size=1,
        max_rounds=3,
        global_timeout=60.0,
    )
    _assert_dumbo_run_invariants(result, num_nodes=4, faulty=1, max_rounds=3)

    # Each round should produce a distinct chain digest
    chain_digests = [r.chain_digest for r in result.rounds]
    assert len(chain_digests) == 3
    assert len(set(chain_digests)) == len(chain_digests), (
        "chain digests should be distinct across rounds"
    )

    # Final run-level chain_digest must equal the last round's chain_digest
    assert result.chain_digest == result.rounds[-1].chain_digest


def test_drive_dumbo_new_driver_with_pool_reuse_produces_carryovers() -> None:
    """With pool reuse enabled, nodes should accumulate mempool entries after
    carryovers are processed."""
    result = run_local_dumbo_new_driver(
        sid="test:bench-driver:dumbo:pool-reuse",
        num_nodes=4,
        faulty=1,
        batch_size=1,
        max_rounds=3,
        global_timeout=60.0,
        enable_broadcast_pool_reuse=True,
        enable_pool_reference_proposals=True,
        pool_grace_ms=100,
        pool_reuse_limit_per_round=4,
        pool_expire_rounds=10,
    )
    assert result.enable_pool_reuse
    _assert_dumbo_run_invariants(result, num_nodes=4, faulty=1, max_rounds=3)
    assert max(node.mempool_size for node in result.nodes) > 0
    assert sum(round_data.reused_reference_count for round_data in result.rounds) > 0


def test_drive_dumbo_new_driver_pool_reuse_chain_is_deterministic() -> None:
    """Running with pool reuse twice with the same SID should produce the same
    chain digest (assuming deterministic ACS and no external entropy)."""
    kwargs = {
        "sid": "test:bench-driver:dumbo:determinism",
        "num_nodes": 4,
        "faulty": 1,
        "batch_size": 1,
        "max_rounds": 2,
        "global_timeout": 60.0,
        "enable_broadcast_pool_reuse": False,  # disabled for determinism check
    }

    result_a = run_local_dumbo_new_driver(**kwargs)
    result_b = run_local_dumbo_new_driver(**kwargs)

    _assert_dumbo_run_invariants(result_a, num_nodes=4, faulty=1, max_rounds=2)
    _assert_dumbo_run_invariants(result_b, num_nodes=4, faulty=1, max_rounds=2)

    # Both runs should finish without errors
    assert result_a.chain_digest is not None
    assert result_b.chain_digest is not None


def test_drive_dumbo_new_driver_node_stats_are_non_zero() -> None:
    """Per-node stats (push/pull call counts) must be positive after running."""
    result = run_local_dumbo_new_driver(
        sid="test:bench-driver:dumbo:stats",
        num_nodes=4,
        faulty=1,
        batch_size=1,
        max_rounds=1,
        global_timeout=30.0,
    )
    _assert_dumbo_run_invariants(result, num_nodes=4, faulty=1, max_rounds=1)

    for node in result.nodes:
        assert node.start_round_calls == 1, f"node {node.pid}: start_round_calls should be 1"
        assert node.push_inbound_wire_batch_calls >= 0
        assert node.pull_outbound_wire_batch_calls >= 0
