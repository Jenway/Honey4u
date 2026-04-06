"""Runtime runner entrypoints grouped by execution mode."""

from honey.runtime.runners.bridge import (
    benchmark_local_dumbo_nodes_multiprocess,
    benchmark_local_honeybadger_nodes_multiprocess,
    run_local_dumbo_nodes_multiprocess,
    run_local_honeybadger_nodes_deterministic,
    run_local_honeybadger_nodes_multiprocess,
)
from honey.runtime.runners.results import (
    MetricTimingSummary,
    MultiprocessNodeResult,
    NodeQueuePeaks,
    RustDrivenAcsNodeResult,
    RustDrivenAcsRoundResult,
    RustDrivenAcsRunResult,
    RustDrivenHoneyBadgerRoundResult,
    RustDrivenHoneyBadgerRunResult,
    TransportStats,
)
from honey.runtime.runners.rust_driver import (
    benchmark_local_honeybadger_nodes_rust_driven,
    run_local_dumbo_acs_rust_driven,
    run_local_honeybadger_acs_rust_driven,
    run_local_honeybadger_rust_driven,
)
from honey.runtime.runners.rust_hosted import (
    _build_honey_node_binary,
    benchmark_local_dumbo_nodes_rust_hosted,
    benchmark_local_honeybadger_nodes_rust_hosted,
)

__all__ = [
    "MetricTimingSummary",
    "MultiprocessNodeResult",
    "NodeQueuePeaks",
    "RustDrivenAcsNodeResult",
    "RustDrivenAcsRoundResult",
    "RustDrivenAcsRunResult",
    "RustDrivenHoneyBadgerRoundResult",
    "RustDrivenHoneyBadgerRunResult",
    "TransportStats",
    "_build_honey_node_binary",
    "benchmark_local_dumbo_nodes_multiprocess",
    "benchmark_local_dumbo_nodes_rust_hosted",
    "benchmark_local_honeybadger_nodes_multiprocess",
    "benchmark_local_honeybadger_nodes_rust_driven",
    "benchmark_local_honeybadger_nodes_rust_hosted",
    "run_local_dumbo_acs_rust_driven",
    "run_local_dumbo_nodes_multiprocess",
    "run_local_honeybadger_acs_rust_driven",
    "run_local_honeybadger_nodes_deterministic",
    "run_local_honeybadger_nodes_multiprocess",
    "run_local_honeybadger_rust_driven",
]
