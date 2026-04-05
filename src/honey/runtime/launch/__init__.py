"""Canonical runtime launch entrypoints."""

from honey.runtime.launch.local_runner import (
    benchmark_local_dumbo_nodes_multiprocess,
    benchmark_local_dumbo_nodes_rust_hosted,
    benchmark_local_honeybadger_nodes_multiprocess,
    benchmark_local_honeybadger_nodes_rust_hosted,
    run_local_honeybadger_nodes_deterministic,
)

__all__ = [
    "benchmark_local_dumbo_nodes_multiprocess",
    "benchmark_local_dumbo_nodes_rust_hosted",
    "benchmark_local_honeybadger_nodes_multiprocess",
    "benchmark_local_honeybadger_nodes_rust_hosted",
    "run_local_honeybadger_nodes_deterministic",
]
