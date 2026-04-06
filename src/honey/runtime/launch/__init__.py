"""Canonical runtime launch entrypoints."""

from honey.runtime.launch.local_runner import (
    benchmark_local_dumbo_nodes_multiprocess,
    benchmark_local_dumbo_nodes_rust_hosted,
    benchmark_local_honeybadger_nodes_multiprocess,
    benchmark_local_honeybadger_nodes_rust_driven,
    benchmark_local_honeybadger_nodes_rust_hosted,
    run_local_dumbo_acs_rust_driven,
    run_local_honeybadger_acs_rust_driven,
    run_local_honeybadger_rust_driven,
    run_local_honeybadger_nodes_deterministic,
)

__all__ = [
    "benchmark_local_dumbo_nodes_multiprocess",
    "benchmark_local_dumbo_nodes_rust_hosted",
    "benchmark_local_honeybadger_nodes_multiprocess",
    "benchmark_local_honeybadger_nodes_rust_driven",
    "benchmark_local_honeybadger_nodes_rust_hosted",
    "run_local_dumbo_acs_rust_driven",
    "run_local_honeybadger_nodes_deterministic",
    "run_local_honeybadger_acs_rust_driven",
    "run_local_honeybadger_rust_driven",
]
