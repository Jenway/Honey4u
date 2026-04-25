"""Benchmark CLI entrypoints."""

from benchmarks.cli.dumbo_backend_reuse_compare import main as dumbo_backend_reuse_compare_main
from benchmarks.cli.dumbo_paper_suite import main as dumbo_paper_suite_main
from benchmarks.cli.dumbo_reuse_sweep import main as dumbo_reuse_sweep_main
from benchmarks.cli.tps import main as tps_main

__all__ = [
    "dumbo_backend_reuse_compare_main",
    "dumbo_paper_suite_main",
    "dumbo_reuse_sweep_main",
    "tps_main",
]
