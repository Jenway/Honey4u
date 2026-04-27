"""Benchmark CLI entrypoints."""

from benchmarks.cli.dumbo_reuse_sweep import main as dumbo_reuse_sweep_main
from benchmarks.cli.tps import main as tps_main

__all__ = [
    "dumbo_reuse_sweep_main",
    "tps_main",
]
