"""Benchmark CLI entrypoints."""

from benchmarks.cli.acs import main as acs_main
from benchmarks.cli.tps import main as tps_main

__all__ = ["acs_main", "tps_main"]
