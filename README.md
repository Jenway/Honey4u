# Honey4u

Honey4u is a Python 3.14 and Rust codebase for ACS-based asynchronous BFT in the HoneyBadger/Dumbo family.

## Current Architecture

- `src/honey/python_node/`: the remaining Python node implementations and bootstrap helpers.
- `src/honey/acs/`: ACS protocol implementations, now grouped by family under `hb/` and `dumbo/`.
- `src/honey/host/`: persistent Python ACS host bridge, Rust-hosted node glue, and crypto material helpers.
- `src/honey/runtime/transport/` and `src/honey/runtime/routing/`: local transport wrappers and mailbox routing.
- `src/honey/runtime/runners/`: local benchmark and multi-node runner entrypoints for bridge, Rust-hosted, and Rust-driven modes.
- `native/honey-native/`: the PyO3 extension crate exposed as `honey_native`.
- `native/runtime-core/`: shared native runtime support code.
- `native/honey-node/`: the Rust-hosted and Rust-driven node binary.

## Benchmarks And Tools

- TPS benchmark CLI: `benchmarks/cli/tps.py`
- ACS benchmark CLI: `benchmarks/cli/acs.py`
- Benchmark plots: `benchmarks/plots/compare.py`
- Native key generation helper: `tools/keys/generate_native.py`

## Scope

This repository is intentionally scoped to ACS-based asynchronous BFT with a HoneyBadger-style outer shell. It is not trying to stay generic for DAG-style or dispersed-ledger protocol families.
