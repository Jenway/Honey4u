# Honey4u

ACS-based asynchronous BFT in the HoneyBadger/Dumbo family.

## Current Scope

This repository focuses on ACS-family asynchronous BFT protocols in the HoneyBadger / Dumbo line.
The current engineering target is a thesis-oriented prototype for studying and implementing
cross-round broadcast reuse under the Honey4u runtime, not a generic consensus framework.

## Repository Layout

- `Cargo.toml`: root Rust workspace.
- `honey-crypto/`: shared cryptographic primitives and threshold-crypto helpers.
- `honey-wire/`: shared wire types, codecs, archived message formats, and crypto wire helpers.
- `honey-acs/`: Rust ACS protocol crate plus the co-located Python ACS package and PyO3 extension.
- `honey-transport/`: local TCP transport implementation and transport handle abstraction used by
  the Rust driver.
- `honey-node/`: reusable node/driver runtime crate and local TCP runtime logic.
- `honey-bench/`: Rust benchmark package that provides the suite runner `honey-bench`.
- `configs/`: benchmark and thesis experiment configurations, split into `smoke/`, `paper/core/`,
  `paper/appendix/`, `paper/exploratory/`, `legacy/`, and `debug/`. Here `paper/core/` follows
  the current Chapter 4 main experiment narrative in the thesis source.
- `paper/`: thesis sources and local reference material.

The old root-level `packages/` and `native/` prefixes have been removed. Python ACS sources now
live under `honey-acs/packages/honey-acs/`, and the PyO3 extension lives under
`honey-acs/honey-native/`.

## Rust Crates

The Rust crates used by the current driver are:

- `honey-crypto`: BLS/threshold cryptography, ECDSA helpers, AES-GCM, Merkle utilities, and shared
  crypto error types. This crate should not depend on protocol runtime layers.
- `honey-wire`: wire-format and codec layer. It contains API/wire types, `rkyv` codec helpers,
  phase-stat DTOs, and crypto-wire serialization helpers. It may depend on `honey-crypto`, but
  must not depend on `honey-node` or driver runtime code.
- `honey-acs`: ACS protocol layer. It owns the Python-hosted backend adapter plus Rust-native ACS
  backends under `honey-acs/src/backends/rust_fin/`, `rust_dumbo/`, and `rust_hb/`. It also owns
  the co-located Python package and `honey-native` extension source tree.
- `honey-transport`: transport crate used by the node driver. It owns `LocalTcpTransport`,
  `TransportHandle`, wakeup handling, and optional transport backends/features.
- `honey-node`: pure driver/runtime layer. It owns the reusable node runtime API, ledger/keygen
  helpers exposed to bindings, HoneyBadger TPKE batch sealing/opening, mempool reuse, fetch
  fallback, and the per-round driver loop under `honey-node/src/driver/`.

Additional workspace members:

- `honey-acs/honey-native`: PyO3 extension exposed to Python as `honey_native`.
- `honey-bench`: Rust benchmark package. Its top-level CLI runs suites and spawns an explicitly
  selected `honey-node` worker binary.

## Python Packages

- `honey-acs/packages/honey-acs/src/honey_acs/`: Python HoneyBadger/Dumbo ACS package.
- `honey-acs/packages/honey-acs/tests/`: Python ACS and subprotocol tests.
- `honey-acs/honey-native/`: Rust/PyO3 package named `honey-native`, imported as `honey_native`.
- `honey-acs/honey-native/tests/`: native binding tests.

The root `pyproject.toml` uses a `uv` workspace with these Python package members:

- `honey-acs/packages/honey-acs`
- `honey-acs/honey-native`

## Dependency Graph

Arrows point from a crate/package to the crate/package it depends on.

```text
honey-wire -----------> honey-crypto
honey-acs ------------> honey-wire, honey-crypto
honey-transport ------> honey-wire
honey-node -----------> honey-acs, honey-wire, honey-crypto, honey-transport
honey-native ---------> honey-wire, honey-crypto
Python honey_acs -----> honey-native
honey-bench ----------> honey-node
```

Practical reading:

- `honey-wire` is a shared wire/codec crate and stays free of `honey-node` runtime dependencies.
- `honey-acs` depends on `honey-crypto` and `honey-wire` for protocol backends.
- `honey-transport` owns the local TCP implementation used by the driver.
- `honey-node` depends on `honey-acs`, `honey-wire`, `honey-crypto`, and `honey-transport`, and
  remains the driver/runtime boundary implemented as a reusable crate.
- Python `honey_acs` depends on the `honey_native` extension.
- `honey-native` bridges Python to selected Rust helpers from `honey-crypto` and `honey-wire`.

## Current Runtime

- The main benchmark/runtime mode is `rust-driver`.
- `honey-node` runs each logical node as a separate local TCP process.
- ACS backends can be Python-hosted or Rust-native, selected through TOML benchmark config.
- Current-round sealed transaction batches are embedded in the ACS proposal payload. The driver
  does not provide a separate reliable-broadcast path for those batches; availability is supplied
  by the selected ACS backend's RBC/PRBC/ACS machinery.
- The driver only forwards ACS wire events, resolves already-available proposal payloads, fetches
  reusable cross-round proposal artifacts when configured, and exchanges TPKE share bundles bound
  to the selected proposal ids and digests.
- Benchmark execution is driven through `honey-bench --suite-config <path>`.
- Even one-off and smoke runs are represented as suite TOML files rather than a separate single-run CLI schema.
- The CLI is suite-only, but it still dispatches internally to either the HoneyBadger-style or
  Dumbo-style benchmark driver path based on the configured ACS backend.
- Runtime features such as `quic` and `python-backend` belong to `honey-node`, not `honey-bench`.
- Run `honey-bench` with `--node-binary <path>` to point at the exact worker executable to spawn.
- `HONEY_NODE_BINARY` is also supported as an environment override.

## Current Thesis Status

- One-line status: the task-book implementation and performance goals are effectively done; the
  remaining work is thesis finalization rather than protocol-core completion.
- The cross-round reuse mechanism is implemented.
- The current checkout does not contain the historical `paper-final-*` result directories referred
  to by older planning notes. The visible `honey-bench/results/dumbo-paper-suite-*` directories are
  incomplete/failed smoke outputs and should not be used as formal thesis evidence.
- The remaining work is mainly thesis/result reconciliation, a clean formal rerun or restoration of
  archived result artifacts, a minimal cross-machine rerun, and manual thesis cover metadata.

## Quick Commands

```bash
uv sync --dev --locked
cargo build
cargo test
uv run pytest
cargo build -p honey-node --release --features quic
cargo run -p honey-bench -- \
  --node-binary target/release/honey-node.exe \
  --suite-config configs/paper/core/paper_highload.toml \
  --list-experiments
typst compile paper/main.typ
```

See these files for the current authoritative status:

- [AGENTS.md](AGENTS.md): repository-specific engineering guidance
- [configs/README.md](configs/README.md): benchmark-config directory layout and recommended entrypoints
- [TARGET.md](TARGET.md): original task book
