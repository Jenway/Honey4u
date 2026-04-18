# AGENTS.md

## Purpose
- This repository contains a Python 3.14 implementation of HoneyBadger/Dumbo-style BFT protocols plus a native Rust extension exposed as `honey_native` through PyO3.
- The Rust workspace also contains `honey-node`, a standalone binary that drives the full protocol stack over multi-process local TCP, including both Python-hosted and Rust-native ACS backends.
- Use this file as the primary repository-specific guide for coding agents working in `/home/jenway/codeFiles/Honey4u`.
- Keep changes small, protocol-aware, and consistent with the existing code rather than introducing new abstractions by default.

## Current Branch Focus
- The active benchmark and test runner mode is `rust-driver`: `honey-node` spawns N subprocesses, each running the full protocol over local TCP.
- ACS execution under `rust-driver` is no longer Python-only. The driver can run the Python ACS host through PyO3 or one of the Rust-native ACS hosts selected by `config_json`.
- `benchmarks/cli/tps.py` accepts `--node-runtime rust-driver` only; other runtime labels have been removed from the CLI.
- `honey-node bench-driver` now takes benchmark configuration from a TOML file via `--config <path>`. Benchmark helper scripts generate or point to TOML configs instead of assembling long CLI flag lists.
- Current benchmark work is centered on three entrypoints: `benchmarks/cli/tps.py` for general TPS/latency runs, `benchmarks/cli/dumbo_reuse_sweep.py` for reuse on/off sweeps, and `benchmarks/cli/dumbo_backend_reuse_compare.py` for Python-vs-Rust backend comparisons.
- Checked-in benchmark evidence currently covers large Dumbo reuse sweeps and a backend comparison between `python` and `rust_fin`; there is not yet a checked-in result set for `rust_dumbo`, network-perturbation experiments, or Byzantine-node injection experiments.
- A top-level Rust workspace exists at `native/Cargo.toml` with three members: `honey-crypto`, `honey-native`, and `honey-node`.
- `native/honey-native/src/bindings/ledger.rs` and the Python bridge add optional SQLite-backed block persistence and chain-digest tracking.
- The project scope is intentionally limited to ACS-based asynchronous BFT in the HoneyBadger/Dumbo family; do not preserve extensibility for DAG-style, dispersed-ledger, or unrelated consensus families unless the task explicitly requires it.
- HoneyBadger outer orchestration, ACS scheduling, and other runtime-facing control logic are valid Rust-downshift targets; agents should not keep them in Python just to preserve a generic or overly extensible framework shape.
- The three Rust ACS backends are now structured as thin root modules plus submodules:
  `native/honey-node/src/rust_acs/`, `native/honey-node/src/rust_dumbo_acs/`, and `native/honey-node/src/rust_hb_acs/`.
- The rust-driver networking code is also split into focused submodules under `native/honey-node/src/network_driver/`.
- Generated benchmark reports appear under `benchmarks/results/`; treat them as artifacts rather than source.

## Stack And Layout
- The main Python ACS library lives under `packages/honey-acs/src/honey_acs/`.
- ACS family implementations live under `packages/honey-acs/src/honey_acs/hb/` (BKR93 / HoneyBadger) and `packages/honey-acs/src/honey_acs/dumbo/` (Dumbo ACS).
- Sub-protocol implementations (RBC, ABA, common coin, PRBC, MVBA) live under `packages/honey-acs/src/honey_acs/subprotocols/`.
- The `AcsService` abstraction and its HoneyBadger/Dumbo implementations live under `packages/honey-acs/src/honey_acs/service/`.
- The `PersistentAcsHost` bridge (Python ↔ Rust IPC glue) lives in `packages/honey-acs/src/honey_acs/host_bridge.py`.
- Cryptographic parameter construction and key serialization helpers live in `packages/honey-acs/src/honey_acs/host_crypto.py`.
- Pool-reuse encoding/decoding (cross-round broadcast reuse) lives in `packages/honey-acs/src/honey_acs/pool_reuse.py`.
- The rust-driver broadcast mempool runtime lives in `native/honey-node/src/pool_reuse.rs`; Python-side configuration for it flows through `packages/honey-acs/src/honey_acs/params.py`.
- Telemetry and metrics live in `packages/honey-acs/src/honey_acs/telemetry.py`.
- Protocol exceptions live in `packages/honey-acs/src/honey_acs/exceptions.py`.
- The native Rust workspace lives under `native/`; `native/honey-crypto/` is the shared crypto library, `native/honey-native/` builds the `honey-native` PyO3 package, and `native/honey-node/` contains the Rust-hosted node binary plus the Rust-native ACS backends.
- `native/honey-node/src/network_driver.rs` is the rust-driver entry module; its detailed logic is split across `native/honey-node/src/network_driver/`.
- `native/honey-node/src/rust_acs.rs` is the FIN-style ACS host root; protocol logic is split across `native/honey-node/src/rust_acs/`.
- `native/honey-node/src/rust_dumbo_acs.rs` is the Rust-native Dumbo ACS host root; protocol logic is split across `native/honey-node/src/rust_dumbo_acs/`.
- `native/honey-node/src/rust_hb_acs.rs` is the Rust-native HoneyBadger ACS host root; protocol logic is split across `native/honey-node/src/rust_hb_acs/`.
- Python tests live under `tests/` and use `pytest` plus `pytest-asyncio`. Sub-directories: `tests/acs/`, `tests/subprotocols/`, `tests/runtime/`, `tests/native/`, `tests/benchmarks/`, `tests/data/`.
- Benchmark CLIs live under `benchmarks/cli/`; reusable runner helpers live under `benchmarks/support/runners/`.
- Benchmark comparison helpers currently include `benchmarks/cli/dumbo_reuse_sweep.py` and `benchmarks/cli/dumbo_backend_reuse_compare.py`.
- Benchmark output snapshots and ad hoc reports may be written under `benchmarks/results/`.
- Thesis sources live under `paper/`. `paper/main-codex-refer.typ` is the active thesis draft, `paper/main.typ` is a template/example document, `paper/sdu-thesis.typ` is the local SDU Typst template, `paper/refer.bib` is the bibliography database, and `paper/reference/` stores local PDF references.
- The root project uses `uv` workspaces; both `packages/honey-acs` and `native/honey-native` are workspace members (see `pyproject.toml`).

## Benchmark Status
- The general benchmark entrypoint is `benchmarks/cli/tps.py`. It reports throughput, multiple elapsed-time views, transaction and round latency, subprotocol timing summaries, queue backlog, and chain-digest agreement/divergence.
- `benchmarks/cli/dumbo_reuse_sweep.py` has already been used to produce checked-in results under `benchmarks/results/dumbo_reuse_sweep_20260408_large/` and `benchmarks/results/dumbo_reuse_sweep_20260408_n12_knee_full/`.
- The checked-in reuse sweep evidence shows a stable positive reuse effect at larger scales. The large sweep covers `n=4,8,12,16`; the separate `n=12` sweep is the main mid-stage data point used in the thesis draft.
- `benchmarks/cli/dumbo_backend_reuse_compare.py` supports `python`, `rust_fin`, and `rust_dumbo`, but the checked-in result set under `benchmarks/results/dumbo-backend-reuse-20260410T093234Z/` currently includes only `python` and `rust_fin`.
- Existing backend-comparison evidence indicates that the Rust FIN-style ACS backend is materially faster than the Python Dumbo host on the tested local setup. Use the checked-in JSON for exact numbers rather than restating them from memory.
- Do not claim that the benchmark suite already covers realistic WAN jitter, packet perturbation, or Byzantine behavior injection. Those were discussed as future work but are not yet represented by checked-in benchmark runs.
- Treat `benchmarks/results/` as experiment artifacts. Keep them out of commits unless the task explicitly asks to check in new reports or reference outputs.

## Thesis And Graduation Context
- The formal task description is in `TARGET.md`. The thesis topic is narrowly defined: mitigate bandwidth waste in ACS-based asynchronous BFT caused by honest-but-delayed broadcast outputs being discarded by the current round.
- The task book sets four concrete success conditions: implement the cross-round reuse module, preserve safety/liveness, obtain a throughput improvement of at least 10% in high-load settings, and provide a stable, well-documented system plus a complete thesis.
- The mid-term report is in `mid-term.md`. It records the already-established narrative that the project targets ACS-style HoneyBadger/Dumbo protocols rather than DAG-style protocols, and it reports preliminary local-TCP results around `N=12, f=3`.
- The current thesis draft is `paper/main-codex-refer.typ`. It is already aligned with the narrowed repository direction and should be treated as the main writing target; `paper/main.typ` is only a template/demo file and should not be mistaken for the actual thesis content.
- The thesis must stay academically conservative. Do not write that the reuse mechanism applies to arbitrary ACS black boxes. The current argument is strongest when the reused object already carries a strong availability guarantee such as PRBC-style output/proof material.
- Likewise, do not claim that FIN-ACS itself has already been fully adopted as the thesis baseline. What is implemented and benchmarked in the repository is a Rust FIN-style ACS backend inside the current Honey4u runtime, not a paper-faithful end-to-end reimplementation of every external codebase that was discussed during exploration.
- The papers in `paper/reference/` are the primary local references for protocol analysis. Prefer grounding architectural comparisons and thesis statements in those PDFs rather than in remembered summaries of third-party code.
- Future agents should keep a clear distinction in thesis-related writing between:
  1. confirmed implemented results in this repository,
  2. benchmark evidence already collected,
  3. design ideas or future experiments that have not yet been completed.

## Environment
- Required Python version: `>=3.14`.
- CI uses Rust stable.
- Prefer `uv` for Python environment management and command execution.
- Run commands from the repository root so `pytest` picks up `pythonpath = ["src", "packages/honey-acs/src", "."]` from `pyproject.toml`.
- If the native extension needs to know which Python interpreter to bind against, export `PYO3_PYTHON="$(python -c 'import sys; print(sys.executable)')"` before syncing or building.

## Setup And Build Commands
- Install or refresh the full dev environment: `uv sync --dev --locked`
- CI-equivalent bootstrap for native builds:
  `export PYO3_PYTHON="$(python -c 'import sys; print(sys.executable)')" && uv sync --dev --locked`
- Build the full native workspace: `cargo build --manifest-path native/Cargo.toml`
- Build the root Python package wheel/sdist if needed: `uv build`
- Compile the current thesis draft PDF: `typst compile paper/main-codex-refer.typ`
- Compile the template/demo PDF: `typst compile paper/main.typ`
- Run repository hooks in one shot: `uv run pre-commit run --all-files`

## Lint, Format, And Typecheck Commands
- Python lint: `uv run ruff check .`
- Python lint with autofixes: `uv run ruff check . --fix`
- Python format check: `uv run ruff format --check .`
- Python format rewrite: `uv run ruff format .`
- Python typecheck: `uv run ty check`
- Rust workspace format check: `cargo fmt --manifest-path native/Cargo.toml --all --check`
- Rust workspace format rewrite: `cargo fmt --manifest-path native/Cargo.toml --all`
- Rust workspace lint: `cargo clippy --manifest-path native/Cargo.toml --workspace --all-targets -- -D warnings`

## Test Commands
- Run the full Python suite: `uv run pytest`
- Run one Python test file: `uv run pytest tests/acs/test_acs.py`
- Run one Python test by node id: `uv run pytest tests/acs/test_acs.py::test_acs_run_single_round`
- Run Python tests matching a pattern: `uv run pytest -k pool_reuse`
- Run ACS host and local-node integration tests: `uv run pytest tests/runtime/`
- Run the full Rust suite the same way CI does: `cargo nextest run --manifest-path native/Cargo.toml --workspace`
- Run one Rust test by filter with nextest: `cargo nextest run --manifest-path native/Cargo.toml --workspace -E 'test(seal_and_open)'`
- Run one Rust test exactly with `cargo test`: `cargo test --manifest-path native/Cargo.toml --workspace test_seal_and_open_success -- --exact`

## Command Notes
- First-time Python test runs may build the `honey-native` extension because the root package depends on the Rust workspace member.
- The Python package consumes `native/honey-native` through the `uv` workspace; the broader native workspace is defined in `native/Cargo.toml`.
- Building the root native workspace pulls in all three crates (`honey-crypto`, `honey-native`, `honey-node`); keep `native/Cargo.lock` in sync if a workspace dependency changes.
- Running native workspace commands may create or refresh `native/Cargo.lock` and `native/target/`; treat both as generated unless the task explicitly includes workspace lock updates.
- `honey-node bench-driver` is config-file driven. Prefer editing or generating TOML benchmark configs rather than extending the CLI argument surface.
- The internal `run-driver-node` command still uses explicit flags because it is spawned by the benchmark driver, not by end users.
- `ty` is configured with `error-on-warning = true`, so warnings should be treated as failures.
- `ty` currently checks `packages/honey-acs/src/honey_acs` and `tests/native/test_ecdsa_and_crypto_params.py` only (see `pyproject.toml [tool.ty.src]`).
- Ruff excludes `native/honey-native`, so do not expect Python lint commands to touch Rust sources.
- `__init__.py` files are allowed to re-export unused imports because Ruff ignores `F401` there.
- Local benchmark/profiling runs may leave artifacts under `benchmarks/results/` and `.codex`; do not include them in a source commit unless the user explicitly wants report outputs checked in.
- When running formal benchmarks for the thesis, prefer preserving the generated TOML configs, raw JSON outputs, run date, and commit hash together so the experiment remains reproducible on another machine.
- The current checked-in benchmark story is strong enough for reuse-vs-baseline and Python-vs-Rust-FIN comparisons, but not yet for network-disturbance or Byzantine-behavior sections. Do not imply that those experiments already exist.
- The benchmark runtime metric shape expected by `benchmarks/support/runners/_core.py` is `{sample_count, total_seconds, max_seconds}` under `METRICS.snapshot()["timings"]`; keep Rust-side metric output aligned with this shape.

## Python Style
- Follow Ruff formatting; the configured line length is 100.
- Ruff selects `E`, `F`, `W`, `I`, `B`, and `UP`; import ordering is enforced.
- `E501` is ignored, but do not use that as permission to write dense or unreadable long lines.
- Group imports as standard library, third-party, then local package imports, separated by blank lines.
- Use explicit imports; do not add wildcard imports.
- When an import list is long, wrap it with parentheses the same way existing protocol modules do.

## Comments And Docstrings
- Keep module, class, and function docstrings short and concrete.
- Add comments only when protocol flow, binary layout, or concurrency behavior is not obvious from the code itself.
- Avoid line-by-line comments that merely restate the implementation.

## Python Typing
- Prefer modern Python typing syntax: `list[...]`, `dict[...]`, `tuple[...]`, `X | None`, and `type Alias = ...`.
- This codebase already uses PEP 695 generics such as `class Success[T]` and `type Result[T] = ...`; keep new code compatible with Python 3.14 rather than backporting syntax.
- Add type annotations to public functions, dataclass fields, and non-trivial helpers.
- Use `Any` only at genuine dynamic boundaries, especially Python/Rust interop and protocol payload edges.
- Prefer `Protocol` for interface-style abstractions such as transports.
- Prefer dataclasses for structured protocol state and message payloads.
- For immutable message/value objects, existing code often uses `@dataclass(frozen=True, slots=True)`; follow that pattern when appropriate.

## Python Naming
- Use `snake_case` for modules, functions, local variables, and methods.
- Use `PascalCase` for classes and dataclasses.
- Use `UPPER_SNAKE_CASE` for module-level constants.
- Preserve established protocol abbreviations in names: `RbcVal`, `PrbcReady`, `HBConfig`, `TpkeShareBundle`, `DumboBFT`.
- Do not rename established math/protocol fields such as `N`, `f`, `K`, `pid`, `sid`, or `leader` just to make them more generic.
- Private helpers use a leading underscore.

## Python Data And Protocol Conventions
- Protocol message payloads are usually represented as dataclasses rather than raw dictionaries.
- Binary protocol payloads are usually `bytes`; convert `str` to UTF-8 bytes at the edge and keep inner logic byte-oriented.
- Configuration and parameter validation is commonly done in `__post_init__`.
- Queue-based async plumbing is pervasive; most network and protocol boundaries use `asyncio.Queue` with typed payloads.
- Keep protocol-specific state local to the protocol implementation instead of building broad shared utility layers unless reuse is obvious.

## Error Handling
- Raise `ValueError` for invalid configuration, malformed caller arguments, and impossible constructor inputs.
- Raise domain exceptions from `honey_acs.exceptions` for protocol/runtime invariants: `ProtocolInvariantError`, `RoutingError`, `UnknownTagError`, and `SerializationError`.
- When wrapping lower-level failures, preserve the cause with `raise ... from exc`.
- Use result objects (`Success`, `Failure`, and the `Result[...]` alias) for expected round outcomes rather than throwing exceptions for ordinary protocol failure states.
- Keep error messages concrete and actionable; the existing code usually includes the failing value or invariant.

## Logging And Telemetry
- Use `logging.getLogger(...)` or `logging.LoggerAdapter(...)` consistently with the surrounding module.
- Node-aware code often attaches `extra={"node": pid}` through a `LoggerAdapter`; preserve that context when extending those paths.
- Structured event-style logging goes through `honey_acs.telemetry.log_event(...)`.
- Timing and counters go through `METRICS` and `timed_metric(...)`.
- Do not add verbose logging in tight loops unless it is guarded by an existing debug pattern.

## Async And Concurrency Patterns
- Async protocol code uses `asyncio`, `asyncio.Queue`, `asyncio.Task`, and sometimes `asyncio.TaskGroup`.
- The native local transport `send()` and `recv_batch()` calls are nonblocking channel operations; keep them on the event-loop hot path instead of wrapping each call in `asyncio.to_thread(...)`.
- Always handle `asyncio.CancelledError` explicitly when shutting down background tasks; do not accidentally swallow cancellation in broad exception handlers.
- Use `try/finally` to clean up router tasks, mailbox tasks, or background workers.
- In tests, protocol tasks are commonly wrapped in `asyncio.wait_for(...)` to prevent hangs.

## Test Style
- Python tests live under area-specific subdirectories in `tests/`, and files/functions are still named `test_*`.
- Async tests use `@pytest.mark.asyncio`.
- Local helper classes inside tests are normal in this repo, especially to override one method of a protocol class or simulate a failing transport.
- Prefer direct state assertions over snapshot-style golden files.
- Use `pytest.raises(..., match=...)` for error-path tests.
- Keep test data simple and explicit: byte literals, tiny JSON objects, short transaction strings, and small node counts like `N = 4` and `f = 1` are common.

## Rust Style
- The Rust crate uses edition `2024`.
- `cargo fmt` and `cargo clippy -D warnings` are part of the required quality bar.
- Prefer small fallible functions returning `Result<_, CryptoError>` for library logic.
- Domain errors are centralized in `native/honey-native/src/crypto/` with `thiserror::Error`.
- Keep public Rust APIs explicit and typed; avoid stringly-typed control flow in the core crypto code.
- Unit tests live alongside implementation modules under `#[cfg(test)]`.
- `unwrap()` appears in tests; avoid adding new `unwrap()` calls in non-test logic unless the invariant is truly internal and obvious.
- If an invariant is impossible but worth documenting, use `expect(...)` with a specific message rather than a bare `unwrap()`.
- For `honey-node`, prefer keeping the root backend files (`rust_acs.rs`, `rust_dumbo_acs.rs`, `rust_hb_acs.rs`) as thin orchestration shells. Put wire/state/crypto/protocol details in their sibling submodules instead of growing the root files again.
- Likewise, keep `network_driver.rs` as an entry module and place detailed driver logic in `native/honey-node/src/network_driver/`.

## Interop Guidance
- Python serialization/deserialization helpers in `honey_acs.messages` wrap native errors as `SerializationError`; preserve that pattern.
- Native codec boundaries should stay narrow: validate at the edge, convert once, then pass typed objects inward.
- Do not bypass the existing `honey_native` helpers for transaction encoding, protocol envelope encoding, Merkle proofs, threshold crypto, or the Rust tx pool unless there is a concrete reason.
- Local transport bridging currently flows through native `LocalTcpTransport` handles; keep those contracts aligned with the Python wrapper in `honey_acs.host_bridge`.
- TPKE and similar HoneyBadger-internal crypto stages do not need to remain broad Python-facing public APIs; when practical, prefer coarse Rust-owned protocol-specific interfaces over reusable Python crypto surface area.

## Agent Communication
- Answer architectural questions directly. State the conclusion first, then the concrete implications.
- Do not use rhetorical inversion such as "不是……而是……" to sidestep or soften a direct technical judgment.
- Do not preserve generic-framework language when the repository target has already been explicitly narrowed by the user.

## Working Style For Agents
- Read the surrounding protocol carefully before editing; consensus code has many local invariants.
- Prefer the smallest correct change over introducing new layers, helpers, or compatibility code.
- Match the surrounding file's style even when another file in the repo uses a slightly different pattern.
- When editing mixed Python/Rust features, keep Python-side types and Rust-side wire formats synchronized.
- Do not collapse the newly split Rust backend modules back into giant single files. If a protocol submodule becomes too large, split it again by responsibility rather than re-centralizing it.
- When identifying reuse across Rust ACS backends, prefer extracting only low-risk shared shell/helper code first, such as wire envelope helpers, outbound queue helpers, counters, or threshold-coin utilities. Do not force protocol-core generic abstractions unless the benefit is clear and the invariants line up.
- When reviewing or staging changes, separate source edits from generated artifacts such as `native/target/`, `.codex`, and ad hoc benchmark result directories.
- After changes, run the narrowest relevant checks first, then the broader suite if the change has cross-cutting impact.
