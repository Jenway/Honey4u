# AGENTS.md

## Purpose
- This repository contains a Python 3.14 implementation of HoneyBadger/Dumbo-style BFT protocols plus a native Rust extension exposed as `honey_native` through PyO3.
- The Rust workspace also contains `honey-node`, a standalone binary that drives the full protocol stack over multi-process local TCP, including both Python-hosted and Rust-native ACS backends.
- Use this file as the primary repository-specific guide for coding agents working in `D:\codeFiles\Honey4u`.
- Keep changes small, protocol-aware, and consistent with the existing code rather than introducing new abstractions by default.

## Current Branch Focus
- The active benchmark and test runner mode is `rust-driver`: `honey-node` spawns N subprocesses, each running the full protocol over local TCP.
- ACS execution under `rust-driver` is no longer Python-only. The driver can run the Python ACS host through PyO3 or one of the Rust-native ACS hosts selected by `config_json`.
- `honey-bench` is now suite-only: benchmark execution goes through `honey-bench suite --suite-config <path>`, and helper scripts should generate or point to suite TOML files instead of assembling long CLI flag lists.
- `suite` remains the only benchmark CLI entrypoint, but it still supports both HoneyBadger-style and Dumbo-style benchmark execution internally based on the configured ACS backend.
- Current benchmark work is centered on the Rust `honey-bench suite` CLI plus the curated TOML configs under `configs/paper/core/` and `configs/paper/appendix/`. The `paper/core/` label should track the current thesis Chapter 4 main experiment narrative, not a generic notion of importance.
- The current checkout does not contain the older `paper-final-*` formal result directories referenced by some historical notes. The visible `honey-bench/results/dumbo-paper-suite-*` directories are incomplete/failed smoke outputs and must not be treated as formal evidence. Restore the archived artifacts or rerun the TOML suites before quoting exact thesis numbers.
- The current worktree includes controlled runtime fault injection at the `rust-driver` boundary: network faults (`fixed_delay_ms`, `jitter_ms`, `slow_honest`) and initial Byzantine node behaviors (`silent`, `invalid_fetch_response`). Treat those capabilities as implemented tooling, but do not generalize them to full WAN or broad Byzantine robustness claims without fresh evidence.
- A top-level Rust workspace exists at `Cargo.toml` (project root) with members: `honey-crypto`, `honey-wire`, `honey-acs`, `honey-acs/honey-native`, `honey-node`, and `honey-bench`. The `honey-transport/` crate is a path dependency used by `honey-node` but is not currently listed as a workspace member.
- `honey-node/src/ledger.rs` and the Python bridge add optional SQLite-backed block persistence and chain-digest tracking; `honey-native` exposes the Python-facing native bindings.
- The project scope is intentionally limited to ACS-based asynchronous BFT in the HoneyBadger/Dumbo family; do not preserve extensibility for DAG-style, dispersed-ledger, or unrelated consensus families unless the task explicitly requires it.
- HoneyBadger outer orchestration, ACS scheduling, and other runtime-facing control logic are valid Rust-downshift targets; agents should not keep them in Python just to preserve a generic or overly extensible framework shape.
- The three Rust ACS backends live in the `honey-acs` crate under `honey-acs/src/backends/rust_fin/`, `honey-acs/src/backends/rust_dumbo/`, and `honey-acs/src/backends/rust_hb/`; each is a `mod.rs` root plus focused submodules.
- The rust-driver node implementation lives under `honey-node/src/driver/`; it is the binary-only module tree orchestrating round execution, HoneyBadger TPKE, ACS proposal payload resolution, cross-round reuse, and the fetch fallback protocol.
- Current-round sealed transaction batches must enter the protocol as ACS proposal payload bytes. Do not add a separate driver-level reliable-broadcast path for current-round batches; correctness-critical availability belongs to the ACS backend's RBC/PRBC/ACS machinery.
- Generated benchmark reports appear under `honey-bench/results/`; treat them as artifacts rather than source.

## Stack And Layout
- The main Python ACS library lives under `honey-acs/packages/honey-acs/src/honey_acs/`.
- ACS family implementations live under `honey-acs/packages/honey-acs/src/honey_acs/hb/` (BKR93 / HoneyBadger) and `honey-acs/packages/honey-acs/src/honey_acs/dumbo/` (Dumbo ACS).
- Sub-protocol implementations (RBC, ABA, common coin, PRBC, MVBA) live under `honey-acs/packages/honey-acs/src/honey_acs/subprotocols/`.
- The `AcsService` abstraction and its HoneyBadger/Dumbo implementations live under `honey-acs/packages/honey-acs/src/honey_acs/service/`.
- The `PersistentAcsHost` bridge (Python ↔ Rust IPC glue) lives in `honey-acs/packages/honey-acs/src/honey_acs/host.py`.
- Python cryptographic parameter construction and key serialization helpers live in `honey-acs/packages/honey-acs/src/honey_acs/crypto/bootstrap.py`; Rust-side host crypto helpers live in `honey-acs/src/host_crypto.rs`.
- Pool-reuse encoding/decoding (cross-round broadcast reuse) lives in `honey-acs/packages/honey-acs/src/honey_acs/pool_reuse.py`.
- The rust-driver broadcast mempool runtime lives in `honey-node/src/driver/mempool/pool.rs` and `honey-node/src/driver/mempool/fetch.rs`; Python-side configuration for it flows through `honey-acs/packages/honey-acs/src/honey_acs/params.py`.
- Telemetry and metrics live in `honey-acs/packages/honey-acs/src/honey_acs/telemetry.py`.
- Protocol exceptions live in `honey-acs/packages/honey-acs/src/honey_acs/exceptions.py`.
- The Rust workspace is defined at the project root `Cargo.toml`; the core workspace members are `honey-crypto/` (shared crypto), `honey-wire/` (wire-format and codec layer), `honey-acs/` (ACS protocol backends), `honey-node/` (standalone driver/runtime binary), `honey-acs/honey-native/` (PyO3 extension), and `honey-bench/` (Rust benchmark orchestrator). `honey-transport/` is a path dependency that owns transport handles and local TCP.
- Crate boundaries: `honey-wire` may depend on `honey-crypto` but must not depend on `honey-node` or driver runtime code; `honey-acs` depends on `honey-crypto` and `honey-wire`; `honey-transport` depends on `honey-wire`; `honey-node` depends on `honey-acs`, `honey-wire`, `honey-crypto`, and `honey-transport` and owns runtime orchestration.
- `honey-node`'s library surface (`honey-node/src/lib.rs`) currently exposes only `keygen` (cryptographic key-pair generation) and `ledger` (SQLite persistence).
- `honey-node`'s binary entry (`honey-node/src/main.rs` → `cli.rs`) delegates to `driver/mod.rs`, which owns the full rust-driver node loop under `honey-node/src/driver/`.
- Key submodules of `honey-node/src/driver/`: `encryption/` (HoneyBadger batch encryption/decryption shell), `mempool/` (ACS proposal payload bundle/reference encoding, reusable proposal mempool, and fetch fallback), `frame.rs` (driver TCP frames and pool-fetch wire), `round/` (round inbox, state, metrics, and per-round loop), `config.rs`/`args.rs` (runtime config and CLI parsing), and `output.rs` (result JSON rendering).
- Python tests use `pytest` plus `pytest-asyncio`. Protocol tests live alongside the code they test: `honey-acs/packages/honey-acs/tests/acs/`, `honey-acs/packages/honey-acs/tests/subprotocols/`, and `honey-acs/honey-native/tests/native/`.
- Benchmark code lives under `honey-bench/`, and benchmark configs live under `configs/` with the following intent split: `smoke/`, `paper/core/`, `paper/appendix/`, `paper/exploratory/`, `legacy/`, and `debug/`.
- Benchmark output snapshots and ad hoc reports may be written under `honey-bench/results/`.
- Thesis sources live under `paper/`. In this checkout, `paper/main.typ` is the active thesis manuscript source. `paper/main_refer.typ` is an older alternate draft, `paper/main_refer2.typ` is an untracked design-note draft, `paper/sdu-thesis.typ` is the local SDU Typst template, `paper/refer.bib` is the bibliography database, and `paper/reference/` stores local PDF references.
- The root project uses `uv` workspaces; both `honey-acs/packages/honey-acs` and `honey-acs/honey-native` are workspace members (see `pyproject.toml`).
- The old root-level `packages/` and `native/` prefixes have been removed; do not add new code under those paths.

## Benchmark Status
- The general benchmark entrypoint is `honey-bench suite`. It expands suite TOML experiments, executes the selected cases, and writes aggregated summaries, deltas, raw per-run JSON, and a manifest.
- When runtime faults are configured, suite outputs also record transport perturbation counters and node-level byzantine action counters through the aggregated raw and summary artifacts.
- Older planning notes mention reuse-sweep and backend-comparison result directories, but those directories are not present in the current checkout. Do not quote their exact numbers from memory; restore the artifacts or rerun the relevant benchmark configs first.
- Backend comparison runs can be driven through the current TOML-suite path (`honey-bench suite`) or through the legacy Python benchmark helper when appropriate, but the current checkout has no archived formal `rust_dumbo` comparison.
- `configs/paper/core/` holds the configs that best align with the current thesis Chapter 4 mainline result narrative; `configs/paper/appendix/` holds appendix/supplementary configs; `configs/paper/exploratory/` holds pilot and tuning configs that informed those final suites.
- Current visible suite outputs under `honey-bench/results/dumbo-paper-suite-*` have `executed_runs == 0` where manifests exist, and empty summary/delta data. Treat them as failed smoke artifacts, not thesis evidence.
- Do not claim that the repository already has realistic WAN evidence or general Byzantine robustness. The implemented jitter/fixed-delay/slow-honest and byzantine-boundary capabilities are local runtime perturbation tools until backed by fresh successful result directories.
- Treat `honey-bench/results/` as experiment artifacts. Keep them out of commits unless the task explicitly asks to check in new reports or reference outputs.

## Thesis And Graduation Context
- One-line status: the task-book protocol/benchmark goals are effectively complete; the remaining
  delivery risk is thesis finalization and conservative result integration.
- The formal task description is in `TARGET.md`. The thesis topic is narrowly defined: mitigate bandwidth waste in ACS-based asynchronous BFT caused by honest-but-delayed broadcast outputs being discarded by the current round.
- The task book sets four concrete success conditions: implement the cross-round reuse module, preserve safety/liveness, obtain a throughput improvement of at least 10% in high-load settings, and provide a stable, well-documented system plus a complete thesis.
- In the current repository state, the implementation side of the task book is effectively satisfied: the reuse module, runtime fault injection, benchmark configs, and driver metrics are implemented. The performance-evidence side must be reconciled for this checkout because the historical formal `paper-final-*` result directories are absent.
- The active full manuscript source in this checkout is `paper/main.typ`. Keep exact result claims conservative until the supporting artifacts in `honey-bench/results/` are restored or rerun and rechecked against the manuscript.
- Preferred next-work order for agents:
  1. restore or rerun the formal benchmark result directories needed by `paper/main.typ`, then regenerate the final tables/figures and tighten wording
  2. finish thesis cleanup, threat-to-validity wording, abstract/conclusion consistency, and conservative claim review
  3. run one minimal cross-machine rerun
  4. if time remains after the required delivery items are done, tighten Rust fetch-stat appendix wording
- Practical delivery order for the current workspace:
  1. finalize `paper/main.typ`
  2. run one minimal cross-machine rerun
  3. fill manual cover metadata fields
  4. export the final PDF only after one last conservative wording pass
- Two remaining closure items cannot be finished by protocol/source edits alone:
  1. the minimal cross-machine rerun requires a second machine or distinct external environment
  2. the thesis cover metadata requires manual entry of real personal information
- In practice, the remaining delivery blockers now reduce to three categories:
  1. thesis manuscript finalization
  2. one minimal cross-machine trend rerun
  3. local/manual cover metadata completion and final PDF export
- Any extra backend comparison, extra byzantine behavior, or generalized network-simulation work
  beyond that point is optional follow-on work, not a blocker for closing the current task book.
- Treat the thesis/task-book delivery as fully closed only when all four practical delivery items above are done.
- Equivalent completion criteria for future agents:
  1. `paper/main.typ` has final-form body text, tables, captions, appendix placement, and threat-to-validity wording, with all exact result numbers traceable to present artifacts
  2. at least one minimal cross-machine trend rerun has been completed and archived with run metadata
  3. the manual thesis cover metadata fields have been filled locally and the final PDF exports cleanly
  4. the final wording keeps `fixed-delay` as appendix-grade pressure testing, keeps `fetch` as a boundary observation, and does not generalize the results to arbitrary ACS black boxes, realistic WAN validation, or broad Byzantine robustness
- Deprioritize the following until thesis-result integration is done: standalone WAN simulators, new protocol families/backends, generalized byzantine attack frameworks, and cosmetic large-scale refactors.
- The mid-term report is in `mid-term.md`. It records the already-established narrative that the project targets ACS-style HoneyBadger/Dumbo protocols rather than DAG-style protocols, and it reports preliminary local-TCP results around `N=12, f=3`.
- The current thesis manuscript source is `paper/main.typ`. Treat `paper/main_refer.typ` as an older alternate draft unless the user explicitly asks to edit it.
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
- Run commands from the repository root so `pytest` picks up `pythonpath = ["src", "honey-acs/packages/honey-acs/src", "."]` from `pyproject.toml`.
- If the native extension needs to know which Python interpreter to bind against, export `PYO3_PYTHON="$(python -c 'import sys; print(sys.executable)')"` before syncing or building.

## Setup And Build Commands
- Install or refresh the full dev environment: `uv sync --dev --locked`
- CI-equivalent bootstrap for native builds:
  `export PYO3_PYTHON="$(python -c 'import sys; print(sys.executable)')" && uv sync --dev --locked`
- Build the full Rust workspace: `cargo build`
- Run the full Rust test suite with Cargo: `cargo test`
- Build the root Python package wheel/sdist if needed: `uv build`
- Compile the current thesis manuscript PDF: `typst compile paper/main.typ`
- Compile the alternate draft PDF if needed: `typst compile paper/main_refer.typ`
- Run repository hooks in one shot: `uv run pre-commit run --all-files`

## Lint, Format, And Typecheck Commands
- Python lint: `uv run ruff check .`
- Python lint with autofixes: `uv run ruff check . --fix`
- Python format check: `uv run ruff format --check .`
- Python format rewrite: `uv run ruff format .`
- Python typecheck: `uv run ty check`
- Rust workspace format check: `cargo fmt --all --check`
- Rust workspace format rewrite: `cargo fmt --all`
- Rust workspace lint: `cargo clippy --workspace --all-targets -- -D warnings`

## Test Commands
- Run the full Python suite: `uv run pytest`
- Run one Python ACS test file: `uv run pytest honey-acs/packages/honey-acs/tests/acs/test_acs.py`
- Run one Python ACS test by node id: `uv run pytest honey-acs/packages/honey-acs/tests/acs/test_acs.py::test_acs_run_single_round`
- Run Python tests matching a pattern: `uv run pytest -k pool_reuse`
- Run the persistent ACS host test: `uv run pytest honey-acs/packages/honey-acs/tests/acs/test_persistent_host.py`
- Run native binding tests: `uv run pytest honey-acs/honey-native/tests/native/`
- Run the full Rust suite the same way CI does: `cargo nextest run --workspace`
- Run one Rust test by filter with nextest: `cargo nextest run --workspace -E 'test(seal_and_open)'`
- Run one Rust test exactly with `cargo test`: `cargo test --workspace test_seal_and_open_success -- --exact`

## Command Notes
- First-time Python test runs may build the `honey-native` extension because the root package depends on the Rust workspace member.
- The Python package consumes `honey-acs/honey-native` through the `uv` workspace; the Rust workspace is defined at the project root `Cargo.toml`.
- Building the Rust workspace pulls in all crates (`honey-crypto`, `honey-wire`, `honey-acs`, `honey-native`, `honey-node`, `honey-bench`); keep the root `Cargo.lock` in sync if a workspace dependency changes.
- Running Rust workspace commands may create or refresh `Cargo.lock` and `target/`; treat both as generated unless the task explicitly includes workspace lock updates.
- `honey-bench` is suite-config driven. Prefer editing or generating suite TOML benchmark configs rather than extending the CLI argument surface.
- `honey-node` is the internal per-node process entrypoint spawned by the benchmark driver. It uses explicit flags directly and no longer has a `run-driver-node` subcommand.
- `ty` is configured with `error-on-warning = true`, so warnings should be treated as failures.
- `ty` currently checks `honey-acs/packages/honey-acs/src/honey_acs` and `honey-acs/honey-native/tests/native/test_ecdsa_and_crypto_params.py` only (see `pyproject.toml [tool.ty.src]`).
- Ruff excludes `honey-acs/honey-native`, so do not expect Python lint commands to touch Rust sources.
- `__init__.py` files are allowed to re-export unused imports because Ruff ignores `F401` there.
- Local benchmark/profiling runs may leave artifacts under `honey-bench/results/` and `.codex`; do not include them in a source commit unless the user explicitly wants report outputs checked in.
- When running formal benchmarks for the thesis, prefer preserving the generated TOML configs, raw JSON outputs, run date, and commit hash together so the experiment remains reproducible on another machine.
- The current code and configs support the reuse-vs-baseline, backend-comparison, and intentionally narrow local network-disturbance / boundary Byzantine experiments, but this checkout does not include successful formal result artifacts for those claims. Do not imply realistic WAN validation or broad Byzantine robustness.
- `configs/smoke/dumbo_smoke.toml` is the preferred smoke-suite entrypoint. For thesis reruns, prefer the curated `configs/paper/core/` and `configs/paper/appendix/` configs over the exploratory configs unless you are intentionally revisiting old tuning work.
- The benchmark runtime metric shape expected by the Rust benchmark aggregation path is `{sample_count, total_seconds, max_seconds}` under `METRICS.snapshot()["timings"]`; keep Rust-side metric output aligned with this shape.

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
- Python protocol tests live under `honey-acs/packages/honey-acs/tests/`; native binding tests live under `honey-acs/honey-native/tests/`. Files/functions are still named `test_*`.
- Async tests use `@pytest.mark.asyncio`.
- Local helper classes inside tests are normal in this repo, especially to override one method of a protocol class or simulate a failing transport.
- Prefer direct state assertions over snapshot-style golden files.
- Use `pytest.raises(..., match=...)` for error-path tests.
- Keep test data simple and explicit: byte literals, tiny JSON objects, short transaction strings, and small node counts like `N = 4` and `f = 1` are common.

## Rust Style
- The Rust crate uses edition `2024`.
- `cargo fmt` and `cargo clippy -D warnings` are part of the required quality bar.
- Prefer small fallible functions returning `Result<_, CryptoError>` for library logic.
- Rust crypto domain errors are centralized in `honey-crypto/src/crypto_error.rs` with `thiserror::Error`.
- Keep public Rust APIs explicit and typed; avoid stringly-typed control flow in the core crypto code.
- Unit tests live alongside implementation modules under `#[cfg(test)]`.
- `unwrap()` appears in tests; avoid adding new `unwrap()` calls in non-test logic unless the invariant is truly internal and obvious.
- If an invariant is impossible but worth documenting, use `expect(...)` with a specific message rather than a bare `unwrap()`.
- For `honey-acs`, keep each backend root (`honey-acs/src/backends/rust_fin/mod.rs`, `rust_dumbo/mod.rs`, `rust_hb/mod.rs`) as a thin orchestration shell; put wire/state/crypto/protocol details in their sibling submodules.
- For `honey-node`, keep `honey-node/src/driver/mod.rs` as the rust-driver node entry and place per-stage logic in its submodules (`encryption/`, `mempool/`, `round/`, `config.rs`, `frame.rs`); do not re-centralize that logic back into lib.rs.

## Interop Guidance
- Python serialization/deserialization helpers in `honey_acs.messages` wrap native errors as `SerializationError`; preserve that pattern.
- Native codec boundaries should stay narrow: validate at the edge, convert once, then pass typed objects inward.
- Do not bypass the existing `honey_native` helpers for transaction encoding, protocol envelope encoding, Merkle proofs, threshold crypto, or the Rust tx pool unless there is a concrete reason.
- Local transport bridging currently flows through native `LocalTcpTransport` handles; keep those contracts aligned with the Python wrapper in `honey_acs.host`.
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
- When reviewing or staging changes, separate source edits from generated artifacts such as `target/`, `.codex`, and ad hoc benchmark result directories.
- After changes, run the narrowest relevant checks first, then the broader suite if the change has cross-cutting impact.
