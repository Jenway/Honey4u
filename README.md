# Honey4u

ACS-based asynchronous BFT in the HoneyBadger/Dumbo family.

## Current Scope

This repository focuses on ACS-family asynchronous BFT protocols in the HoneyBadger / Dumbo line.
The current engineering target is no longer a generic consensus playground. It is a thesis-oriented
prototype for studying and implementing cross-round broadcast reuse under the Honey4u runtime.

## Current Runtime

- The main benchmark/runtime mode is `rust-driver`.
- `honey-node` runs each logical node as a separate local TCP process.
- ACS backends can be Python-hosted or Rust-native, selected through TOML benchmark config.
- The benchmark driver is config-file driven; prefer TOML configs over long CLI flag lists.

## Current Thesis Status

- One-line status: the task-book implementation and performance goals are effectively done; the
  remaining work is thesis finalization rather than protocol-core completion.
- The cross-round reuse mechanism is implemented.
- Existing high-load local-TCP evidence already exceeds the task-book throughput target of `10%`.
- Archived local formal reruns now exist for:
  - `benchmarks/results/paper-final-highload-20260421T182250Z/`
  - `benchmarks/results/paper-final-grace-python-20260421T191900Z/`
  - `benchmarks/results/paper-final-boundary-20260421T180132Z/`
  - `benchmarks/results/paper-final-network-jitter-20260422T000021Z/`
  - `benchmarks/results/paper-final-network-fixed-delay-20260422T020028Z/`
- The active thesis source at `paper/main-codex-refer.typ` has been synchronized to these result sets and
  currently compiles successfully with `typst compile`.
- The thesis manuscript has also been cleaned up toward final form: internal writing-plan/sample text
  has been removed, while personal cover metadata still needs to be filled locally.
- The remaining work is now mainly thesis integration, appendix/figure polish, and a minimal
  cross-machine rerun, not missing protocol-core functionality or missing minimum
  benchmark-freeze coverage.
- There are currently no remaining repository-internal protocol blockers.
- In practical terms, only three delivery categories remain:
  - finalizing the thesis manuscript text/figures/appendix wording
  - running one minimal cross-machine trend rerun
  - filling the thesis cover metadata locally
- The two remaining closure items that cannot be fully finished by protocol coding alone are:
  - one minimal rerun on a second machine
  - filling the personal thesis cover metadata locally

## Current Priorities

Current gate:

- Do not expand protocol scope unless thesis-result integration is already finished.
- Prefer final tables/figures, cross-machine reproducibility, and wording cleanup over new
  backends or new attack scenarios.

Priority `P0`:

- Turn the archived high-load, grace, boundary, jitter, and fixed-delay result sets into thesis
  tables, figures, appendix material, and final experimental claims.
- Tighten wording so the thesis distinguishes confirmed local evidence, appendix-grade pressure
  tests, and optional future work.
- Finish thesis cleanup and final proofreading on top of the already compiling manuscript.

Priority `P1`:

- Do a minimal rerun on a second machine.
  This is part of the final closure criteria, not an optional enhancement.
- Export final thesis figures/tables from the archived result sets and keep captions conservative.
- Tighten the remaining fetch-path and appendix wording so the explanation matches the frozen data.

Priority `P2`:

- Extend the minimal byzantine harness with one more reuse-related behavior such as
  `invalid_reference_proposal`, but only if `P0` and `P1` are already done.

Anything in `P2` should be treated as optional post-thesis enhancement work, not as a blocker for
closing the current task book.

Immediate next steps if continuing today:

- finish the final thesis tables/captions in `paper/main-codex-refer.typ`
- run one minimal cross-machine rerun for `highload_n12` and `slow_honest_n12`
- fill the thesis cover metadata fields locally
- do one last wording/appendix pass before exporting the final PDF

This project can be treated as fully closed for the thesis when all four items above are done.

Not recommended before thesis-result lock-in:

- building a full WAN proxy / standalone network simulator
- adding more protocol families or new ACS/MVBA backends
- turning the current minimal byzantine injection into a general attack framework

See these files for the current authoritative status:

- [AGENTS.md](AGENTS.md): repository-specific engineering guidance
- [TODO.md](TODO.md): final-stage task tracking and current priorities
- [paper/experiment-checklist.md](paper/experiment-checklist.md): formal experiment freeze plan
- [TARGET.md](TARGET.md): original task book

## Quick Commands

```bash
uv sync --dev --locked
cargo build --manifest-path native/Cargo.toml
uv run pytest tests/runtime/
uv run python benchmarks/cli/dumbo_paper_suite.py \
  --suite-config benchmarks/configs/paper/dumbo_comprehensive.toml \
  --list-experiments
typst compile paper/main-codex-refer.typ
```
