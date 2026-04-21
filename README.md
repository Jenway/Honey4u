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

- The cross-round reuse mechanism is implemented.
- Existing high-load local-TCP evidence already exceeds the task-book throughput target of `10%`.
- The remaining work is mainly clean-tree experiment freezing and thesis finalization, not missing
  protocol-core functionality.

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
