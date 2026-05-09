# Config Layout

This directory is split by intent so long-lived thesis configs do not mix with one-off probes.

## Layout

- `smoke/`: minimal smoke configs for quick validation before longer runs.
- `paper/core/`: configs that best match the current Chapter 4 mainline experiment narrative in the thesis source.
- `paper/appendix/`: configs that primarily support appendix tables, boundary cases, or supplementary result discussion.
- `paper/exploratory/`: surviving exploratory configs with distinct tuning, backend-comparison, or N=16 probe value. Redundant pilot, merged omnibus, or single-backend subsets should not be kept here once a curated core/appendix replacement exists.
- `legacy/`: older benchmark/driver examples kept only as historical reference during the Rust-driver transition.
- `debug/`: single-run probes and transport/root-cause investigation configs.

## Recommended Entry Points

- Smoke: `configs/smoke/dumbo_smoke.toml`
- Chapter 4 mainline scalability: `configs/paper/core/paper_scalability.toml`
- Chapter 4 mainline network faults: `configs/paper/core/paper_network_faults.toml`
- Chapter 4 mainline byzantine boundary: `configs/paper/core/paper_byzantine_boundary.toml`
- Chapter 4 mainline grace-boundary case: `configs/paper/core/paper_grace_faulty.toml`
- Chapter 4 mainline high-load study: `configs/paper/core/paper_highload.toml`
- Appendix grace reference tables: `configs/paper/appendix/paper_grace_sensitivity.toml`
- Appendix N=16 reuse exploration: `configs/paper/appendix/paper_reuse_n16.toml`

## Notes

- Some configs under `debug/` and `legacy/` depend on optional build features such as `python-backend` or `quic`.
- `honey-bench suite --suite-config <path>` is the only supported benchmark entrypoint in the current tree, including smoke and one-off runs.
- That single `suite` entrypoint can still execute either HoneyBadger-family or Dumbo-family benchmark paths depending on the selected backend in the suite TOML.
- The current thesis source in `paper/main.typ` emphasizes reuse-system behavior under high load, scalability, network perturbation, slow-node count effects, byzantine boundary behavior, and a faulty-boundary grace study. Backend-to-backend comparison is therefore treated as exploratory support work rather than a Chapter 4 mainline result.
- `configs/paper/core/paper_highload.toml` merges the Chapter 4 high-load study into one suite file while still keeping separate experiment blocks for the base sweep, deeper large-batch sweep, and the post-fix densify passes.
