# Reuse Broad-Range Scan Notes (2026-04-29)

## Scope

This note records two coarse N=16 range scans intended to find a usable sweep region,
not a single headline point.

Configs:

- `benchmarks/configs/paper/reuse_broad_range_n16.toml`

Result directories:

- `benchmarks/results/reuse-band-core-n16-20260429/`
- `benchmarks/results/reuse-band-long-n16-20260429/`

## What the scan was trying to answer

The goal was to find a broad parameter band where:

- reuse is actually activated,
- the runtime remains stable,
- and a later thesis sweep can vary parameters without immediately falling into
  "no reuse" or "driver timeout" regions.

The main axes were:

- `batch_size`
- number of delayed honest nodes
- extra delay per delayed node

The reuse-side parameters were fixed at the currently most conservative setting:

- `pool_grace_ms = 0`
- `pool_reuse_limit_per_round = 1`
- `pool_expire_rounds = 3`
- `pool_mempool_max = 4096`

## Main findings

### 1. Low-pressure regions are bad sweep candidates

The first broad scan showed that the following regions are poor foundations for a thesis sweep:

- `none`
- only `2` delayed honest nodes
- some `3`-delayed-node cases

Reason:

- reuse was often inactive, or
- the reuse-on run became unstable and timed out around round 5.

This means these regions are not merely "low benefit". They are bad experimental terrain.

### 2. A clear instability boundary appeared at 3 slow nodes / 25 ms

In the focused band scan, all `reuse_on` cases for:

- `slow25p13_15`

failed across all tested batch sizes:

- `768`
- `1024`
- `1536`
- `2048`

So this line is useful as an upper boundary marker, but not as the center of a sweep.

### 3. The most usable activation band is 4 slow nodes with 20-30 ms delay

The strongest stable activation region in the current runtime was:

- `slow20p12_15`
- `slow30p12_15`

Across that band:

- runs were stable in the 8-round and 16-round scans except one failed `b=768, slow20p12_15` long-window case,
- `reused_reference_total_mean` was about `7` over 8 rounds,
- `reused_reference_total_mean` was about `15` over 16 rounds.

Interpretation:

- this regime reliably activates reuse,
- and does so at a nearly one-extra-reference-per-round rate.

### 4. Five delayed nodes is mostly a boundary, not a sweet spot

The `5`-slow-node cases:

- `slow20p11_15`
- `slow25p11_15`

were usually stable, but reuse was weak:

- `reused_reference_total_mean` was `0` or `4` over 16 rounds.

This makes them useful as a "too much pressure / too little useful reuse" comparison band,
not as the main sweep center.

### 5. The current runtime does not show a broad throughput-win region

Under the current executable state used for these scans, the long-window sweep did **not**
reproduce the older `reuse-best-candidate-n16-20260429` style positive wall-throughput result
across a broad range.

Observed shape in the 16-round scan:

- `b=768, slow30p12_15`: slight positive `TPS_wall` delta
- most other stable points: flat to negative `TPS_wall` delta
- `bytes/tx` usually improved when reuse activated

Interpretation:

- the broad band is still useful for studying activation and cost tradeoffs,
- but it is not currently a reliable "headline positive throughput" band in the present runtime state.

## Recommended sweep region

If the next goal is a structured sweep, use the following as the **core sweep band**:

- `nodes = 16`
- `backend = rust_fin`
- `batch_size in {1024, 1536, 2048}`
- delayed honest nodes = `4`
- extra delay in `{20, 30}` ms
- `pool_grace_ms = 0`
- `pool_reuse_limit_per_round = 1`
- `rounds >= 16`

Why this band:

- reuse is active,
- most points are stable,
- and the sweep can measure how block-size growth and TPKE cost change as batch size increases.

## Do-not-scan list

The following regions should be treated as **known bad** unless there is a very specific reason to revisit them:

- `none`
- only `2` delayed honest nodes
- `slow25p13_15`
- `batch_size = 768` together with `slow20p12_15` in long-window runs
- `pool_reuse_limit_per_round >= 2` for the current zero-grace N=16 regime
- long `pool_grace_ms` values used just to "buy more reuse"

Expected failure modes:

- reuse never activates,
- reuse activates but wall-throughput drops,
- or the run stalls around round 5 and burns the full timeout budget.

## Recommended boundary lines

To make the sweep scientifically useful, keep two boundary families:

- instability boundary:
  `slow25p13_15`
- over-pressure / low-reuse boundary:
  `slow20p11_15` and optionally `slow25p11_15`

These should not dominate the matrix, but they are valuable for explaining where the mechanism stops helping.

## Practical advice for the next sweep

- Do not center the next sweep on `none`, `2` slow nodes, or the full 3-slow-node family.
- Do not use `slow25p13_15` in the main matrix. It is a boundary-only case now.
- Do not use `batch_size = 768` in the main 16-round matrix.
- Use `rounds = 16` or more. Short 8-round scans are good for activation screening, but they mix in too much warm-up noise.
- Treat the 4-slow-node / 20-30 ms band as the main study area.
- Treat the 5-slow-node band as a comparison boundary.
- Before quoting any thesis headline number, rerun the chosen sweep band under the exact final executable state, because the current broad scans do not align with the older positive single-point artifact.

## Fail-fast policy

To avoid wasting time on bad regions in future scans:

- exploratory scans should use `global_timeout = 90-120s`,
- the first pass should use `repeats = 1`,
- only after a point is stable should it be promoted to `rounds = 16+`,
- and a point that times out once in a coarse scan should be removed from the next wider sweep unless it is being kept explicitly as a boundary case.
