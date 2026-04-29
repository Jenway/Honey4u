# Reuse Tuning Notes (2026-04-29)

## Scope

This note records the exploratory N=16 reuse-parameter search run on 2026-04-29.
It is intended as engineering guidance for future benchmark tuning, not as final thesis evidence.

Primary exploratory config:

- `benchmarks/configs/paper/reuse_focus_n16.toml`

Primary result directories:

- `benchmarks/results/reuse-largebatch-n16-20260429/`
- `benchmarks/results/reuse-focus-n16-20260429/`
- `benchmarks/results/reuse-focus-confirm-n16-20260429/`
- `benchmarks/results/reuse-zero-grace-n16-20260429/`
- `benchmarks/results/reuse-best-candidate-n16-20260429/`

## Mechanism Lessons

- Reuse benefit is not triggered by transport delay alone. A proposal must first become `ProposalAvailable` and enter the local proposal store before it can be cached for later rounds.
- `pool_grace_ms` only helps the subset of late proposals that finish PRBC after ACS decision but before the round is torn down.
- `pool_grace_ms = 0` can still produce reuse benefit when extra proposals already became `ProposalAvailable` before decision but were not selected into the ACS output.
- The practical tradeoff is not "more reuse is always better". Reusing too many extra proposals increases delivered transactions and block size, which can push more cost into TPKE/open/combine and reduce wall-throughput.
- For this local TCP setup, the best wall-throughput point was obtained by reusing about one extra proposal per round, not by maximizing reused proposals.

## Negative Findings

### 1. Large-batch, 5 slow nodes was the wrong regime

Config family:

- `slow25p11_15`
- `batch_size = 1024/2048/4096`
- `pool_grace_ms = 20/35/50`
- `pool_reuse_limit_per_round = 5`

Observed behavior:

- ACS almost always selected the same fast quorum of 11 nodes.
- Slow nodes rarely became `ProposalAvailable` in time.
- `reused_reference_total_mean` was effectively `0` for `b=2048` and `b=4096`.
- `reuse_on` was slower than `reuse_off`.

Conclusion:

- Delaying all `f = 5` tail nodes made the fast `n-f` quorum win too early.
- This regime mostly measured reuse-path overhead, not useful reuse.

### 2. Longer grace did not help enough

Config family:

- `slow25p13_15`
- `batch_size = 2048`
- `pool_grace_ms = 35/100/200`
- `pool_reuse_limit_per_round = 5`

Observed behavior:

- Reuse was active.
- `g=200` slightly increased reused proposals.
- Wall-throughput still became worse because the extra waiting cost dominated.

Conclusion:

- In this setup, longer post-decision grace is a poor way to buy more reuse.

### 3. Reuse limit `2` was too aggressive in zero-grace mode

Config family:

- `slow20p12_15`
- `pool_grace_ms = 0`
- `pool_reuse_limit_per_round = 2`

Observed behavior:

- Reuse was active.
- Delivered transactions increased.
- Wall-throughput dropped sharply relative to baseline.

Conclusion:

- Reusing around two extra proposals per round was already enough to hurt end-to-end throughput in the local driver.

### 4. Some zero-grace combinations became unstable

Config family:

- `slow25p13_15`
- `pool_grace_ms = 0`
- `pool_reuse_limit_per_round = 1`

Observed behavior:

- Multiple runs timed out around round 5.
- The suite `reuse-zero-grace-n16-20260429` spent a long time waiting because each bad case consumed the full per-round `global_timeout = 300s`.

Conclusion:

- This regime is too aggressive and should be avoided in future scans.

## Positive Findings

### Best confirmed candidate

Config:

- `backend = rust_fin`
- `nodes = 16`
- `batch_size = 1024`
- `network_fault = slow20p12_15`
- `pool_grace_ms = 0`
- `pool_reuse_limit_per_round = 1`
- `pool_expire_rounds = 3`
- `pool_mempool_max = 4096`
- `rounds = 16`
- `repeats = 4`

Confirmation result directory:

- `benchmarks/results/reuse-best-candidate-n16-20260429/`

Mean result:

| Metric | Reuse Off | Reuse On | Delta |
| --- | ---: | ---: | ---: |
| `tps_wall_mean` | 17133.06 | 20562.50 | +20.02% |
| `wall_total_seconds_mean` | 10.53 | 9.52 | -9.58% |
| `delivered_total_mean` | 180224 | 195584 | +8.52% |
| `tracked_driver_bytes_per_delivered_tx_mean` | 202.44 | 189.31 | -6.49% |
| `reused_reference_total_mean` | 0 | 15 | active |

Interpretation:

- This point works because it reuses a small amount steadily.
- The mean ACS output still corresponds to 11 selected proposals per round, but one additional proposal is usually available for caching and later reuse.
- This gives a real throughput improvement without blowing up the TPKE tail cost.

## Practical Tuning Rules

- Prefer delaying fewer than `f` honest nodes when the goal is to expose useful reuse.
- Start from `pool_grace_ms = 0` if extra proposals are already known to become available before decision.
- Treat `pool_reuse_limit_per_round = 1` as the first serious wall-throughput candidate.
- Increase `pool_reuse_limit_per_round` only if reuse is too rare, not by default.
- Use larger `pool_grace_ms` only when instrumentation shows that desired proposals are finishing strictly after decision.
- During exploratory scans, reduce `global_timeout` to `90-120s` to avoid wasting time on obviously bad parameter regions.

## Recommended Next Use

If a future run needs one headline N=16 local-TCP candidate that currently looks strongest, use:

```toml
backend = ["rust_fin"]
reuse_enabled = [false, true]
nodes = [16]
batch_size = [1024]
rounds = 16
repeats = 4
global_timeout = 300.0
pool_grace_ms = 0
pool_reuse_limit_per_round = 1
pool_expire_rounds = 3
pool_mempool_max = 4096
enable_pool_reference_proposals = true
enable_pool_fetch_fallback = true
network_faults = [
  { label = "slow20p12_15", enabled = true, seed = 20260429, slow_honest = { pids = [12, 13, 14, 15], extra_delay_ms = 20 } },
]
```

## Caution

- These notes come from exploratory local loopback runs, not from restored formal `paper-final-*` archives.
- Do not quote these numbers in the thesis body without rerunning them under the final evidence workflow and preserving the final result directory.
