# Current Thesis Evidence Notes

This note records the result directories and headline numbers currently used by
`paper/main-codex.typ`.

## Main result directories

- QUIC minimal thesis suite:
  `benchmarks/results/dumbo-paper-suite-1777546922`
- QUIC full highload sweep:
  `benchmarks/results/dumbo-paper-suite-1777561891`
- TCP cross-check suite:
  `benchmarks/results/dumbo-paper-suite-1777545376`

## Manifest snapshot

- QUIC minimal suite:
  `paper_fill_minimal_quic`
  created at `2026-04-30T11:10:15Z`
  commit `e810af83d8d6077b7e7525e31dc2e61b7fb3111e`
- QUIC full sweep:
  `paper_highload_full_quic`
  created on `2026-05-01`
  use `summaries.csv` in the result directory for the main throughput table

## Highload headline numbers

Representative QUIC rows used in `main-codex.typ`:

- `python_dumbo`, `b=16`: `TPS_wall +9.79%`, `bytes/tx +11.26%`, `reused=21.0`
- `python_dumbo`, `b=32`: `TPS_wall +10.13%`, `bytes/tx +7.22%`, `reused=21.0`
- `python_dumbo`, `b=48`: `TPS_wall +15.56%`, `bytes/tx +2.04%`, `reused=21.0`
- `rust_fin`, `b=16`: `TPS_wall +21.90%`, `bytes/tx +21.68%`, `reused=21.0`
- `rust_fin`, `b=32`: `TPS_wall +18.93%`, `bytes/tx +13.91%`, `reused=21.0`
- `rust_fin`, `b=48`: `TPS_wall +19.12%`, `bytes/tx +8.27%`, `reused=21.0`

Full-sweep interpretation:

- `python_dumbo` stays positive across `b in {8,12,16,24,32,48,64}`:
  about `+7.80%` to `+15.56%` in `TPS_wall`
- `rust_fin` stays positive across the same sweep:
  about `+16.54%` to `+21.90%` in `TPS_wall`
- Current reruns do **not** reproduce lower `bytes/tx`; the normalized tracked
  byte metric rises in the current sweep

## Grace micro results

From `dumbo-paper-suite-1777546922/summaries.csv`:

- `50ms`: `TPS_wall 916.20`, `bytes/tx 682.97`, `reused 9.0`
- `100ms`: `TPS_wall 893.49`, `bytes/tx 688.33`, `reused 9.0`
- `200ms`: `TPS_wall 955.60`, `bytes/tx 673.95`, `reused 9.0`
- `400ms`: `TPS_wall 954.82`, `bytes/tx 675.17`, `reused 9.0`

Interpretation used in the thesis:

- the mechanism remains active across the tested window
- no strong monotonic optimum is reproduced in the current rerun

## Boundary results

Representative QUIC `rust_fin` rows from the minimal suite:

- slow honest `none`: `TPS_wall +17.23%`, `bytes/tx +13.83%`, `reused 21.0`, `fetch 0.0`
- slow honest `80ms`: `TPS_wall +19.14%`, `bytes/tx +13.71%`, `reused 21.0`, `fetch 0.0`
- slow honest `150ms`: `TPS_wall +15.38%`, `bytes/tx +15.14%`, `reused 21.0`, `fetch 0.0`
- byzantine `silent-p11`: `TPS_wall +15.49%`, `bytes/tx +16.33%`, `reused 21.0`, `fetch 0.0`
- byzantine `invalid_fetch_response-p11`: `TPS_wall +15.75%`, `bytes/tx +13.83%`, `reused 21.0`, `fetch 0.0`

Interpretation used in the thesis:

- reuse still improves throughput under these minimal perturbations
- fetch is not demonstrated as an active path in these runs
- main正文 experiments use `pool_expire_rounds = 10`, while the cited suites run
  only `4` or `8` rounds, so current fetch observations mostly reflect cache
  misses, not expiration-driven refetch

## TCP cross-check

TCP is not used as the main thesis table source, but representative points keep
the same direction:

- `rust_fin`, `b=32`, highload core:
  `reuse_off TPS_wall 440.14` -> `reuse_on TPS_wall 521.46`
- `rust_fin`, slow honest `none`:
  `reuse_off TPS_wall 441.91` -> `reuse_on TPS_wall 536.33`

## Metric caveat

The thesis now treats `tracked_driver_bytes_total` /
`tracked_driver_bytes_per_delivered_tx_mean` as a driver-observed composite
metric, not literal wire traffic. In the current implementation it combines:

- `send_payload_bytes_total`
- `proposal_available_payload_bytes_total`
- `proposal_available_proof_bytes_total`

This metric is still useful for within-implementation relative comparison, but
it should not be quoted as physical network bandwidth.
