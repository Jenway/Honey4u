//! Statistical helpers and structured benchmark metrics.
//!
//! Mirrors the Python-side `LatencyStats`, `TimingStats`, `PeakStats`,
//! `CommunicationStats`, `FetchStats`, and consistency checking used by
//! `benchmarks/cli/tps.py` so that Rust can own the full aggregation path.

use serde_json::Value;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Percentile (linear interpolation, matches tps.py `_percentile`)
// ---------------------------------------------------------------------------

/// Linear-interpolation percentile (P50, P95, P99).
///
/// `values` must be sorted in ascending order.
pub fn percentile(values: &[f64], p: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    if values.len() == 1 {
        return values[0];
    }
    let rank = (p / 100.0) * (values.len() - 1) as f64;
    let lower = rank as usize;
    let upper = (lower + 1).min(values.len() - 1);
    let weight = rank - lower as f64;
    values[lower] * (1.0 - weight) + values[upper] * weight
}

// ---------------------------------------------------------------------------
// LatencyStats
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct LatencyStats {
    pub sample_count: usize,
    pub coverage: f64,
    pub mean_ms: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
}

impl LatencyStats {
    pub fn from_seconds(samples_seconds: &[f64], expected_count: usize) -> Self {
        let coverage = if expected_count > 0 {
            samples_seconds.len() as f64 / expected_count as f64
        } else {
            0.0
        };
        if samples_seconds.is_empty() {
            return Self {
                sample_count: 0,
                coverage,
                mean_ms: 0.0,
                p50_ms: 0.0,
                p95_ms: 0.0,
                p99_ms: 0.0,
                max_ms: 0.0,
            };
        }
        let mut samples_ms: Vec<f64> = samples_seconds.iter().map(|s| s * 1000.0).collect();
        samples_ms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let sample_count = samples_ms.len();
        Self {
            sample_count,
            coverage,
            mean_ms: mean(&samples_ms),
            p50_ms: percentile(&samples_ms, 50.0),
            p95_ms: percentile(&samples_ms, 95.0),
            p99_ms: percentile(&samples_ms, 99.0),
            max_ms: *samples_ms.last().unwrap_or(&0.0),
        }
    }
}

// ---------------------------------------------------------------------------
// TimingStats
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct TimingStats {
    pub sample_count: usize,
    pub mean_ms: f64,
    pub max_ms: f64,
}

impl TimingStats {
    pub fn from_subprotocol_timings(
        round_timings: &[BTreeMap<String, Value>],
        label: &str,
    ) -> Self {
        let mut sample_count = 0usize;
        let mut total_seconds = 0.0f64;
        let mut max_seconds = 0.0f64;
        for timings_map in round_timings {
            let Some(entry) = timings_map.get(label) else {
                continue;
            };
            let sc = entry
                .get("sample_count")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize;
            let ts = entry
                .get("total_seconds")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let ms = entry
                .get("max_seconds")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            sample_count += sc;
            total_seconds += ts;
            if ms > max_seconds {
                max_seconds = ms;
            }
        }
        if sample_count == 0 {
            return Self::default();
        }
        Self {
            sample_count,
            mean_ms: (total_seconds / sample_count as f64) * 1000.0,
            max_ms: max_seconds * 1000.0,
        }
    }
}

// ---------------------------------------------------------------------------
// PeakStats
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PeakStats {
    pub mean: f64,
    pub p95: f64,
    pub max: u64,
}

impl PeakStats {
    pub fn from_values(values: &[u64]) -> Self {
        if values.is_empty() {
            return Self {
                mean: 0.0,
                p95: 0.0,
                max: 0,
            };
        }
        let mut float_vals: Vec<f64> = values.iter().map(|v| *v as f64).collect();
        float_vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let max_val = *values.iter().max().unwrap_or(&0);
        Self {
            mean: mean(&float_vals),
            p95: percentile(&float_vals, 95.0),
            max: max_val,
        }
    }
}

// ---------------------------------------------------------------------------
// CommunicationStats
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct CommunicationStats {
    pub send_events: usize,
    pub send_payload_bytes: usize,
    pub proposal_available_events: usize,
    pub proposal_available_payload_bytes: usize,
    pub proposal_available_proof_bytes: usize,
    pub total_tracked_bytes: usize,
    pub bytes_per_delivered_transaction: f64,
}

impl CommunicationStats {
    pub fn from_rounds(rounds: &[Value], delivered_transactions: usize) -> Self {
        let mut send_events = 0usize;
        let mut send_payload_bytes = 0usize;
        let mut proposal_available_events = 0usize;
        let mut proposal_available_payload_bytes = 0usize;
        let mut proposal_available_proof_bytes = 0usize;
        for round in rounds {
            let Some(stats) = round.get("acs_drive_stats") else {
                continue;
            };
            send_events += stats
                .get("send_events")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize;
            send_payload_bytes += stats
                .get("send_payload_bytes")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize;
            proposal_available_events += stats
                .get("proposal_available_events")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize;
            proposal_available_payload_bytes += stats
                .get("proposal_available_payload_bytes")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize;
            proposal_available_proof_bytes += stats
                .get("proposal_available_proof_bytes")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize;
        }
        let total_tracked_bytes =
            send_payload_bytes + proposal_available_payload_bytes + proposal_available_proof_bytes;
        Self {
            send_events,
            send_payload_bytes,
            proposal_available_events,
            proposal_available_payload_bytes,
            proposal_available_proof_bytes,
            total_tracked_bytes,
            bytes_per_delivered_transaction: if delivered_transactions > 0 {
                total_tracked_bytes as f64 / delivered_transactions as f64
            } else {
                0.0
            },
        }
    }
}

// ---------------------------------------------------------------------------
// FetchStats
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct FetchStats {
    pub fetch_requests_sent: usize,
    pub fetch_responses_served: usize,
    pub fetch_responses_received: usize,
    pub fetched_reference_count: usize,
    pub fetch_requests_per_delivered_transaction: f64,
    pub fetched_references_per_delivered_transaction: f64,
    pub fetch_success_ratio: f64,
}

impl FetchStats {
    pub fn from_rounds(rounds: &[Value], delivered_transactions: usize) -> Self {
        let mut fetch_requests_sent = 0usize;
        let mut fetch_responses_served = 0usize;
        let mut fetch_responses_received = 0usize;
        let mut fetched_reference_count = 0usize;
        for round in rounds {
            fetch_requests_sent += round
                .get("fetch_requests_sent")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize;
            fetch_responses_served += round
                .get("fetch_responses_served")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize;
            fetch_responses_received += round
                .get("fetch_responses_received")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize;
            fetched_reference_count += round
                .get("fetched_reference_count")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize;
        }
        let div = |n: usize, d: usize| -> f64 { if d > 0 { n as f64 / d as f64 } else { 0.0 } };
        Self {
            fetch_requests_sent,
            fetch_responses_served,
            fetch_responses_received,
            fetched_reference_count,
            fetch_requests_per_delivered_transaction: div(
                fetch_requests_sent,
                delivered_transactions,
            ),
            fetched_references_per_delivered_transaction: div(
                fetched_reference_count,
                delivered_transactions,
            ),
            fetch_success_ratio: if fetch_requests_sent > 0 {
                fetched_reference_count as f64 / fetch_requests_sent as f64
            } else {
                0.0
            },
        }
    }
}

// ---------------------------------------------------------------------------
// ConsistencySummary
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct ConsistencySummary {
    pub all_nodes_agree: bool,
    pub diverge_count: usize,
    pub diverged_pids: Vec<usize>,
    pub canonical_digest: Option<String>,
}

impl ConsistencySummary {
    pub fn from_node_digests(digests: &[Option<String>]) -> Self {
        if digests.is_empty() {
            return Self::default();
        }
        let canonical = digests[0].clone();
        if canonical.is_none() {
            return Self {
                all_nodes_agree: true,
                diverge_count: 0,
                diverged_pids: Vec::new(),
                canonical_digest: None,
            };
        }
        let canonical = canonical.unwrap();
        let mut diverged_pids = Vec::new();
        for (pid, digest) in digests.iter().enumerate() {
            if digest.as_ref() != Some(&canonical) {
                diverged_pids.push(pid);
            }
        }
        Self {
            all_nodes_agree: diverged_pids.is_empty(),
            diverge_count: diverged_pids.len(),
            diverged_pids,
            canonical_digest: Some(canonical),
        }
    }
}

// ---------------------------------------------------------------------------
// Warmup-aware round filtering
// ---------------------------------------------------------------------------

/// Split round array into warmup and measured slices.
pub fn split_warmup_rounds<'a>(
    rounds: &'a [Value],
    warmup_rounds: usize,
) -> (&'a [Value], &'a [Value]) {
    if warmup_rounds == 0 {
        return (&[], rounds);
    }
    let split = warmup_rounds.min(rounds.len());
    (&rounds[..split], &rounds[split..])
}

// ---------------------------------------------------------------------------
// Arithmetic helpers
// ---------------------------------------------------------------------------

pub fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f64>() / values.len() as f64
}

pub fn pct_change(old: f64, new: f64) -> f64 {
    if old == 0.0 {
        if new == 0.0 {
            return 0.0;
        }
        return f64::INFINITY;
    }
    ((new - old) / old.abs()) * 100.0
}

// ---------------------------------------------------------------------------
// Subprotocol metric name → label mapping (mirrors tps.py `_SUBPROTOCOL_LABELS`)
// ---------------------------------------------------------------------------

use std::sync::LazyLock;

static SUBPROTOCOL_LABELS_MAP: LazyLock<Vec<(&'static str, &'static str)>> = LazyLock::new(|| {
    vec![
        ("prbc_val", "PRBC Val"),
        ("prbc_echo", "PRBC Echo"),
        ("prbc_ready", "PRBC Ready"),
        ("prbc_output", "PRBC Output"),
        ("wrbc_send", "WRBC Send"),
        ("wrbc_echo", "WRBC Echo"),
        ("wrbc_ready", "WRBC Ready"),
        ("wrbc_reconstruct", "WRBC Reconstruct"),
        ("raba_coin", "Coin"),
        ("raba_val", "RABA Val"),
        ("raba_aux", "RABA Aux"),
        ("raba_conf", "RABA Conf"),
        ("raba_finish", "RABA Finish"),
        ("rbc_send", "RBC Send"),
        ("rbc_echo", "RBC Echo"),
        ("rbc_ready", "RBC Ready"),
        ("rbc_reconstruct", "RBC Reconstruct"),
        ("aba_bval", "ABA BVal"),
        ("aba_aux", "ABA Aux"),
        ("aba_coin", "ABA Coin"),
        ("aba_decide", "ABA Decide"),
    ]
});

/// Returns the human-readable label for a subprotocol metric name,
/// or the original metric_name if no mapping exists.
pub fn subprotocol_label<'a>(metric_name: &'a str) -> &'a str {
    for (key, label) in SUBPROTOCOL_LABELS_MAP.iter() {
        if *key == metric_name {
            return label;
        }
    }
    metric_name
}

pub fn subprotocol_labels() -> impl Iterator<Item = &'static (&'static str, &'static str)> {
    SUBPROTOCOL_LABELS_MAP.iter()
}

/// Known queue-peak field names (mirrors tps.py `_QUEUE_PEAK_FIELDS`).
pub const QUEUE_PEAK_FIELDS: &[&str] = &[
    "raw_inbound_messages",
    "raw_outbound_messages",
    "transport_inbound",
    "transport_outbound",
    "bridged_share_bundles",
    "bridged_pool_fetch_requests",
    "bridged_pool_fetch_responses",
    "acs_inbound_wire_buffered",
    "share_bundle_buffered",
    "pool_fetch_request_buffered",
    "pool_fetch_response_buffered",
];
