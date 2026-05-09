//! `honey-bench tps` subcommand — runs a single benchmark configuration,
//! computes comprehensive statistics (latency percentiles, subprotocol timings,
//! communication / fetch derived ratios, consistency checks), and writes JSON.

use crate::stats::{self, ConsistencySummary, LatencyStats, PeakStats, TimingStats};
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// Structured output of a single tps benchmark run.
#[derive(Debug, Clone)]
pub struct TpsResult {
    pub sid: String,
    pub protocol: String,
    pub backend: String,
    pub nodes: usize,
    pub faulty: usize,
    pub batch_size: usize,
    pub rounds: usize,
    pub warmup_rounds: usize,
    pub measured_rounds: usize,
    pub global_timeout: f64,
    pub enable_pool_reuse: bool,
    pub pool_grace_ms: u64,
    pub elapsed_seconds: f64,
    // Core throughput
    pub delivered_total: usize,
    pub tps_wall: f64,
    pub tps_acs: f64,
    pub wall_total_seconds: f64,
    pub acs_total_seconds: f64,
    // Latency statistics (all rounds / measured only)
    pub round_wall_latency_all: LatencyStats,
    pub round_acs_latency_all: LatencyStats,
    pub round_wall_latency_measured: LatencyStats,
    pub round_acs_latency_measured: LatencyStats,
    // Subprotocol timing breakdown
    pub subprotocol_timings: BTreeMap<String, TimingStats>,
    // Communication stats
    pub communication: stats::CommunicationStats,
    // Reuse stats
    pub reused_reference_total: usize,
    pub reused_references_per_delivered_tx: f64,
    // Fetch stats
    pub fetch: stats::FetchStats,
    // Transport summary
    pub transport: TransportSummary,
    // Byzantine stats
    pub byzantine: ByzantineSummary,
    // Queue peak stats
    pub queue_peak_stats: BTreeMap<String, PeakStats>,
    // Consistency
    pub consistency: ConsistencySummary,
    // Raw per-round data (for plotting)
    pub round_wall_seconds: Vec<f64>,
    pub round_acs_seconds: Vec<f64>,
}

#[derive(Debug, Clone, Default)]
pub struct TransportSummary {
    pub sent_frames_total: usize,
    pub recv_frames_total: usize,
    pub connect_retries_total: usize,
    pub send_retries_total: usize,
    pub delayed_frames_total: usize,
    pub total_injected_delay_ms_total: usize,
    pub max_delayed_frames_per_node: usize,
    pub max_injected_delay_ms_per_node: usize,
}

#[derive(Debug, Clone, Default)]
pub struct ByzantineSummary {
    pub invalid_fetch_responses_sent_total: usize,
    pub fetch_requests_ignored_total: usize,
    pub share_broadcast_suppressed_total: usize,
    pub empty_proposal_rounds_total: usize,
}

/// Build a `TpsResult` from the raw JSON output of a benchmark run.
pub fn build_tps_result(result_json: &Value, warmup_rounds: usize, backend: &str) -> TpsResult {
    let rounds_data = result_json["rounds"]
        .as_array()
        .map(|a| a.as_slice())
        .unwrap_or(&[]);
    let nodes_data = result_json["nodes"]
        .as_array()
        .map(|a| a.as_slice())
        .unwrap_or(&[]);

    let sid = result_json["sid"].as_str().unwrap_or("").to_owned();
    let protocol = result_json["protocol"]
        .as_str()
        .unwrap_or("dumbo")
        .to_owned();
    let nodes = result_json["nodes_count"].as_u64().unwrap_or(0) as usize;
    let faulty = result_json["faulty"].as_u64().unwrap_or(0) as usize;
    let enable_pool_reuse = result_json["enable_pool_reuse"].as_bool().unwrap_or(false);

    // Per-round metrics
    let mut round_wall_seconds: Vec<f64> = Vec::with_capacity(rounds_data.len());
    let mut round_acs_seconds: Vec<f64> = Vec::with_capacity(rounds_data.len());
    let mut subprotocol_timing_maps: Vec<BTreeMap<String, Value>> =
        Vec::with_capacity(rounds_data.len());
    let mut delivered_total = 0usize;
    let mut wall_total_seconds = 0.0f64;
    let mut acs_total_seconds = 0.0f64;
    let mut reused_reference_total = 0usize;

    for round in rounds_data {
        round_wall_seconds.push(round["wall_seconds"].as_f64().unwrap_or(0.0));
        round_acs_seconds.push(round["acs_seconds"].as_f64().unwrap_or(0.0));
        delivered_total += round["delivered_count"].as_u64().unwrap_or(0) as usize;
        wall_total_seconds += round["wall_seconds"].as_f64().unwrap_or(0.0);
        acs_total_seconds += round["acs_seconds"].as_f64().unwrap_or(0.0);
        reused_reference_total += round["reused_reference_count"].as_u64().unwrap_or(0) as usize;

        if let Some(timings) = round.get("subprotocol_timings").and_then(Value::as_object) {
            let map: BTreeMap<String, Value> = timings
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            subprotocol_timing_maps.push(map);
        }
    }

    // Split warmup / measured
    let (_warmup_rounds, measured_rounds) = stats::split_warmup_rounds(rounds_data, warmup_rounds);
    let measured_round_count = measured_rounds.len();
    let (measured_wall, measured_acs) =
        if warmup_rounds > 0 && warmup_rounds < round_wall_seconds.len() {
            (
                round_wall_seconds[warmup_rounds..].to_vec(),
                round_acs_seconds[warmup_rounds..].to_vec(),
            )
        } else {
            (round_wall_seconds.clone(), round_acs_seconds.clone())
        };

    let total_rounds = rounds_data.len();
    let tps_wall = if wall_total_seconds > 0.0 {
        delivered_total as f64 / wall_total_seconds
    } else {
        0.0
    };
    let tps_acs = if acs_total_seconds > 0.0 {
        delivered_total as f64 / acs_total_seconds
    } else {
        0.0
    };

    // CommunicationStats from round data
    let communication = stats::CommunicationStats::from_rounds(rounds_data, delivered_total);

    // FetchStats
    let fetch = stats::FetchStats::from_rounds(rounds_data, delivered_total);

    // Subprotocol timing stats
    let mut subprotocol_timings = BTreeMap::new();
    for (metric_name, label) in stats::subprotocol_labels() {
        let ts = TimingStats::from_subprotocol_timings(&subprotocol_timing_maps, metric_name);
        subprotocol_timings.insert(label.to_string(), ts);
    }

    // Transport summary
    let mut transport = TransportSummary::default();
    for node in nodes_data {
        transport.sent_frames_total += node["transport_sent_frames"].as_u64().unwrap_or(0) as usize;
        transport.recv_frames_total += node["transport_recv_frames"].as_u64().unwrap_or(0) as usize;
        transport.connect_retries_total +=
            node["transport_connect_retries"].as_u64().unwrap_or(0) as usize;
        transport.delayed_frames_total +=
            node["transport_delayed_frames"].as_u64().unwrap_or(0) as usize;
        transport.total_injected_delay_ms_total += node["transport_total_injected_delay_ms"]
            .as_u64()
            .unwrap_or(0) as usize;
        let df = node["transport_delayed_frames"].as_u64().unwrap_or(0) as usize;
        let dm = node["transport_total_injected_delay_ms"]
            .as_u64()
            .unwrap_or(0) as usize;
        transport.max_delayed_frames_per_node = transport.max_delayed_frames_per_node.max(df);
        transport.max_injected_delay_ms_per_node = transport.max_injected_delay_ms_per_node.max(dm);
    }

    // Byzantine summary
    let mut byzantine = ByzantineSummary::default();
    for node in nodes_data {
        byzantine.invalid_fetch_responses_sent_total +=
            node["byzantine_invalid_fetch_responses_sent"]
                .as_u64()
                .unwrap_or(0) as usize;
        byzantine.fetch_requests_ignored_total += node["byzantine_fetch_requests_ignored"]
            .as_u64()
            .unwrap_or(0) as usize;
        byzantine.share_broadcast_suppressed_total += node["byzantine_share_broadcast_suppressed"]
            .as_u64()
            .unwrap_or(0) as usize;
        byzantine.empty_proposal_rounds_total += node["byzantine_empty_proposal_rounds"]
            .as_u64()
            .unwrap_or(0) as usize;
    }

    // Queue peak stats
    let mut queue_values: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for node in nodes_data {
        if let Some(peaks_obj) = node.get("queue_peaks").and_then(Value::as_object) {
            for (key, val) in peaks_obj {
                if let Some(num) = val.as_u64() {
                    queue_values.entry(key.clone()).or_default().push(num);
                }
            }
        }
    }
    let mut queue_peak_stats = BTreeMap::new();
    for (field, values) in &queue_values {
        queue_peak_stats.insert(field.clone(), PeakStats::from_values(values));
    }

    // Consistency
    let node_digests: Vec<Option<String>> = nodes_data
        .iter()
        .map(|n| n["chain_digest"].as_str().map(|s| s.to_owned()))
        .collect();
    let consistency = ConsistencySummary::from_node_digests(&node_digests);

    // Compute elapsed (wall clock from rounds)
    let elapsed_seconds = round_wall_seconds.iter().sum::<f64>();

    let div_tx = |n: usize| -> f64 {
        if delivered_total > 0 {
            n as f64 / delivered_total as f64
        } else {
            0.0
        }
    };

    TpsResult {
        sid,
        protocol,
        backend: backend.to_owned(),
        nodes,
        faulty,
        batch_size: 0, // filled by caller
        rounds: total_rounds,
        warmup_rounds,
        measured_rounds: measured_round_count,
        global_timeout: 0.0,
        enable_pool_reuse,
        pool_grace_ms: 0,
        elapsed_seconds,
        delivered_total,
        tps_wall,
        tps_acs,
        wall_total_seconds,
        acs_total_seconds,
        round_wall_latency_all: LatencyStats::from_seconds(&round_wall_seconds, total_rounds),
        round_acs_latency_all: LatencyStats::from_seconds(&round_acs_seconds, total_rounds),
        round_wall_latency_measured: LatencyStats::from_seconds(
            &measured_wall,
            measured_round_count,
        ),
        round_acs_latency_measured: LatencyStats::from_seconds(&measured_acs, measured_round_count),
        subprotocol_timings,
        communication,
        reused_reference_total,
        reused_references_per_delivered_tx: div_tx(reused_reference_total),
        fetch,
        transport,
        byzantine,
        queue_peak_stats,
        consistency,
        round_wall_seconds,
        round_acs_seconds,
    }
}

pub fn tps_result_to_json(result: &TpsResult) -> Value {
    json!({
        "sid": result.sid,
        "protocol": result.protocol,
        "backend": result.backend,
        "nodes": result.nodes,
        "faulty": result.faulty,
        "batch_size": result.batch_size,
        "rounds": result.rounds,
        "warmup_rounds": result.warmup_rounds,
        "measured_rounds": result.measured_rounds,
        "global_timeout": result.global_timeout,
        "enable_pool_reuse": result.enable_pool_reuse,
        "pool_grace_ms": result.pool_grace_ms,
        "elapsed_seconds": result.elapsed_seconds,
        "delivered_total": result.delivered_total,
        "tps_wall": result.tps_wall,
        "tps_acs": result.tps_acs,
        "wall_total_seconds": result.wall_total_seconds,
        "acs_total_seconds": result.acs_total_seconds,
        "round_wall_latency_all": latency_to_json(&result.round_wall_latency_all),
        "round_acs_latency_all": latency_to_json(&result.round_acs_latency_all),
        "round_wall_latency_measured": latency_to_json(&result.round_wall_latency_measured),
        "round_acs_latency_measured": latency_to_json(&result.round_acs_latency_measured),
        "round_wall_seconds": result.round_wall_seconds,
        "round_acs_seconds": result.round_acs_seconds,
        "subprotocol_timings": result.subprotocol_timings.iter().map(|(k, v)| {
            (k.clone(), json!({
                "sample_count": v.sample_count,
                "mean_ms": v.mean_ms,
                "max_ms": v.max_ms,
            }))
        }).collect::<BTreeMap<_, _>>(),
        "communication": json!({
            "send_events": result.communication.send_events,
            "send_payload_bytes": result.communication.send_payload_bytes,
            "proposal_available_events": result.communication.proposal_available_events,
            "proposal_available_payload_bytes": result.communication.proposal_available_payload_bytes,
            "proposal_available_proof_bytes": result.communication.proposal_available_proof_bytes,
            "total_tracked_bytes": result.communication.total_tracked_bytes,
            "bytes_per_delivered_transaction": result.communication.bytes_per_delivered_transaction,
        }),
        "reused_reference_total": result.reused_reference_total,
        "reused_references_per_delivered_tx": result.reused_references_per_delivered_tx,
        "fetch": json!({
            "fetch_requests_sent": result.fetch.fetch_requests_sent,
            "fetch_responses_served": result.fetch.fetch_responses_served,
            "fetch_responses_received": result.fetch.fetch_responses_received,
            "fetched_reference_count": result.fetch.fetched_reference_count,
            "fetch_requests_per_delivered_transaction": result.fetch.fetch_requests_per_delivered_transaction,
            "fetched_references_per_delivered_transaction": result.fetch.fetched_references_per_delivered_transaction,
            "fetch_success_ratio": result.fetch.fetch_success_ratio,
        }),
        "transport": json!({
            "sent_frames_total": result.transport.sent_frames_total,
            "recv_frames_total": result.transport.recv_frames_total,
            "connect_retries_total": result.transport.connect_retries_total,
            "send_retries_total": result.transport.send_retries_total,
            "delayed_frames_total": result.transport.delayed_frames_total,
            "total_injected_delay_ms_total": result.transport.total_injected_delay_ms_total,
            "max_delayed_frames_per_node": result.transport.max_delayed_frames_per_node,
            "max_injected_delay_ms_per_node": result.transport.max_injected_delay_ms_per_node,
        }),
        "byzantine": json!({
            "invalid_fetch_responses_sent_total": result.byzantine.invalid_fetch_responses_sent_total,
            "fetch_requests_ignored_total": result.byzantine.fetch_requests_ignored_total,
            "share_broadcast_suppressed_total": result.byzantine.share_broadcast_suppressed_total,
            "empty_proposal_rounds_total": result.byzantine.empty_proposal_rounds_total,
        }),
        "consistency": json!({
            "all_nodes_agree": result.consistency.all_nodes_agree,
            "diverge_count": result.consistency.diverge_count,
            "diverged_pids": result.consistency.diverged_pids,
            "canonical_digest": result.consistency.canonical_digest,
        }),
        "queue_peak_stats": result.queue_peak_stats.iter().map(|(k, v)| {
            (k.clone(), json!({
                "mean": v.mean,
                "p95": v.p95,
                "max": v.max,
            }))
        }).collect::<BTreeMap<_, _>>(),
    })
}

fn latency_to_json(s: &LatencyStats) -> Value {
    json!({
        "sample_count": s.sample_count,
        "coverage": s.coverage,
        "mean_ms": s.mean_ms,
        "p50_ms": s.p50_ms,
        "p95_ms": s.p95_ms,
        "p99_ms": s.p99_ms,
        "max_ms": s.max_ms,
    })
}
