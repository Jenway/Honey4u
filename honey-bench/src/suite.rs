//! Suite runner: parses suite TOML, expands Cartesian product, runs each case,
//! aggregates results, and writes JSON + CSV output.
//!
//! Config-file driven benchmark suite runner for paper experiments
//! and dispatching to the matching internal protocol driver directly (no subprocess).

use crate::stats::{self, ConsistencySummary, LatencyStats, PeakStats, TimingStats};
use crate::{
    BenchBackendKind, BenchDriveArgs, BenchmarkProtocolFamily, current_build_info,
    format_build_info, load_node_binary_build_info, run_drive_multiprocess,
    suggested_node_build_command,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SUPPORTED_BACKENDS: &[&str] = &[
    "python_hb",
    "python_dumbo",
    "rust_fin",
    "rust_dumbo",
    "rust_hb",
];
const SUPPORTED_TRANSPORTS: &[&str] = &["tcp", "quic"];

/// Ordered list of keys that may appear as expansion dimensions in [[experiments]].
/// `byzantine_nodes` is intentionally absent — it is a fixed attribute of the
/// experiment (not a sweep dimension) and is extracted separately.
const DIMENSION_KEYS: &[&str] = &[
    "backend",
    "transport",
    "reuse_enabled",
    "nodes",
    "faulty",
    "batch_size",
    "rounds",
    "global_timeout",
    "pool_grace_ms",
    "pool_reuse_limit_per_round",
    "pool_expire_rounds",
    "pool_mempool_max",
    "enable_pool_reference_proposals",
    "enable_pool_fetch_fallback",
    "network_faults",
];

// ---------------------------------------------------------------------------
// Public options
// ---------------------------------------------------------------------------

pub struct SuiteRunOpts {
    /// Run only these experiments (None = all).
    pub experiments: Option<Vec<String>>,
    /// Print experiments list and exit.
    pub list_only: bool,
    /// Expand but do not execute.
    pub dry_run: bool,
    /// Cap total executed runs.
    pub max_runs: Option<usize>,
    /// Output directory (None = auto-timestamped).
    pub output_dir: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct FailedCase {
    experiment: String,
    label: String,
    error: String,
}

// ---------------------------------------------------------------------------
// Internal data structures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
struct NetworkFaultsCase {
    enabled: bool,
    seed: u64,
    fixed_delay_ms: u64,
    jitter_ms: u64,
    slow_honest_pids: Vec<u64>,
    slow_honest_extra_delay_ms: u64,
    custom_label: Option<String>,
}

impl NetworkFaultsCase {
    fn label(&self) -> String {
        if let Some(lbl) = &self.custom_label {
            return slugify(lbl);
        }
        if !self.enabled {
            return "none".to_owned();
        }
        let mut parts = Vec::<String>::new();
        if self.fixed_delay_ms > 0 {
            parts.push(format!("fd{}", self.fixed_delay_ms));
        }
        if self.jitter_ms > 0 {
            parts.push(format!("j{}", self.jitter_ms));
        }
        if !self.slow_honest_pids.is_empty() && self.slow_honest_extra_delay_ms > 0 {
            let pids = self
                .slow_honest_pids
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join("-");
            parts.push(format!("slow{}-p{}", self.slow_honest_extra_delay_ms, pids));
        }
        if self.seed > 0 {
            parts.push(format!("s{}", self.seed));
        }
        if parts.is_empty() {
            "enabled".to_owned()
        } else {
            parts.join("-")
        }
    }

    fn to_config_json(&self) -> Value {
        let mut obj = serde_json::Map::new();
        obj.insert("enabled".to_owned(), json!(self.enabled));
        if self.seed > 0 {
            obj.insert("seed".to_owned(), json!(self.seed));
        }
        if self.fixed_delay_ms > 0 {
            obj.insert("fixed_delay_ms".to_owned(), json!(self.fixed_delay_ms));
        }
        if self.jitter_ms > 0 {
            obj.insert("jitter_ms".to_owned(), json!(self.jitter_ms));
        }
        if !self.slow_honest_pids.is_empty() {
            obj.insert(
                "slow_honest".to_owned(),
                json!({
                    "pids": self.slow_honest_pids,
                    "extra_delay_ms": self.slow_honest_extra_delay_ms,
                }),
            );
        }
        Value::Object(obj)
    }
}

#[derive(Debug, Clone)]
struct ByzantineNodeCase {
    pid: u64,
    behavior: String,
}

#[derive(Debug, Clone)]
struct ExperimentCase {
    backend: String,
    transport: String,
    reuse_enabled: bool,
    nodes: usize,
    faulty: usize,
    batch_size: usize,
    rounds: usize,
    global_timeout: f64,
    pool_grace_ms: u64,
    pool_reuse_limit_per_round: usize,
    pool_expire_rounds: u32,
    pool_mempool_max: usize,
    enable_pool_reference_proposals: bool,
    enable_pool_fetch_fallback: bool,
    network_faults: NetworkFaultsCase,
    byzantine_nodes: Vec<ByzantineNodeCase>,
    network_fault_label: String,
    byzantine_label: String,
}

struct ExperimentMeta {
    name: String,
    description: String,
    repeats: usize,
    case_count: usize,
    run_count: usize,
}

// ---------------------------------------------------------------------------
// Run record (one row per repeat execution)
// ---------------------------------------------------------------------------

#[allow(dead_code)]
struct RunRecord {
    // Group key fields
    experiment: String,
    backend: String,
    transport: String,
    reuse_mode: String,
    reuse_enabled: bool,
    nodes: usize,
    faulty: usize,
    batch_size: usize,
    rounds: usize,
    global_timeout: f64,
    pool_grace_ms: u64,
    pool_reuse_limit_per_round: usize,
    pool_expire_rounds: u32,
    pool_mempool_max: usize,
    enable_pool_reference_proposals: bool,
    enable_pool_fetch_fallback: bool,
    network_fault_label: String,
    byzantine_label: String,
    // Run-specific
    repeat_index: usize,
    elapsed_seconds: f64,
    // Core metrics
    delivered_total: usize,
    wall_total_seconds: f64,
    acs_total_seconds: f64,
    tps_wall: f64,
    tps_acs: f64,
    // ACS driver stats (summed over rounds)
    send_events_total: usize,
    send_payload_bytes_total: usize,
    proposal_available_events_total: usize,
    proposal_available_payload_bytes_total: usize,
    proposal_available_proof_bytes_total: usize,
    tracked_driver_bytes_total: usize,
    tracked_driver_bytes_per_delivered_tx: f64,
    // Pool reuse stats
    reused_reference_total: usize,
    reused_references_per_delivered_tx: f64,
    // Fetch stats
    fetch_requests_sent_total: usize,
    fetch_responses_served_total: usize,
    fetch_responses_received_total: usize,
    fetched_reference_total: usize,
    fetch_requests_per_delivered_tx: f64,
    fetched_references_per_delivered_tx: f64,
    // Transport stats
    transport_sent_frames_total: usize,
    transport_recv_frames_total: usize,
    transport_connect_retries_total: usize,
    transport_delayed_frames_total: usize,
    transport_injected_delay_ms_total: usize,
    transport_max_delayed_frames_per_node: usize,
    transport_max_injected_delay_ms_per_node: usize,
    // Byzantine stats
    byzantine_invalid_fetch_responses_sent_total: usize,
    byzantine_fetch_requests_ignored_total: usize,
    byzantine_share_broadcast_suppressed_total: usize,
    byzantine_empty_proposal_rounds_total: usize,
    chain_digest: Option<String>,
    // Per-round latency samples (for percentile computation in Summary)
    round_wall_seconds: Vec<f64>,
    round_acs_seconds: Vec<f64>,
    // Raw subprotocol timing maps (one per round)
    subprotocol_timings: Vec<BTreeMap<String, Value>>,
    // Queue peak snapshots (one per node)
    queue_peak_snapshots: Vec<Value>,
    // Per-node chain digests for consistency check
    node_chain_digests: Vec<Option<String>>,
    // Warmup rounds deducted from latency computation
    warmup_rounds: usize,
}

// ---------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------

#[derive(Hash, PartialEq, Eq, Clone)]
struct AggKey {
    experiment: String,
    backend: String,
    transport: String,
    reuse_mode: String,
    nodes: usize,
    faulty: usize,
    batch_size: usize,
    rounds: usize,
    global_timeout_repr: String,
    pool_grace_ms: u64,
    pool_reuse_limit_per_round: usize,
    pool_expire_rounds: u32,
    pool_mempool_max: usize,
    enable_pool_reference_proposals: bool,
    enable_pool_fetch_fallback: bool,
    network_fault_label: String,
    byzantine_label: String,
}

impl AggKey {
    fn from_record(r: &RunRecord) -> Self {
        Self {
            experiment: r.experiment.clone(),
            backend: r.backend.clone(),
            transport: r.transport.clone(),
            reuse_mode: r.reuse_mode.clone(),
            nodes: r.nodes,
            faulty: r.faulty,
            batch_size: r.batch_size,
            rounds: r.rounds,
            global_timeout_repr: format!("{:.6}", r.global_timeout),
            pool_grace_ms: r.pool_grace_ms,
            pool_reuse_limit_per_round: r.pool_reuse_limit_per_round,
            pool_expire_rounds: r.pool_expire_rounds,
            pool_mempool_max: r.pool_mempool_max,
            enable_pool_reference_proposals: r.enable_pool_reference_proposals,
            enable_pool_fetch_fallback: r.enable_pool_fetch_fallback,
            network_fault_label: r.network_fault_label.clone(),
            byzantine_label: r.byzantine_label.clone(),
        }
    }
}

struct Summary {
    key: AggKey,
    run_count: usize,
    // All mean fields (same list as Python `mean_fields`)
    elapsed_seconds_mean: f64,
    delivered_total_mean: f64,
    wall_total_seconds_mean: f64,
    acs_total_seconds_mean: f64,
    tps_wall_mean: f64,
    tps_acs_mean: f64,
    send_events_total_mean: f64,
    send_payload_bytes_total_mean: f64,
    proposal_available_events_total_mean: f64,
    proposal_available_payload_bytes_total_mean: f64,
    proposal_available_proof_bytes_total_mean: f64,
    tracked_driver_bytes_total_mean: f64,
    tracked_driver_bytes_per_delivered_tx_mean: f64,
    reused_reference_total_mean: f64,
    reused_references_per_delivered_tx_mean: f64,
    fetch_requests_sent_total_mean: f64,
    fetch_responses_served_total_mean: f64,
    fetch_responses_received_total_mean: f64,
    fetched_reference_total_mean: f64,
    fetch_requests_per_delivered_tx_mean: f64,
    fetched_references_per_delivered_tx_mean: f64,
    transport_sent_frames_total_mean: f64,
    transport_recv_frames_total_mean: f64,
    transport_connect_retries_total_mean: f64,
    transport_delayed_frames_total_mean: f64,
    transport_injected_delay_ms_total_mean: f64,
    transport_max_delayed_frames_per_node_mean: f64,
    transport_max_injected_delay_ms_per_node_mean: f64,
    byzantine_invalid_fetch_responses_sent_total_mean: f64,
    byzantine_fetch_requests_ignored_total_mean: f64,
    byzantine_share_broadcast_suppressed_total_mean: f64,
    byzantine_empty_proposal_rounds_total_mean: f64,
    // New comprehensive statistics from stats.rs
    round_wall_latency: LatencyStats,
    round_acs_latency: LatencyStats,
    subprotocol_timings: BTreeMap<String, TimingStats>,
    bytes_per_delivered_transaction: f64,
    fetch_success_ratio: f64,
    consistency: ConsistencySummary,
    queue_peak_stats: BTreeMap<String, PeakStats>,
}

// ---------------------------------------------------------------------------
// Helper utilities
// ---------------------------------------------------------------------------

fn slugify(s: &str) -> String {
    let mut out = String::new();
    let mut prev_dash = false;
    for ch in s.trim().chars() {
        if ch.is_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    let s = out.trim_matches('-').to_owned();
    if s.is_empty() {
        "unnamed".to_owned()
    } else {
        s
    }
}

fn reuse_mode_label(enabled: bool) -> &'static str {
    if enabled { "reuse_on" } else { "reuse_off" }
}

fn protocol_family_label(family: BenchmarkProtocolFamily) -> &'static str {
    match family {
        BenchmarkProtocolFamily::HoneyBadger => "hb",
        BenchmarkProtocolFamily::Dumbo => "dumbo",
    }
}

fn protocol_family_for_backend(backend: &str) -> Result<BenchmarkProtocolFamily, String> {
    Ok(BenchBackendKind::parse(backend)?.benchmark_protocol_family())
}

fn backend_delta_baseline(backend: &str) -> Result<&'static str, String> {
    Ok(match protocol_family_for_backend(backend)? {
        BenchmarkProtocolFamily::HoneyBadger => "python_hb",
        BenchmarkProtocolFamily::Dumbo => "python_dumbo",
    })
}

fn fmean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f64>() / values.len() as f64
}

fn pct_change(new_val: f64, old_val: f64) -> f64 {
    if old_val == 0.0 {
        0.0
    } else {
        ((new_val / old_val) - 1.0) * 100.0
    }
}

fn default_output_dir() -> PathBuf {
    // Timestamped directory under honey-bench/results/
    let stamp = {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Format as YYYYMMDDTHHMMSSz (rough, UTC not guaranteed)
        format!("{secs}")
    };
    PathBuf::from(crate::BENCH_RESULTS_DIR).join(format!("dumbo-paper-suite-{stamp}"))
}

// ---------------------------------------------------------------------------
// TOML parsing helpers
// ---------------------------------------------------------------------------

fn toml_as_bool(v: &toml::Value, key: &str) -> Result<bool, String> {
    v.as_bool()
        .ok_or_else(|| format!("{key} must be a boolean, got {v}"))
}

fn toml_as_usize(v: &toml::Value, key: &str, minimum: usize) -> Result<usize, String> {
    let n = v
        .as_integer()
        .ok_or_else(|| format!("{key} must be an integer, got {v}"))?;
    if n < minimum as i64 {
        return Err(format!("{key} must be >= {minimum}"));
    }
    Ok(n as usize)
}

fn toml_as_u64(v: &toml::Value, key: &str) -> Result<u64, String> {
    let n = v
        .as_integer()
        .ok_or_else(|| format!("{key} must be an integer, got {v}"))?;
    if n < 0 {
        return Err(format!("{key} must be >= 0"));
    }
    Ok(n as u64)
}

fn toml_as_f64(v: &toml::Value, key: &str, minimum: f64) -> Result<f64, String> {
    let f = match v {
        toml::Value::Float(f) => *f,
        toml::Value::Integer(i) => *i as f64,
        _ => return Err(format!("{key} must be numeric, got {v}")),
    };
    if f < minimum {
        return Err(format!("{key} must be >= {minimum}"));
    }
    Ok(f)
}

fn toml_as_str<'a>(v: &'a toml::Value, key: &str) -> Result<&'a str, String> {
    v.as_str()
        .ok_or_else(|| format!("{key} must be a string, got {v}"))
}

// ---------------------------------------------------------------------------
// Network faults parsing
// ---------------------------------------------------------------------------

fn parse_network_faults_table(
    table: &toml::map::Map<String, toml::Value>,
    ctx: &str,
) -> Result<NetworkFaultsCase, String> {
    let allowed = [
        "label",
        "enabled",
        "seed",
        "fixed_delay_ms",
        "jitter_ms",
        "slow_honest",
    ];
    for key in table.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(format!("{ctx} network_faults: unsupported key {key:?}"));
        }
    }

    let enabled = table
        .get("enabled")
        .map(|v| toml_as_bool(v, &format!("{ctx} network_faults.enabled")))
        .transpose()?
        .unwrap_or(false);
    let seed = table
        .get("seed")
        .map(|v| toml_as_u64(v, &format!("{ctx} network_faults.seed")))
        .transpose()?
        .unwrap_or(0);
    let fixed_delay_ms = table
        .get("fixed_delay_ms")
        .map(|v| toml_as_u64(v, &format!("{ctx} network_faults.fixed_delay_ms")))
        .transpose()?
        .unwrap_or(0);
    let jitter_ms = table
        .get("jitter_ms")
        .map(|v| toml_as_u64(v, &format!("{ctx} network_faults.jitter_ms")))
        .transpose()?
        .unwrap_or(0);
    let custom_label = table
        .get("label")
        .map(|v| toml_as_str(v, &format!("{ctx} network_faults.label")))
        .transpose()?
        .map(|s| s.to_owned());

    let (slow_honest_pids, slow_honest_extra_delay_ms) = if let Some(sh_val) =
        table.get("slow_honest")
    {
        let sh = sh_val
            .as_table()
            .ok_or_else(|| format!("{ctx} network_faults.slow_honest must be a table"))?;
        let pids = sh
            .get("pids")
            .map(|v| {
                v.as_array()
                    .ok_or_else(|| {
                        format!("{ctx} network_faults.slow_honest.pids must be an array")
                    })?
                    .iter()
                    .map(|p| toml_as_u64(p, &format!("{ctx} network_faults.slow_honest.pids[]")))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();
        let delay = sh
            .get("extra_delay_ms")
            .map(|v| {
                toml_as_u64(
                    v,
                    &format!("{ctx} network_faults.slow_honest.extra_delay_ms"),
                )
            })
            .transpose()?
            .unwrap_or(0);
        (pids, delay)
    } else {
        (Vec::new(), 0)
    };

    Ok(NetworkFaultsCase {
        enabled,
        seed,
        fixed_delay_ms,
        jitter_ms,
        slow_honest_pids,
        slow_honest_extra_delay_ms,
        custom_label,
    })
}

fn parse_network_faults_value(v: &toml::Value, ctx: &str) -> Result<NetworkFaultsCase, String> {
    match v {
        toml::Value::Table(t) => parse_network_faults_table(t, ctx),
        _ => Err(format!(
            "{ctx} network_faults must be a TOML table/inline table"
        )),
    }
}

// ---------------------------------------------------------------------------
// Byzantine nodes parsing
// ---------------------------------------------------------------------------

fn parse_byzantine_nodes(v: &toml::Value, ctx: &str) -> Result<Vec<ByzantineNodeCase>, String> {
    let arr = v
        .as_array()
        .ok_or_else(|| format!("{ctx} byzantine_nodes must be an array"))?;
    let mut nodes = Vec::with_capacity(arr.len());
    let mut seen_pids = std::collections::HashSet::new();
    for (i, item) in arr.iter().enumerate() {
        let t = item
            .as_table()
            .ok_or_else(|| format!("{ctx} byzantine_nodes[{i}] must be an inline table"))?;
        let pid = t
            .get("pid")
            .ok_or_else(|| format!("{ctx} byzantine_nodes[{i}] missing pid"))?;
        let pid = toml_as_u64(pid, &format!("{ctx} byzantine_nodes[{i}].pid"))?;
        let behavior = t
            .get("behavior")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("{ctx} byzantine_nodes[{i}].behavior must be a string"))?;
        if !["silent", "invalid_fetch_response"].contains(&behavior) {
            return Err(format!(
                "{ctx} byzantine_nodes[{i}].behavior must be 'silent' or 'invalid_fetch_response'"
            ));
        }
        if !seen_pids.insert(pid) {
            return Err(format!("{ctx} duplicate byzantine_nodes pid {pid}"));
        }
        nodes.push(ByzantineNodeCase {
            pid,
            behavior: behavior.to_owned(),
        });
    }
    Ok(nodes)
}

fn byzantine_label(nodes: &[ByzantineNodeCase]) -> String {
    if nodes.is_empty() {
        return "none".to_owned();
    }
    let mut sorted = nodes.to_vec();
    sorted.sort_by_key(|n| n.pid);
    sorted
        .iter()
        .map(|n| format!("{}-p{}", n.behavior, n.pid))
        .collect::<Vec<_>>()
        .join("-")
}

// ---------------------------------------------------------------------------
// Cartesian product expansion
// ---------------------------------------------------------------------------

fn cartesian_product(dims: Vec<Vec<toml::Value>>) -> Vec<Vec<toml::Value>> {
    dims.into_iter().fold(vec![vec![]], |acc, dim| {
        acc.into_iter()
            .flat_map(|row| {
                dim.iter()
                    .map(move |v| {
                        let mut new_row = row.clone();
                        new_row.push(v.clone());
                        new_row
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    })
}

// ---------------------------------------------------------------------------
// Experiment expansion
// ---------------------------------------------------------------------------

fn expand_experiment(
    experiment: &toml::map::Map<String, toml::Value>,
    defaults: &toml::map::Map<String, toml::Value>,
) -> Result<(ExperimentMeta, Vec<ExperimentCase>), String> {
    // Merge: defaults first, experiment overrides
    let mut merged: toml::map::Map<String, toml::Value> = defaults.clone();
    for (k, v) in experiment {
        merged.insert(k.clone(), v.clone());
    }

    let name = merged
        .remove("name")
        .and_then(|v| v.as_str().map(|s| s.to_owned()))
        .ok_or("experiment missing 'name' field")?;
    let ctx = format!("experiment {name:?}:");

    let description = merged
        .remove("description")
        .and_then(|v| v.as_str().map(|s| s.to_owned()))
        .unwrap_or_default();

    let repeats = merged
        .remove("repeats")
        .map(|v| toml_as_usize(&v, &format!("{ctx} repeats"), 1))
        .transpose()?
        .unwrap_or(1);

    let byzantine_nodes = merged
        .remove("byzantine_nodes")
        .as_ref()
        .map(|v| parse_byzantine_nodes(v, &ctx))
        .transpose()?
        .unwrap_or_default();

    // Extract dimension values (in canonical order)
    let mut dimensions: Vec<(String, Vec<toml::Value>)> = Vec::new();
    for &key in DIMENSION_KEYS {
        let Some(value) = merged.remove(key) else {
            continue;
        };
        let values: Vec<toml::Value> = if let toml::Value::Array(arr) = value {
            if arr.is_empty() {
                return Err(format!("{ctx} dimension {key:?} must not be empty"));
            }
            arr
        } else {
            vec![value]
        };
        dimensions.push((key.to_owned(), values));
    }

    // Check for leftover unknown keys
    let extra_keys: Vec<_> = merged.keys().cloned().collect();
    if !extra_keys.is_empty() {
        return Err(format!("{ctx} unsupported keys: {}", extra_keys.join(", ")));
    }

    // Validate required dimensions
    let dim_set: std::collections::HashSet<&str> =
        dimensions.iter().map(|(k, _)| k.as_str()).collect();
    for req in ["backend", "nodes", "batch_size", "rounds", "global_timeout"] {
        if !dim_set.contains(req) {
            return Err(format!("{ctx} missing required dimension: {req:?}"));
        }
    }

    // Cartesian product
    let dim_values: Vec<Vec<toml::Value>> = dimensions.iter().map(|(_, v)| v.clone()).collect();
    let combos = cartesian_product(dim_values);
    let mut cases = Vec::with_capacity(combos.len());

    for combo in &combos {
        let mut map: HashMap<&str, &toml::Value> = dimensions
            .iter()
            .zip(combo.iter())
            .map(|((k, _), v)| (k.as_str(), v))
            .collect();

        let backend = toml_as_str(map["backend"], &format!("{ctx} backend"))?.to_owned();
        if !SUPPORTED_BACKENDS.contains(&backend.as_str()) {
            return Err(format!("{ctx} unsupported backend: {backend:?}"));
        }
        let transport = map
            .get("transport")
            .map(|v| toml_as_str(v, &format!("{ctx} transport")))
            .transpose()?
            .unwrap_or("quic")
            .to_owned();
        if !SUPPORTED_TRANSPORTS.contains(&transport.as_str()) {
            return Err(format!("{ctx} unsupported transport: {transport:?}"));
        }

        let nodes = toml_as_usize(map["nodes"], &format!("{ctx} nodes"), 1)?;
        let faulty = map
            .get("faulty")
            .map(|v| toml_as_usize(v, &format!("{ctx} faulty"), 0))
            .transpose()?
            .unwrap_or_else(|| nodes.saturating_sub(1) / 3);
        let batch_size = toml_as_usize(map["batch_size"], &format!("{ctx} batch_size"), 1)?;
        let rounds = toml_as_usize(map["rounds"], &format!("{ctx} rounds"), 1)?;
        let global_timeout = toml_as_f64(
            map["global_timeout"],
            &format!("{ctx} global_timeout"),
            0.001,
        )?;

        let reuse_enabled = map
            .get("reuse_enabled")
            .map(|v| toml_as_bool(v, &format!("{ctx} reuse_enabled")))
            .transpose()?
            .unwrap_or(false);
        let pool_grace_ms = map
            .get("pool_grace_ms")
            .map(|v| toml_as_u64(v, &format!("{ctx} pool_grace_ms")))
            .transpose()?
            .unwrap_or(100);
        let pool_reuse_limit_per_round = map
            .get("pool_reuse_limit_per_round")
            .map(|v| toml_as_usize(v, &format!("{ctx} pool_reuse_limit_per_round"), 0))
            .transpose()?
            .unwrap_or(4);
        let pool_expire_rounds = map
            .get("pool_expire_rounds")
            .map(|v| toml_as_usize(v, &format!("{ctx} pool_expire_rounds"), 0))
            .transpose()?
            .unwrap_or(10) as u32;
        let pool_mempool_max = map
            .get("pool_mempool_max")
            .map(|v| toml_as_usize(v, &format!("{ctx} pool_mempool_max"), 0))
            .transpose()?
            .unwrap_or(1024);
        let enable_pool_reference_proposals = map
            .get("enable_pool_reference_proposals")
            .map(|v| toml_as_bool(v, &format!("{ctx} enable_pool_reference_proposals")))
            .transpose()?
            .unwrap_or(true);
        let enable_pool_fetch_fallback = map
            .get("enable_pool_fetch_fallback")
            .map(|v| toml_as_bool(v, &format!("{ctx} enable_pool_fetch_fallback")))
            .transpose()?
            .unwrap_or(true);

        let network_faults = map
            .get("network_faults")
            .map(|v| parse_network_faults_value(v, &ctx))
            .transpose()?
            .unwrap_or_default();

        let network_fault_label = network_faults.label();
        let byz_label = byzantine_label(&byzantine_nodes);

        cases.push(ExperimentCase {
            backend,
            transport,
            reuse_enabled,
            nodes,
            faulty,
            batch_size,
            rounds,
            global_timeout,
            pool_grace_ms,
            pool_reuse_limit_per_round,
            pool_expire_rounds,
            pool_mempool_max,
            enable_pool_reference_proposals,
            enable_pool_fetch_fallback,
            network_faults,
            byzantine_nodes: byzantine_nodes.clone(),
            network_fault_label,
            byzantine_label: byz_label,
        });

        let _ = map.remove("faulty");
        let _ = map.remove("transport");
        let _ = map.remove("reuse_enabled");
        let _ = map.remove("pool_grace_ms");
        let _ = map.remove("pool_reuse_limit_per_round");
        let _ = map.remove("pool_expire_rounds");
        let _ = map.remove("pool_mempool_max");
        let _ = map.remove("enable_pool_reference_proposals");
        let _ = map.remove("enable_pool_fetch_fallback");
        let _ = map.remove("network_faults");
    }

    let meta = ExperimentMeta {
        name,
        description,
        repeats,
        case_count: cases.len(),
        run_count: cases.len() * repeats,
    };
    Ok((meta, cases))
}

// ---------------------------------------------------------------------------
// Config JSON generation (input to honey-bench/honey-node)
// ---------------------------------------------------------------------------

fn build_config_json(case: &ExperimentCase) -> String {
    let mut byz_arr = serde_json::Value::Array(Vec::new());
    if !case.byzantine_nodes.is_empty() {
        let nodes: Vec<serde_json::Value> = case
            .byzantine_nodes
            .iter()
            .map(|n| json!({"pid": n.pid, "behavior": n.behavior}))
            .collect();
        byz_arr = serde_json::Value::Array(nodes);
    }
    serde_json::to_string(&json!({
        "acs_backend": case.backend,
        "transport": case.transport,
        "enable_broadcast_pool_reuse": case.reuse_enabled,
        "enable_pool_reference_proposals": case.enable_pool_reference_proposals,
        "enable_pool_fetch_fallback": case.enable_pool_fetch_fallback,
        "pool_grace_ms": case.pool_grace_ms,
        "pool_reuse_limit_per_round": case.pool_reuse_limit_per_round,
        "pool_expire_rounds": case.pool_expire_rounds,
        "pool_mempool_max": case.pool_mempool_max,
        "network_faults": case.network_faults.to_config_json(),
        "byzantine_nodes": byz_arr,
    }))
    .expect("config JSON serialization is infallible")
}

fn case_label(case: &ExperimentCase, repeat_index: usize) -> String {
    let reuse = reuse_mode_label(case.reuse_enabled).replace('_', "-");
    format!(
        "{}-{}-{}-n{}-b{}-r{}-g{}-l{}-e{}-m{}-nf{}-rep{}",
        case.backend,
        case.transport,
        reuse,
        case.nodes,
        case.batch_size,
        case.rounds,
        case.pool_grace_ms,
        case.pool_reuse_limit_per_round,
        case.pool_expire_rounds,
        case.pool_mempool_max,
        case.network_fault_label,
        repeat_index,
    )
}

fn case_sid(experiment_name: &str, case: &ExperimentCase, repeat_index: usize) -> String {
    format!(
        "bench:suite:{}:{}:{}:{}:{}:n{}:b{}:nf{}:rep{}",
        protocol_family_label(
            protocol_family_for_backend(&case.backend).expect("validated backend must parse"),
        ),
        experiment_name,
        case.backend,
        case.transport,
        reuse_mode_label(case.reuse_enabled),
        case.nodes,
        case.batch_size,
        case.network_fault_label,
        repeat_index,
    )
}

/// Render a flat TOML string for the case (saved alongside raw results for
/// reproducing individual runs).
fn render_config_toml(sid: &str, case: &ExperimentCase) -> String {
    let nf_json = serde_json::to_string(&case.network_faults.to_config_json())
        .unwrap_or_else(|_| "{}".to_owned());
    let byz_json: String = if case.byzantine_nodes.is_empty() {
        "[]".to_owned()
    } else {
        serde_json::to_string(
            &case
                .byzantine_nodes
                .iter()
                .map(|n| json!({"pid": n.pid, "behavior": n.behavior}))
                .collect::<Vec<_>>(),
        )
        .unwrap_or_else(|_| "[]".to_owned())
    };
    format!(
        r#"mode = "{mode}"
sid = "{sid}"
nodes = {nodes}
faulty = {faulty}
rounds = {rounds}
batch_size = {batch_size}
global_timeout = {global_timeout}

[config]
acs_backend = "{backend}"
transport = "{transport}"
enable_broadcast_pool_reuse = {reuse_enabled}
enable_pool_reference_proposals = {enable_pool_reference_proposals}
enable_pool_fetch_fallback = {enable_pool_fetch_fallback}
pool_grace_ms = {pool_grace_ms}
pool_reuse_limit_per_round = {pool_reuse_limit_per_round}
pool_expire_rounds = {pool_expire_rounds}
pool_mempool_max = {pool_mempool_max}
network_faults = {nf_json}
byzantine_nodes = {byz_json}
"#,
        nodes = case.nodes,
        faulty = case.faulty,
        rounds = case.rounds,
        batch_size = case.batch_size,
        global_timeout = case.global_timeout,
        backend = case.backend,
        transport = case.transport,
        reuse_enabled = case.reuse_enabled,
        enable_pool_reference_proposals = case.enable_pool_reference_proposals,
        enable_pool_fetch_fallback = case.enable_pool_fetch_fallback,
        pool_grace_ms = case.pool_grace_ms,
        pool_reuse_limit_per_round = case.pool_reuse_limit_per_round,
        pool_expire_rounds = case.pool_expire_rounds,
        pool_mempool_max = case.pool_mempool_max,
        mode = protocol_family_label(
            protocol_family_for_backend(&case.backend).expect("validated backend must parse"),
        ),
    )
}

// ---------------------------------------------------------------------------
// Metrics extraction from honey-bench JSON output
// ---------------------------------------------------------------------------

fn extract_run_record(
    experiment: &str,
    case: &ExperimentCase,
    repeat_index: usize,
    elapsed_seconds: f64,
    result_json: &Value,
) -> RunRecord {
    let rounds_data = result_json["rounds"]
        .as_array()
        .map(|a| a.as_slice())
        .unwrap_or(&[]);
    let nodes_data = result_json["nodes"]
        .as_array()
        .map(|a| a.as_slice())
        .unwrap_or(&[]);

    // Collect per-round latency samples
    let mut round_wall_seconds: Vec<f64> = Vec::with_capacity(rounds_data.len());
    let mut round_acs_seconds: Vec<f64> = Vec::with_capacity(rounds_data.len());
    let mut subprotocol_timings: Vec<BTreeMap<String, Value>> =
        Vec::with_capacity(rounds_data.len());

    // Aggregate per-round metrics
    let mut delivered_total = 0usize;
    let mut wall_total_seconds = 0.0f64;
    let mut acs_total_seconds = 0.0f64;
    let mut send_events_total = 0usize;
    let mut send_payload_bytes_total = 0usize;
    let mut proposal_available_events_total = 0usize;
    let mut proposal_available_payload_bytes_total = 0usize;
    let mut proposal_available_proof_bytes_total = 0usize;
    let mut reused_reference_total = 0usize;
    let mut fetch_requests_sent_total = 0usize;
    let mut fetch_responses_served_total = 0usize;
    let mut fetch_responses_received_total = 0usize;
    let mut fetched_reference_total = 0usize;

    for round in rounds_data {
        round_wall_seconds.push(round["wall_seconds"].as_f64().unwrap_or(0.0));
        round_acs_seconds.push(round["acs_seconds"].as_f64().unwrap_or(0.0));

        // Capture subprotocol timings if present
        if let Some(timings) = round.get("subprotocol_timings").and_then(Value::as_object) {
            let map: BTreeMap<String, Value> = timings
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            subprotocol_timings.push(map);
        }

        delivered_total += round["delivered_count"].as_u64().unwrap_or(0) as usize;
        wall_total_seconds += round["wall_seconds"].as_f64().unwrap_or(0.0);
        acs_total_seconds += round["acs_seconds"].as_f64().unwrap_or(0.0);
        reused_reference_total += round["reused_reference_count"].as_u64().unwrap_or(0) as usize;
        fetch_requests_sent_total += round["fetch_requests_sent"].as_u64().unwrap_or(0) as usize;
        fetch_responses_served_total +=
            round["fetch_responses_served"].as_u64().unwrap_or(0) as usize;
        fetch_responses_received_total +=
            round["fetch_responses_received"].as_u64().unwrap_or(0) as usize;
        fetched_reference_total += round["fetched_reference_count"].as_u64().unwrap_or(0) as usize;

        let stats = &round["acs_drive_stats"];
        send_events_total += stats["send_events"].as_u64().unwrap_or(0) as usize;
        let spb = stats["send_payload_bytes"].as_u64().unwrap_or(0) as usize;
        let prpb = stats["proposal_available_payload_bytes"]
            .as_u64()
            .unwrap_or(0) as usize;
        let prcb = stats["proposal_available_proof_bytes"]
            .as_u64()
            .unwrap_or(0) as usize;
        send_payload_bytes_total += spb;
        proposal_available_events_total +=
            stats["proposal_available_events"].as_u64().unwrap_or(0) as usize;
        proposal_available_payload_bytes_total += prpb;
        proposal_available_proof_bytes_total += prcb;
    }

    // Keep this aligned with `CommunicationStats::from_rounds`: it is a
    // driver-observed byte surface for relative comparison, not literal
    // end-to-end wire traffic.
    let tracked_driver_bytes_total = send_payload_bytes_total
        + proposal_available_payload_bytes_total
        + proposal_available_proof_bytes_total;

    // Collect per-node chain digests and queue peak snapshots
    let mut node_chain_digests: Vec<Option<String>> = Vec::with_capacity(nodes_data.len());
    let mut queue_peak_snapshots: Vec<Value> = Vec::with_capacity(nodes_data.len());
    for node in nodes_data {
        node_chain_digests.push(node["chain_digest"].as_str().map(|s| s.to_owned()));
        if let Some(peaks) = node.get("queue_peaks") {
            queue_peak_snapshots.push(peaks.clone());
        }
    }

    // Aggregate per-node transport metrics
    let mut transport_sent_frames_total = 0usize;
    let mut transport_recv_frames_total = 0usize;
    let mut transport_connect_retries_total = 0usize;
    let mut transport_delayed_frames_total = 0usize;
    let mut transport_injected_delay_ms_total = 0usize;
    let mut transport_max_delayed_frames_per_node = 0usize;
    let mut transport_max_injected_delay_ms_per_node = 0usize;
    let mut byzantine_invalid_fetch_responses_sent_total = 0usize;
    let mut byzantine_fetch_requests_ignored_total = 0usize;
    let mut byzantine_share_broadcast_suppressed_total = 0usize;
    let mut byzantine_empty_proposal_rounds_total = 0usize;

    for node in nodes_data {
        let sf = node["transport_sent_frames"].as_u64().unwrap_or(0) as usize;
        let rf = node["transport_recv_frames"].as_u64().unwrap_or(0) as usize;
        let cr = node["transport_connect_retries"].as_u64().unwrap_or(0) as usize;
        let df = node["transport_delayed_frames"].as_u64().unwrap_or(0) as usize;
        let dm = node["transport_total_injected_delay_ms"]
            .as_u64()
            .unwrap_or(0) as usize;
        transport_sent_frames_total += sf;
        transport_recv_frames_total += rf;
        transport_connect_retries_total += cr;
        transport_delayed_frames_total += df;
        transport_injected_delay_ms_total += dm;
        transport_max_delayed_frames_per_node = transport_max_delayed_frames_per_node.max(df);
        transport_max_injected_delay_ms_per_node = transport_max_injected_delay_ms_per_node.max(dm);
        byzantine_invalid_fetch_responses_sent_total +=
            node["byzantine_invalid_fetch_responses_sent"]
                .as_u64()
                .unwrap_or(0) as usize;
        byzantine_fetch_requests_ignored_total += node["byzantine_fetch_requests_ignored"]
            .as_u64()
            .unwrap_or(0) as usize;
        byzantine_share_broadcast_suppressed_total += node["byzantine_share_broadcast_suppressed"]
            .as_u64()
            .unwrap_or(0) as usize;
        byzantine_empty_proposal_rounds_total += node["byzantine_empty_proposal_rounds"]
            .as_u64()
            .unwrap_or(0) as usize;
    }

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
    let div = |n: usize| {
        if delivered_total > 0 {
            n as f64 / delivered_total as f64
        } else {
            0.0
        }
    };

    let chain_digest = result_json["chain_digest"].as_str().map(|s| s.to_owned());

    RunRecord {
        experiment: experiment.to_owned(),
        backend: case.backend.clone(),
        transport: case.transport.clone(),
        reuse_mode: reuse_mode_label(case.reuse_enabled).to_owned(),
        reuse_enabled: case.reuse_enabled,
        nodes: case.nodes,
        faulty: case.faulty,
        batch_size: case.batch_size,
        rounds: case.rounds,
        global_timeout: case.global_timeout,
        pool_grace_ms: case.pool_grace_ms,
        pool_reuse_limit_per_round: case.pool_reuse_limit_per_round,
        pool_expire_rounds: case.pool_expire_rounds,
        pool_mempool_max: case.pool_mempool_max,
        enable_pool_reference_proposals: case.enable_pool_reference_proposals,
        enable_pool_fetch_fallback: case.enable_pool_fetch_fallback,
        network_fault_label: case.network_fault_label.clone(),
        byzantine_label: case.byzantine_label.clone(),
        repeat_index,
        elapsed_seconds,
        delivered_total,
        wall_total_seconds,
        acs_total_seconds,
        tps_wall,
        tps_acs,
        send_events_total,
        send_payload_bytes_total,
        proposal_available_events_total,
        proposal_available_payload_bytes_total,
        proposal_available_proof_bytes_total,
        tracked_driver_bytes_total,
        tracked_driver_bytes_per_delivered_tx: div(tracked_driver_bytes_total),
        reused_reference_total,
        reused_references_per_delivered_tx: div(reused_reference_total),
        fetch_requests_sent_total,
        fetch_responses_served_total,
        fetch_responses_received_total,
        fetched_reference_total,
        fetch_requests_per_delivered_tx: div(fetch_requests_sent_total),
        fetched_references_per_delivered_tx: div(fetched_reference_total),
        transport_sent_frames_total,
        transport_recv_frames_total,
        transport_connect_retries_total,
        transport_delayed_frames_total,
        transport_injected_delay_ms_total,
        transport_max_delayed_frames_per_node,
        transport_max_injected_delay_ms_per_node,
        byzantine_invalid_fetch_responses_sent_total,
        byzantine_fetch_requests_ignored_total,
        byzantine_share_broadcast_suppressed_total,
        byzantine_empty_proposal_rounds_total,
        chain_digest,
        // New comprehensive stats
        round_wall_seconds,
        round_acs_seconds,
        subprotocol_timings,
        queue_peak_snapshots,
        node_chain_digests,
        warmup_rounds: 0, // filled in by caller if needed
    }
}

// ---------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------

fn aggregate_records(records: &[RunRecord]) -> Vec<Summary> {
    let mut groups: HashMap<AggKey, Vec<&RunRecord>> = HashMap::new();
    for r in records {
        groups.entry(AggKey::from_record(r)).or_default().push(r);
    }

    let mut summaries: Vec<Summary> = groups
        .into_iter()
        .map(|(key, runs)| {
            macro_rules! mean_f {
                ($field:ident) => {
                    fmean(&runs.iter().map(|r| r.$field as f64).collect::<Vec<_>>())
                };
            }
            macro_rules! mean_u {
                ($field:ident) => {
                    fmean(&runs.iter().map(|r| r.$field as f64).collect::<Vec<_>>())
                };
            }
            // Compute round latency statistics from all round samples across all repeats
            let mut all_wall_samples: Vec<f64> = Vec::new();
            let mut all_acs_samples: Vec<f64> = Vec::new();
            let mut all_timings: Vec<BTreeMap<String, Value>> = Vec::new();
            let mut all_queue_peaks: HashMap<String, Vec<u64>> = HashMap::new();
            let mut all_node_digests: Vec<Option<String>> = Vec::new();
            let mut total_delivered = 0usize;
            let mut total_tracked_bytes = 0usize;
            let mut total_fetch_reqs = 0usize;
            let mut total_fetched = 0usize;
            for r in &runs {
                all_wall_samples.extend(&r.round_wall_seconds);
                all_acs_samples.extend(&r.round_acs_seconds);
                all_timings.extend(r.subprotocol_timings.iter().cloned());
                total_delivered += r.delivered_total;
                total_tracked_bytes += r.tracked_driver_bytes_total;
                total_fetch_reqs += r.fetch_requests_sent_total;
                total_fetched += r.fetched_reference_total;
                all_node_digests.extend(r.node_chain_digests.iter().cloned());
                for peak in &r.queue_peak_snapshots {
                    for field in stats::QUEUE_PEAK_FIELDS {
                        if let Some(val) = peak.get(*field).and_then(Value::as_u64) {
                            all_queue_peaks
                                .entry(field.to_string())
                                .or_default()
                                .push(val);
                        }
                    }
                }
            }

            let expected_rounds_total: usize = runs.iter().map(|r| r.rounds).sum();
            let div_tx = |n: usize| -> f64 {
                if total_delivered > 0 {
                    n as f64 / total_delivered as f64
                } else {
                    0.0
                }
            };

            // Build consistency summary from node chain digests
            let consistency = ConsistencySummary::from_node_digests(&all_node_digests);

            // Build subprotocol timing stats
            let mut subprotocol_timings = BTreeMap::new();
            for (metric_name, label) in stats::subprotocol_labels() {
                let ts = TimingStats::from_subprotocol_timings(&all_timings, metric_name);
                subprotocol_timings.insert(label.to_string(), ts);
            }

            // Build queue peak stats
            let mut queue_peak_stats = BTreeMap::new();
            for (field, values) in &all_queue_peaks {
                queue_peak_stats.insert(field.clone(), PeakStats::from_values(values));
            }

            Summary {
                run_count: runs.len(),
                elapsed_seconds_mean: mean_f!(elapsed_seconds),
                delivered_total_mean: mean_u!(delivered_total),
                wall_total_seconds_mean: mean_f!(wall_total_seconds),
                acs_total_seconds_mean: mean_f!(acs_total_seconds),
                tps_wall_mean: mean_f!(tps_wall),
                tps_acs_mean: mean_f!(tps_acs),
                send_events_total_mean: mean_u!(send_events_total),
                send_payload_bytes_total_mean: mean_u!(send_payload_bytes_total),
                proposal_available_events_total_mean: mean_u!(proposal_available_events_total),
                proposal_available_payload_bytes_total_mean: mean_u!(
                    proposal_available_payload_bytes_total
                ),
                proposal_available_proof_bytes_total_mean: mean_u!(
                    proposal_available_proof_bytes_total
                ),
                tracked_driver_bytes_total_mean: mean_u!(tracked_driver_bytes_total),
                tracked_driver_bytes_per_delivered_tx_mean: mean_f!(
                    tracked_driver_bytes_per_delivered_tx
                ),
                reused_reference_total_mean: mean_u!(reused_reference_total),
                reused_references_per_delivered_tx_mean: mean_f!(
                    reused_references_per_delivered_tx
                ),
                fetch_requests_sent_total_mean: mean_u!(fetch_requests_sent_total),
                fetch_responses_served_total_mean: mean_u!(fetch_responses_served_total),
                fetch_responses_received_total_mean: mean_u!(fetch_responses_received_total),
                fetched_reference_total_mean: mean_u!(fetched_reference_total),
                fetch_requests_per_delivered_tx_mean: mean_f!(fetch_requests_per_delivered_tx),
                fetched_references_per_delivered_tx_mean: mean_f!(
                    fetched_references_per_delivered_tx
                ),
                transport_sent_frames_total_mean: mean_u!(transport_sent_frames_total),
                transport_recv_frames_total_mean: mean_u!(transport_recv_frames_total),
                transport_connect_retries_total_mean: mean_u!(transport_connect_retries_total),
                transport_delayed_frames_total_mean: mean_u!(transport_delayed_frames_total),
                transport_injected_delay_ms_total_mean: mean_u!(transport_injected_delay_ms_total),
                transport_max_delayed_frames_per_node_mean: mean_u!(
                    transport_max_delayed_frames_per_node
                ),
                transport_max_injected_delay_ms_per_node_mean: mean_u!(
                    transport_max_injected_delay_ms_per_node
                ),
                byzantine_invalid_fetch_responses_sent_total_mean: mean_u!(
                    byzantine_invalid_fetch_responses_sent_total
                ),
                byzantine_fetch_requests_ignored_total_mean: mean_u!(
                    byzantine_fetch_requests_ignored_total
                ),
                byzantine_share_broadcast_suppressed_total_mean: mean_u!(
                    byzantine_share_broadcast_suppressed_total
                ),
                byzantine_empty_proposal_rounds_total_mean: mean_u!(
                    byzantine_empty_proposal_rounds_total
                ),
                round_wall_latency: LatencyStats::from_seconds(
                    &all_wall_samples,
                    expected_rounds_total,
                ),
                round_acs_latency: LatencyStats::from_seconds(
                    &all_acs_samples,
                    expected_rounds_total,
                ),
                subprotocol_timings,
                bytes_per_delivered_transaction: div_tx(total_tracked_bytes),
                fetch_success_ratio: if total_fetch_reqs > 0 {
                    total_fetched as f64 / total_fetch_reqs as f64
                } else {
                    0.0
                },
                consistency,
                queue_peak_stats,
                key,
            }
        })
        .collect();

    // Sort deterministically: experiment, backend, transport, reuse_mode, nodes, batch_size, ...
    summaries.sort_by(|a, b| {
        let ka = &a.key;
        let kb = &b.key;
        ka.experiment
            .cmp(&kb.experiment)
            .then(ka.backend.cmp(&kb.backend))
            .then(ka.transport.cmp(&kb.transport))
            .then(ka.reuse_mode.cmp(&kb.reuse_mode))
            .then(ka.nodes.cmp(&kb.nodes))
            .then(ka.batch_size.cmp(&kb.batch_size))
            .then(ka.rounds.cmp(&kb.rounds))
            .then(ka.network_fault_label.cmp(&kb.network_fault_label))
            .then(ka.byzantine_label.cmp(&kb.byzantine_label))
    });
    summaries
}

fn build_reuse_deltas(summaries: &[Summary]) -> Vec<Value> {
    // Index by AggKey
    let indexed: HashMap<AggKey, &Summary> = summaries.iter().map(|s| (s.key.clone(), s)).collect();

    // Group keys without reuse_mode
    let mut common_keys: Vec<AggKey> = indexed.keys().cloned().collect();
    common_keys.sort_by(|a, b| {
        a.experiment
            .cmp(&b.experiment)
            .then(a.nodes.cmp(&b.nodes))
            .then(
                a.batch_size
                    .cmp(&b.batch_size)
                    .then(a.network_fault_label.cmp(&b.network_fault_label)),
            )
    });
    common_keys.dedup();

    let mut deltas = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for key in &common_keys {
        // Build the dedup fingerprint without reuse_mode
        let fingerprint = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            key.experiment,
            key.backend,
            key.transport,
            key.nodes,
            key.faulty,
            key.batch_size,
            key.rounds,
            key.global_timeout_repr,
            key.pool_grace_ms,
            key.pool_reuse_limit_per_round,
            key.pool_expire_rounds,
            key.pool_mempool_max,
            key.network_fault_label,
            key.byzantine_label,
        );
        if !seen.insert(fingerprint.clone()) {
            continue;
        }

        let off_key = AggKey {
            reuse_mode: "reuse_off".to_owned(),
            ..key.clone()
        };
        let on_key = AggKey {
            reuse_mode: "reuse_on".to_owned(),
            ..key.clone()
        };

        let Some(off) = indexed.get(&off_key) else {
            continue;
        };
        let Some(on) = indexed.get(&on_key) else {
            continue;
        };

        deltas.push(json!({
            "experiment": key.experiment,
            "backend": key.backend,
            "transport": key.transport,
            "nodes": key.nodes,
            "faulty": key.faulty,
            "batch_size": key.batch_size,
            "rounds": key.rounds,
            "global_timeout": key.global_timeout_repr,
            "pool_grace_ms": key.pool_grace_ms,
            "pool_reuse_limit_per_round": key.pool_reuse_limit_per_round,
            "pool_expire_rounds": key.pool_expire_rounds,
            "pool_mempool_max": key.pool_mempool_max,
            "enable_pool_reference_proposals": key.enable_pool_reference_proposals,
            "enable_pool_fetch_fallback": key.enable_pool_fetch_fallback,
            "network_fault_label": key.network_fault_label,
            "byzantine_label": key.byzantine_label,
            "tps_wall_delta_pct": pct_change(on.tps_wall_mean, off.tps_wall_mean),
            "tps_acs_delta_pct": pct_change(on.tps_acs_mean, off.tps_acs_mean),
            "wall_total_delta_pct": pct_change(on.wall_total_seconds_mean, off.wall_total_seconds_mean),
            "acs_total_delta_pct": pct_change(on.acs_total_seconds_mean, off.acs_total_seconds_mean),
            "tracked_driver_bytes_delta_pct": pct_change(on.tracked_driver_bytes_total_mean, off.tracked_driver_bytes_total_mean),
            "tracked_driver_bytes_per_tx_delta_pct": pct_change(on.tracked_driver_bytes_per_delivered_tx_mean, off.tracked_driver_bytes_per_delivered_tx_mean),
            "reused_reference_total_mean": on.reused_reference_total_mean,
            "fetch_requests_sent_total_mean": on.fetch_requests_sent_total_mean,
            "fetch_responses_served_total_mean": on.fetch_responses_served_total_mean,
            "fetch_responses_received_total_mean": on.fetch_responses_received_total_mean,
            "fetched_reference_total_mean": on.fetched_reference_total_mean,
        }));
    }
    deltas
}

fn build_backend_deltas(summaries: &[Summary]) -> Vec<Value> {
    let indexed: HashMap<AggKey, &Summary> = summaries.iter().map(|s| (s.key.clone(), s)).collect();

    let candidate_backends: std::collections::BTreeSet<String> = summaries
        .iter()
        .filter_map(|s| {
            let baseline = backend_delta_baseline(&s.key.backend).ok()?;
            (s.key.backend != baseline).then_some(s.key.backend.clone())
        })
        .collect();

    let mut seen = std::collections::HashSet::new();
    let mut deltas = Vec::new();

    for s in summaries {
        let Ok(baseline_backend) = backend_delta_baseline(&s.key.backend) else {
            continue;
        };
        let Ok(protocol_family) = protocol_family_for_backend(&s.key.backend) else {
            continue;
        };
        let protocol_family_name = protocol_family_label(protocol_family);
        let fingerprint = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            protocol_family_name,
            s.key.experiment,
            s.key.reuse_mode,
            s.key.transport,
            s.key.nodes,
            s.key.faulty,
            s.key.batch_size,
            s.key.rounds,
            s.key.global_timeout_repr,
            s.key.pool_grace_ms,
            s.key.pool_reuse_limit_per_round,
            s.key.pool_expire_rounds,
            s.key.pool_mempool_max,
            s.key.network_fault_label,
            s.key.byzantine_label,
        );
        if !seen.insert(fingerprint) {
            continue;
        }

        let python_key = AggKey {
            backend: baseline_backend.to_owned(),
            ..s.key.clone()
        };
        let Some(python_item) = indexed.get(&python_key) else {
            continue;
        };

        for backend in &candidate_backends {
            let Ok(candidate_family) = protocol_family_for_backend(backend) else {
                continue;
            };
            if candidate_family != protocol_family {
                continue;
            }
            let cand_key = AggKey {
                backend: backend.clone(),
                ..s.key.clone()
            };
            let Some(cand_item) = indexed.get(&cand_key) else {
                continue;
            };
            deltas.push(json!({
                "experiment": s.key.experiment,
                "protocol_family": protocol_family_name,
                "reuse_mode": s.key.reuse_mode,
                "transport": s.key.transport,
                "nodes": s.key.nodes,
                "faulty": s.key.faulty,
                "batch_size": s.key.batch_size,
                "rounds": s.key.rounds,
                "pool_grace_ms": s.key.pool_grace_ms,
                "network_fault_label": s.key.network_fault_label,
                "byzantine_label": s.key.byzantine_label,
                "candidate_backend": backend,
                "baseline_backend": baseline_backend,
                "candidate_vs_python_tps_wall_delta_pct": pct_change(cand_item.tps_wall_mean, python_item.tps_wall_mean),
                "candidate_vs_python_tps_acs_delta_pct": pct_change(cand_item.tps_acs_mean, python_item.tps_acs_mean),
                "candidate_vs_python_tracked_driver_bytes_delta_pct": pct_change(cand_item.tracked_driver_bytes_total_mean, python_item.tracked_driver_bytes_total_mean),
                "candidate_vs_python_bytes_per_tx_delta_pct": pct_change(cand_item.tracked_driver_bytes_per_delivered_tx_mean, python_item.tracked_driver_bytes_per_delivered_tx_mean),
                "python_fetch_requests_sent_total_mean": python_item.fetch_requests_sent_total_mean,
                "candidate_fetch_requests_sent_total_mean": cand_item.fetch_requests_sent_total_mean,
                "python_fetched_reference_total_mean": python_item.fetched_reference_total_mean,
                "candidate_fetched_reference_total_mean": cand_item.fetched_reference_total_mean,
            }));
        }
    }
    deltas
}

fn validate_suite_node_capabilities(
    node_binary: &Path,
    selected: &[&(ExperimentMeta, Vec<ExperimentCase>)],
) -> Result<(), String> {
    let build_info = load_node_binary_build_info(node_binary).map_err(|message| {
        format!(
            "{message}\nrebuild with:\n  cargo build -p honey-node --release [--features \"quic python-backend\"]"
        )
    })?;
    let mut requires_quic = false;
    let mut requires_python_backend = false;

    for (_, cases) in selected {
        for case in cases {
            if case.transport == "quic" {
                requires_quic = true;
            }
            if BenchBackendKind::parse(&case.backend)?.requires_python_backend() {
                requires_python_backend = true;
            }
        }
    }

    let mut missing = Vec::new();
    if requires_quic && !build_info.quic {
        missing.push("quic");
    }
    if requires_python_backend && !build_info.python_backend {
        missing.push("python-backend");
    }
    if missing.is_empty() {
        return Ok(());
    }

    let mut expected = current_build_info();
    expected.package = String::from("honey-node");
    expected.quic = requires_quic;
    expected.python_backend = requires_python_backend;
    Err(format!(
        "node binary '{}' is missing required capabilities for the selected suite cases:\n  need: {}\n  node: {}\nrebuild with:\n  {}",
        node_binary.display(),
        format_build_info(&expected),
        format_build_info(&build_info),
        suggested_node_build_command(node_binary, &expected),
    ))
}

// ---------------------------------------------------------------------------
// JSON / CSV serialization helpers
// ---------------------------------------------------------------------------

fn summary_to_json(s: &Summary) -> Value {
    json!({
        "experiment": s.key.experiment,
        "backend": s.key.backend,
        "transport": s.key.transport,
        "reuse_mode": s.key.reuse_mode,
        "nodes": s.key.nodes,
        "faulty": s.key.faulty,
        "batch_size": s.key.batch_size,
        "rounds": s.key.rounds,
        "global_timeout": s.key.global_timeout_repr,
        "pool_grace_ms": s.key.pool_grace_ms,
        "pool_reuse_limit_per_round": s.key.pool_reuse_limit_per_round,
        "pool_expire_rounds": s.key.pool_expire_rounds,
        "pool_mempool_max": s.key.pool_mempool_max,
        "enable_pool_reference_proposals": s.key.enable_pool_reference_proposals,
        "enable_pool_fetch_fallback": s.key.enable_pool_fetch_fallback,
        "network_fault_label": s.key.network_fault_label,
        "byzantine_label": s.key.byzantine_label,
        "run_count": s.run_count,
        "elapsed_seconds_mean": s.elapsed_seconds_mean,
        "delivered_total_mean": s.delivered_total_mean,
        "wall_total_seconds_mean": s.wall_total_seconds_mean,
        "acs_total_seconds_mean": s.acs_total_seconds_mean,
        "tps_wall_mean": s.tps_wall_mean,
        "tps_acs_mean": s.tps_acs_mean,
        "send_events_total_mean": s.send_events_total_mean,
        "send_payload_bytes_total_mean": s.send_payload_bytes_total_mean,
        "proposal_available_events_total_mean": s.proposal_available_events_total_mean,
        "proposal_available_payload_bytes_total_mean": s.proposal_available_payload_bytes_total_mean,
        "proposal_available_proof_bytes_total_mean": s.proposal_available_proof_bytes_total_mean,
        "tracked_driver_bytes_total_mean": s.tracked_driver_bytes_total_mean,
        "tracked_driver_bytes_per_delivered_tx_mean": s.tracked_driver_bytes_per_delivered_tx_mean,
        "reused_reference_total_mean": s.reused_reference_total_mean,
        "reused_references_per_delivered_tx_mean": s.reused_references_per_delivered_tx_mean,
        "fetch_requests_sent_total_mean": s.fetch_requests_sent_total_mean,
        "fetch_responses_served_total_mean": s.fetch_responses_served_total_mean,
        "fetch_responses_received_total_mean": s.fetch_responses_received_total_mean,
        "fetched_reference_total_mean": s.fetched_reference_total_mean,
        "fetch_requests_per_delivered_tx_mean": s.fetch_requests_per_delivered_tx_mean,
        "fetched_references_per_delivered_tx_mean": s.fetched_references_per_delivered_tx_mean,
        "transport_sent_frames_total_mean": s.transport_sent_frames_total_mean,
        "transport_recv_frames_total_mean": s.transport_recv_frames_total_mean,
        "transport_connect_retries_total_mean": s.transport_connect_retries_total_mean,
        "transport_delayed_frames_total_mean": s.transport_delayed_frames_total_mean,
        "transport_injected_delay_ms_total_mean": s.transport_injected_delay_ms_total_mean,
        "transport_max_delayed_frames_per_node_mean": s.transport_max_delayed_frames_per_node_mean,
        "transport_max_injected_delay_ms_per_node_mean": s.transport_max_injected_delay_ms_per_node_mean,
        "byzantine_invalid_fetch_responses_sent_total_mean": s.byzantine_invalid_fetch_responses_sent_total_mean,
        "byzantine_fetch_requests_ignored_total_mean": s.byzantine_fetch_requests_ignored_total_mean,
        "byzantine_share_broadcast_suppressed_total_mean": s.byzantine_share_broadcast_suppressed_total_mean,
        "byzantine_empty_proposal_rounds_total_mean": s.byzantine_empty_proposal_rounds_total_mean,
        // New comprehensive statistics
        "round_wall_latency": latency_to_json(&s.round_wall_latency),
        "round_acs_latency": latency_to_json(&s.round_acs_latency),
        "subprotocol_timings": s.subprotocol_timings.iter().map(|(k, v)| {
            (k.clone(), json!({
                "sample_count": v.sample_count,
                "mean_ms": v.mean_ms,
                "max_ms": v.max_ms,
            }))
        }).collect::<serde_json::Map<_, _>>(),
        "bytes_per_delivered_transaction": s.bytes_per_delivered_transaction,
        "fetch_success_ratio": s.fetch_success_ratio,
        "consistency": json!({
            "all_nodes_agree": s.consistency.all_nodes_agree,
            "diverge_count": s.consistency.diverge_count,
            "diverged_pids": s.consistency.diverged_pids,
            "canonical_digest": s.consistency.canonical_digest,
        }),
        "queue_peak_stats": s.queue_peak_stats.iter().map(|(k, v)| {
            (k.clone(), json!({
                "mean": v.mean,
                "p95": v.p95,
                "max": v.max,
            }))
        }).collect::<serde_json::Map<_, _>>(),
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

fn record_to_json(r: &RunRecord, raw_result: &Value) -> Value {
    json!({
        "experiment": r.experiment,
        "backend": r.backend,
        "transport": r.transport,
        "reuse_mode": r.reuse_mode,
        "reuse_enabled": r.reuse_enabled,
        "nodes": r.nodes,
        "faulty": r.faulty,
        "batch_size": r.batch_size,
        "rounds": r.rounds,
        "global_timeout": r.global_timeout,
        "pool_grace_ms": r.pool_grace_ms,
        "pool_reuse_limit_per_round": r.pool_reuse_limit_per_round,
        "pool_expire_rounds": r.pool_expire_rounds,
        "pool_mempool_max": r.pool_mempool_max,
        "enable_pool_reference_proposals": r.enable_pool_reference_proposals,
        "enable_pool_fetch_fallback": r.enable_pool_fetch_fallback,
        "network_fault_label": r.network_fault_label,
        "byzantine_label": r.byzantine_label,
        "repeat_index": r.repeat_index,
        "elapsed_seconds": r.elapsed_seconds,
        "delivered_total": r.delivered_total,
        "wall_total_seconds": r.wall_total_seconds,
        "acs_total_seconds": r.acs_total_seconds,
        "tps_wall": r.tps_wall,
        "tps_acs": r.tps_acs,
        "tracked_driver_bytes_total": r.tracked_driver_bytes_total,
        "tracked_driver_bytes_per_delivered_tx": r.tracked_driver_bytes_per_delivered_tx,
        "reused_reference_total": r.reused_reference_total,
        "fetch_requests_sent_total": r.fetch_requests_sent_total,
        "fetched_reference_total": r.fetched_reference_total,
        "chain_digest": r.chain_digest,
        "result": raw_result,
    })
}

/// Write a simple CSV from a slice of JSON objects. Header = union of all keys.
fn write_csv(path: &Path, rows: &[Value]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    if rows.is_empty() {
        fs::write(path, "").map_err(|e| e.to_string())?;
        return Ok(());
    }
    // Collect header (union of keys in insertion order of first row, then extras)
    let mut header: Vec<String> = Vec::new();
    let mut header_set = std::collections::HashSet::new();
    for row in rows {
        if let Some(obj) = row.as_object() {
            for k in obj.keys() {
                if header_set.insert(k.clone()) {
                    header.push(k.clone());
                }
            }
        }
    }
    let mut out = header
        .iter()
        .map(|h| csv_quote(h))
        .collect::<Vec<_>>()
        .join(",");
    out.push('\n');
    for row in rows {
        let cells: Vec<String> = header
            .iter()
            .map(|h| {
                let v = row.get(h).unwrap_or(&Value::Null);
                csv_quote(&json_to_csv_cell(v))
            })
            .collect();
        out.push_str(&cells.join(","));
        out.push('\n');
    }
    fs::write(path, &out).map_err(|e| e.to_string())
}

fn csv_quote(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_owned()
    }
}

fn json_to_csv_cell(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        Value::Array(_) | Value::Object(_) => v.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Suite loading
// ---------------------------------------------------------------------------

type TomlTable = toml::map::Map<String, toml::Value>;
type LoadedSuite = (String, TomlTable, Vec<TomlTable>);

fn load_suite(path: &Path) -> Result<LoadedSuite, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("failed to read suite config '{}': {e}", path.display()))?;
    let payload: toml::Value = toml::from_str(&content)
        .map_err(|e| format!("failed to parse suite config '{}': {e}", path.display()))?;

    let root = payload
        .as_table()
        .ok_or("suite config must be a TOML table")?;

    let suite_meta = root.get("suite").and_then(|v| v.as_table());
    let suite_name = suite_meta
        .and_then(|t| t.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| path.file_stem().and_then(|s| s.to_str()).unwrap_or("suite"))
        .to_owned();

    let defaults = root
        .get("defaults")
        .and_then(|v| v.as_table())
        .cloned()
        .unwrap_or_default();

    let experiments: Vec<toml::map::Map<String, toml::Value>> = root
        .get("experiments")
        .and_then(|v| v.as_array())
        .ok_or("suite config must have [[experiments]] entries")?
        .iter()
        .map(|v| {
            v.as_table()
                .cloned()
                .ok_or_else(|| "[[experiments]] entries must be TOML tables".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok((suite_name, defaults, experiments))
}

// ---------------------------------------------------------------------------
// Manifest helpers
// ---------------------------------------------------------------------------

/// Convert Unix epoch seconds to an ISO 8601 / RFC 3339 UTC string.
/// Uses the Howard Hinnant civil_from_days algorithm (public domain).
fn unix_secs_to_iso8601(secs: u64) -> String {
    let sec_of_day = secs % 86_400;
    let day_count = secs / 86_400;
    let hh = sec_of_day / 3_600;
    let mm = (sec_of_day % 3_600) / 60;
    let ss = sec_of_day % 60;

    let z = day_count as i64 + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y_adj = if m <= 2 { y + 1 } else { y };
    format!("{y_adj:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Run a git command and return trimmed stdout, or None on any failure.
fn run_git(args: &[&str]) -> Option<String> {
    std::process::Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

fn build_manifest(
    suite_path: &Path,
    suite_name: &str,
    selected_names: &[&str],
    total_runs: usize,
    runs_executed: usize,
    runs_failed: usize,
    failed_cases: &[FailedCase],
) -> Value {
    let created_at = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| unix_secs_to_iso8601(d.as_secs()))
        .unwrap_or_else(|_| String::from("unknown"));

    let suite_config = suite_path
        .canonicalize()
        .unwrap_or_else(|_| suite_path.to_path_buf())
        .to_string_lossy()
        .into_owned();

    let cpu_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);

    let argv: Vec<String> = std::env::args().collect();

    json!({
        "created_at": created_at,
        "suite": suite_name,
        "suite_config": suite_config,
        "platform": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "cpu_count": cpu_count,
        "argv": argv,
        "selected_experiments": selected_names,
        "planned_runs": total_runs,
        "executed_runs": runs_executed,
        "runs_failed": runs_failed,
        "failed_cases": failed_cases.iter().map(|case| {
            json!({
                "experiment": case.experiment,
                "label": case.label,
                "error": case.error,
            })
        }).collect::<Vec<_>>(),
        "git": {
            "commit": run_git(&["rev-parse", "HEAD"]),
            "branch": run_git(&["rev-parse", "--abbrev-ref", "HEAD"]),
            "status_short": run_git(&["status", "--short"]),
        },
    })
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn run_suite(suite_path: &Path, node_binary: &Path, opts: SuiteRunOpts) -> Result<(), String> {
    let (suite_name, defaults, raw_experiments) = load_suite(suite_path)?;

    // Expand all experiments
    let expanded: Vec<(ExperimentMeta, Vec<ExperimentCase>)> = raw_experiments
        .iter()
        .map(|e| expand_experiment(e, &defaults))
        .collect::<Result<Vec<_>, _>>()?;

    let meta_map: HashMap<String, usize> = expanded
        .iter()
        .enumerate()
        .map(|(i, (m, _))| (m.name.clone(), i))
        .collect();

    // --list-experiments
    if opts.list_only {
        for (meta, _) in &expanded {
            let line = format!(
                "{}: cases={} runs={}{}",
                meta.name,
                meta.case_count,
                meta.run_count,
                if meta.description.is_empty() {
                    String::new()
                } else {
                    format!(" | {}", meta.description)
                }
            );
            println!("{line}");
        }
        return Ok(());
    }

    // Select experiments
    let selected_indices: Vec<usize> = if let Some(names) = &opts.experiments {
        let mut indices = Vec::new();
        let mut missing = Vec::new();
        for name in names {
            match meta_map.get(name) {
                Some(&i) => indices.push(i),
                None => missing.push(name.clone()),
            }
        }
        if !missing.is_empty() {
            return Err(format!("unknown experiments: {}", missing.join(", ")));
        }
        indices
    } else {
        (0..expanded.len()).collect()
    };

    let selected: Vec<&(ExperimentMeta, Vec<ExperimentCase>)> =
        selected_indices.iter().map(|&i| &expanded[i]).collect();
    let selected_names: Vec<&str> = selected.iter().map(|(m, _)| m.name.as_str()).collect();
    let total_runs: usize = selected.iter().map(|(m, _)| m.run_count).sum();

    validate_suite_node_capabilities(node_binary, &selected)?;

    eprintln!(
        "[suite] name={suite_name} experiments={} planned_runs={total_runs}",
        selected_names.join(",")
    );

    // --dry-run
    if opts.dry_run {
        for (meta, cases) in &selected {
            eprintln!(
                "[experiment] name={} cases={} repeats={}",
                meta.name,
                cases.len(),
                meta.repeats
            );
        }
        return Ok(());
    }

    // Prepare output dir
    let output_dir = opts.output_dir.unwrap_or_else(default_output_dir);
    fs::create_dir_all(&output_dir).map_err(|e| e.to_string())?;

    let mut all_records: Vec<RunRecord> = Vec::new();
    let mut all_raw_results: Vec<Value> = Vec::new(); // parallel to all_records
    let mut runs_executed = 0usize;
    let mut failed_cases: Vec<FailedCase> = Vec::new();

    for (meta, cases) in &selected {
        let exp_dir = output_dir.join(&meta.name);
        let configs_dir = exp_dir.join("configs");
        let raw_dir = exp_dir.join("raw");
        fs::create_dir_all(&configs_dir).map_err(|e| e.to_string())?;
        fs::create_dir_all(&raw_dir).map_err(|e| e.to_string())?;

        'case_loop: for case in cases.iter() {
            for repeat_index in 0..meta.repeats {
                if let Some(max) = opts.max_runs
                    && runs_executed >= max
                {
                    break 'case_loop;
                }

                let label = case_label(case, repeat_index);
                let sid = case_sid(&meta.name, case, repeat_index);

                // Save reproducible flat TOML
                let toml_path = configs_dir.join(format!("{label}.toml"));
                fs::write(&toml_path, render_config_toml(&sid, case)).map_err(|e| e.to_string())?;

                // Build benchmark args and call the unified multiprocess driver directly.
                let config_json = build_config_json(case);
                let bench_args = BenchDriveArgs {
                    sid: sid.clone(),
                    acs_backend: BenchBackendKind::parse(&case.backend)?,
                    nodes: case.nodes,
                    faulty: case.faulty,
                    rounds: case.rounds,
                    batch_size: case.batch_size,
                    global_timeout: case.global_timeout,
                    config_json,
                    ledger_dir: None,
                    tx_json: None,
                };

                let t0 = Instant::now();
                let run_result = run_drive_multiprocess(&bench_args, node_binary);
                let elapsed = t0.elapsed().as_secs_f64();

                let result_json_str = match run_result {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("[suite] experiment={} label={label} FAILED: {e}", meta.name);
                        failed_cases.push(FailedCase {
                            experiment: meta.name.clone(),
                            label: label.clone(),
                            error: e,
                        });
                        continue;
                    }
                };

                let result_val: Value = match serde_json::from_str(&result_json_str) {
                    Ok(v) => v,
                    Err(e) => {
                        let error = format!("json parse: {e}");
                        eprintln!(
                            "[suite] experiment={} label={label} FAILED ({error})",
                            meta.name
                        );
                        failed_cases.push(FailedCase {
                            experiment: meta.name.clone(),
                            label: label.clone(),
                            error,
                        });
                        continue;
                    }
                };

                let record =
                    extract_run_record(&meta.name, case, repeat_index, elapsed, &result_val);

                eprintln!(
                    "[run] experiment={} label={label} tps_wall={:.3} bytes_per_tx={:.2}",
                    meta.name, record.tps_wall, record.tracked_driver_bytes_per_delivered_tx,
                );

                // Save raw JSON
                let raw_path = raw_dir.join(format!("{label}.json"));
                let raw_json = record_to_json(&record, &result_val);
                fs::write(
                    &raw_path,
                    serde_json::to_string_pretty(&raw_json).unwrap_or_default(),
                )
                .map_err(|e| e.to_string())?;

                all_raw_results.push(raw_json);
                all_records.push(record);
                runs_executed += 1;
            }
        }
    }

    // Aggregate
    let summaries = aggregate_records(&all_records);
    let summaries_json: Vec<Value> = summaries.iter().map(summary_to_json).collect();
    let reuse_deltas = build_reuse_deltas(&summaries);
    let backend_deltas = build_backend_deltas(&summaries);

    // Write CSV outputs
    write_csv(&output_dir.join("summaries.csv"), &summaries_json)?;
    write_csv(&output_dir.join("reuse_deltas.csv"), &reuse_deltas)?;
    write_csv(&output_dir.join("backend_deltas.csv"), &backend_deltas)?;

    // Write combined JSON
    let payload = json!({
        "suite": suite_name,
        "records": all_raw_results,
        "summaries": summaries_json,
        "reuse_deltas": reuse_deltas,
        "backend_deltas": backend_deltas,
    });
    fs::write(
        output_dir.join("dumbo_paper_suite.json"),
        serde_json::to_string_pretty(&payload).unwrap_or_default(),
    )
    .map_err(|e| e.to_string())?;

    // Write manifest.json
    let manifest = build_manifest(
        suite_path,
        &suite_name,
        &selected_names,
        total_runs,
        runs_executed,
        failed_cases.len(),
        &failed_cases,
    );
    fs::write(
        output_dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap_or_default(),
    )
    .map_err(|e| e.to_string())?;

    eprintln!(
        "[done] runs_ok={} runs_failed={} output_dir={}",
        runs_executed,
        failed_cases.len(),
        output_dir.display()
    );
    if !failed_cases.is_empty() {
        eprintln!("[suite] failed cases ({}):", failed_cases.len());
        for case in &failed_cases {
            eprintln!("  - {}: {}", case.label, case.error);
        }
        return Err(format!(
            "{} case(s) failed; partial results written to {}",
            failed_cases.len(),
            output_dir.display()
        ));
    }
    Ok(())
}
