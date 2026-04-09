use honey_crypto::hb::{
    BatchDecryptor as HbBatchDecryptor, HbPkePrivateKeyShare, HbPkePublicParams,
    decode_pke_private_share, decode_pke_public_params, decode_tx_batch as decode_hb_tx_batch,
    encode_json_string as encode_hb_json_string, encode_tx_batch as encode_hb_tx_batch,
    merge_tx_batches_bytes as merge_hb_tx_batches_bytes,
    seal_encrypted_batch as seal_hb_encrypted_batch,
};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use pyo3::types::{PyList, PyModule};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs::{self, File};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod cli;
mod drive_acs;
mod drive_dumbo;
mod drive_hb;
mod network_driver;
mod pool_reuse;
mod py_host;
mod runner;

// Re-export types that live in submodules but must be visible across all drivers
// via the `use super::*;` pattern used in the submodule files.
pub(crate) use py_host::{AcsRoundOutcome, PyAcsHost, PyAcsHostStats, PyAcsWireEvent};
pub(crate) use runner::SpawnedNode;

#[derive(Clone, Copy)]
enum Protocol {
    HoneyBadger,
    Dumbo,
}

impl Protocol {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "hb" | "honeybadger" => Ok(Self::HoneyBadger),
            "dumbo" => Ok(Self::Dumbo),
            _ => Err(format!("unsupported protocol: {value}")),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::HoneyBadger => "hb",
            Self::Dumbo => "dumbo",
        }
    }
}

enum CliCommand {
    RunDriverNode(RunDriverNodeArgs),
    BenchDriver(BenchDriverArgs),
}

#[derive(Clone, Copy)]
enum BenchDriverMode {
    Benchmark,
    Acs,
    HoneyBadger,
    Dumbo,
}

impl BenchDriverMode {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "benchmark" => Ok(Self::Benchmark),
            "acs" => Ok(Self::Acs),
            "hb" | "honeybadger" => Ok(Self::HoneyBadger),
            "dumbo" => Ok(Self::Dumbo),
            _ => Err(format!("unsupported bench-driver mode: {value}")),
        }
    }
}

struct RunDriverNodeArgs {
    pid: usize,
    sid: String,
    acs_protocol: Protocol,
    nodes: usize,
    faulty: usize,
    rounds: usize,
    batch_size: usize,
    global_timeout: f64,
    addresses_json: String,
    hb_crypto_json: String,
    acs_crypto_json: String,
    config_json: String,
    start_at_ms: Option<u64>,
    result_path: Option<String>,
}

struct BenchDriverArgs {
    mode: BenchDriverMode,
    sid: String,
    protocol: Protocol,
    acs_protocol: Protocol,
    nodes: usize,
    faulty: usize,
    rounds: usize,
    batch_size: usize,
    global_timeout: f64,
    config_json: String,
    result_path: Option<String>,
    ledger_dir: Option<String>,
    tx_json: Option<String>,
}

struct BenchAcsArgs {
    protocol: Protocol,
    sid: String,
    nodes: usize,
    faulty: usize,
    rounds: usize,
    global_timeout: f64,
    config_json: String,
    result_path: Option<String>,
}

struct BenchHoneyBadgerArgs {
    sid: String,
    acs_protocol: Protocol,
    nodes: usize,
    faulty: usize,
    rounds: usize,
    batch_size: usize,
    global_timeout: f64,
    config_json: String,
    result_path: Option<String>,
}

struct BenchDumboArgs {
    sid: String,
    nodes: usize,
    faulty: usize,
    rounds: usize,
    batch_size: usize,
    global_timeout: f64,
    config_json: String,
    result_path: Option<String>,
    /// Directory to write per-round ledger block files (optional).
    ledger_dir: Option<String>,
    /// JSON-encoded per-node transaction lists: `[[tx, ...], ...]`.
    /// Index 0 = node 0's transactions, consumed `batch_size` per round.
    /// If absent, deterministic dummy transactions are generated.
    tx_json: Option<String>,
}

const GENESIS_CHAIN_DIGEST: [u8; 32] = [0; 32];
const ACS_IDLE_BACKOFF: Duration = Duration::from_micros(50);
const ACS_PULL_BATCH_LIMIT: usize = 512;

#[derive(Clone, Default)]
struct DriverHostPhaseStats {
    pid: usize,
    push_calls: usize,
    push_items: usize,
    max_push_batch: usize,
    push_seconds: f64,
    pull_calls: usize,
    empty_pull_calls: usize,
    pulled_events: usize,
    max_pull_batch: usize,
    pull_limit_hits: usize,
    pull_seconds: f64,
}

#[derive(Clone, Default)]
struct DriverPhaseStats {
    sweep_count: usize,
    active_sweeps: usize,
    idle_sweeps: usize,
    idle_backoff_count: usize,
    total_pending_deliveries: usize,
    max_pending_deliveries: usize,
    total_pushed_items: usize,
    total_pulled_events: usize,
    max_pull_batch: usize,
    pull_limit_hits: usize,
    total_push_seconds: f64,
    total_pull_seconds: f64,
    send_events: usize,
    send_payload_bytes: usize,
    decision_events: usize,
    failure_events: usize,
    carryover_events: usize,
    broadcast_output_events: usize,
    broadcast_output_payload_bytes: usize,
    broadcast_output_roothash_bytes: usize,
    host_stats: Vec<DriverHostPhaseStats>,
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let command = cli::parse_cli(std::env::args())?;
    match command {
        CliCommand::RunDriverNode(args) => {
            network_driver::run_rust_driver_node(args).map_err(Into::into)
        }
        CliCommand::BenchDriver(args) => run_bench_driver(args).map_err(Into::into),
    }
}

fn run_bench_driver(args: BenchDriverArgs) -> Result<(), String> {
    match args.mode {
        BenchDriverMode::Benchmark => network_driver::run_bench_rust_driver(args),
        BenchDriverMode::Acs => drive_acs::run_drive_acs(BenchAcsArgs {
            protocol: args.protocol,
            sid: args.sid,
            nodes: args.nodes,
            faulty: args.faulty,
            rounds: args.rounds,
            global_timeout: args.global_timeout,
            config_json: args.config_json,
            result_path: args.result_path,
        }),
        BenchDriverMode::HoneyBadger => drive_hb::run_drive_honeybadger(BenchHoneyBadgerArgs {
            sid: args.sid,
            acs_protocol: args.acs_protocol,
            nodes: args.nodes,
            faulty: args.faulty,
            rounds: args.rounds,
            batch_size: args.batch_size,
            global_timeout: args.global_timeout,
            config_json: args.config_json,
            result_path: args.result_path,
        }),
        BenchDriverMode::Dumbo => drive_dumbo::run_drive_dumbo(BenchDumboArgs {
            sid: args.sid,
            nodes: args.nodes,
            faulty: args.faulty,
            rounds: args.rounds,
            batch_size: args.batch_size,
            global_timeout: args.global_timeout,
            config_json: args.config_json,
            result_path: args.result_path,
            ledger_dir: args.ledger_dir,
            tx_json: args.tx_json,
        }),
    }
}

fn take_value<I>(argv: &mut I, flag: &str) -> Result<String, String>
where
    I: Iterator<Item = String>,
{
    argv.next()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn parse_usize_flag<I>(argv: &mut I, flag: &str) -> Result<usize, String>
where
    I: Iterator<Item = String>,
{
    let value = take_value(argv, flag)?;
    value
        .parse::<usize>()
        .map_err(|_| format!("invalid {flag} value: {value}"))
}

fn parse_u64_flag<I>(argv: &mut I, flag: &str) -> Result<u64, String>
where
    I: Iterator<Item = String>,
{
    let value = take_value(argv, flag)?;
    value
        .parse::<u64>()
        .map_err(|_| format!("invalid {flag} value: {value}"))
}

fn parse_f64_flag<I>(argv: &mut I, flag: &str) -> Result<f64, String>
where
    I: Iterator<Item = String>,
{
    let value = take_value(argv, flag)?;
    value
        .parse::<f64>()
        .map_err(|_| format!("invalid {flag} value: {value}"))
}

fn prepend_python_paths(py: Python<'_>) -> PyResult<()> {
    let sys = PyModule::import(py, "sys")?;
    let path = sys.getattr("path")?.cast_into::<PyList>()?;
    path.insert(0, "packages/honey-acs/src")?;
    for candidate in venv_site_packages_candidates() {
        path.insert(0, candidate)?;
    }
    path.insert(0, ".")?;
    path.insert(0, "src")?;
    Ok(())
}

fn hex_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(format!("invalid hex digit: {}", value as char)),
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err(format!(
            "hex payload must have even length, got {}",
            value.len()
        ));
    }

    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0usize;
    while index < bytes.len() {
        let high = hex_nibble(bytes[index])?;
        let low = hex_nibble(bytes[index + 1])?;
        decoded.push((high << 4) | low);
        index += 2;
    }
    Ok(decoded)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut value, "{byte:02x}");
    }
    value
}

fn sha256_hex(payload: &[u8]) -> String {
    hex_encode(&Sha256::digest(payload))
}

fn compute_chain_digest(prev_digest: &[u8], round_id: usize, block_payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prev_digest);
    hasher.update((round_id as u64).to_be_bytes());
    hasher.update(block_payload);
    hasher.finalize().into()
}

fn json_string_field<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string field: {key}"))
}

fn parse_honeybadger_crypto_payload(
    payload: &str,
) -> Result<(HbPkePublicParams, HbPkePrivateKeyShare), String> {
    let decoded = serde_json::from_str::<Value>(payload).map_err(|err| err.to_string())?;
    let public_key = decode_hex(json_string_field(&decoded, "enc_pk")?)?;
    let private_share = decode_hex(json_string_field(&decoded, "enc_sk")?)?;
    Ok((
        decode_pke_public_params(&public_key)?,
        decode_pke_private_share(&private_share)?,
    ))
}

fn debug_acs_driver(message: &str) {
    if std::env::var_os("HONEY_DEBUG_ACS").is_some() {
        eprintln!("[bench-driver:acs] {message}");
    }
}

fn serialize_crypto_payloads(
    protocol: Protocol,
    nodes: usize,
    faulty: usize,
) -> Result<Vec<String>, String> {
    Python::attach(|py| -> PyResult<Vec<String>> {
        prepend_python_paths(py)?;
        let materials = PyModule::import(py, "honey_acs.host_crypto")?;
        let function_name = match protocol {
            Protocol::HoneyBadger => "serialize_hb_crypto_payloads_json",
            Protocol::Dumbo => "serialize_dumbo_crypto_payloads_json",
        };
        materials
            .getattr(function_name)?
            .call1((nodes, faulty))?
            .extract::<Vec<String>>()
    })
    .map_err(|err| err.to_string())
}

fn allocate_loopback_addresses(num_nodes: usize) -> Result<Vec<(String, u16)>, String> {
    let mut listeners = Vec::with_capacity(num_nodes);
    for _ in 0..num_nodes {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|err| err.to_string())?;
        listeners.push(listener);
    }
    let addresses = listeners
        .iter()
        .map(|listener| {
            listener
                .local_addr()
                .map(|addr| (String::from("127.0.0.1"), addr.port()))
                .map_err(|err| err.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(addresses)
}

fn build_result_dir(prefix: &str, sid: &str) -> Result<PathBuf, String> {
    let scratch_root = PathBuf::from(".tmp_multiprocess_results");
    fs::create_dir_all(&scratch_root).map_err(|err| err.to_string())?;
    let safe_sid: String = sid
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .take(48)
        .collect();
    let safe_sid = safe_sid.trim_matches('-');
    let safe_sid = if safe_sid.is_empty() { "sid" } else { safe_sid };
    let dir_name = format!(
        "{prefix}-{safe_sid}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| err.to_string())?
            .as_nanos()
    );
    let result_dir = scratch_root.join(dir_name);
    fs::create_dir_all(&result_dir).map_err(|err| err.to_string())?;
    Ok(result_dir)
}

fn current_time_millis() -> Result<u64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| err.to_string())?;
    u64::try_from(duration.as_millis()).map_err(|_| String::from("current time overflow"))
}

fn read_log_file(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|_| String::from("unable to read worker stderr"))
}

fn write_output(result_path: Option<&str>, rendered: &str) -> Result<(), String> {
    if let Some(result_path) = result_path {
        fs::write(result_path, rendered).map_err(|err| err.to_string())?;
    } else {
        println!("{rendered}");
    }
    Ok(())
}

fn venv_site_packages_candidates() -> Vec<String> {
    let mut candidates = Vec::new();
    if let Ok(root) = std::env::current_dir() {
        let mut direct = PathBuf::from(&root);
        direct.push(".venv");
        direct.push("lib");
        direct.push("python3.14");
        direct.push("site-packages");
        if direct.exists() {
            candidates.push(direct.to_string_lossy().into_owned());
        }
    }
    candidates
}
