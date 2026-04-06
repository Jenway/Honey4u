use honey_native::hb::{
    BatchDecryptor as HbBatchDecryptor, HbPkePrivateKeyShare, HbPkePublicParams,
    decode_pke_private_share, decode_pke_public_params, decode_tx_batch as decode_hb_tx_batch,
    encode_json_string as encode_hb_json_string, encode_tx_batch as encode_hb_tx_batch,
    merge_tx_batches_bytes as merge_hb_tx_batches_bytes,
    seal_encrypted_batch as seal_hb_encrypted_batch,
};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use pyo3::types::{PyList, PyModule};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod bench_local;
mod cli;
mod drive_acs;
mod drive_hb;
mod hb_worker;
mod py_host;

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

impl HbWorkerIpcMode {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "json" => Ok(Self::Json),
            "binary" => Ok(Self::Binary),
            _ => Err(format!("unsupported hb-worker ipc mode: {value}")),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Binary => "binary",
        }
    }
}

enum CliCommand {
    RunNode(RunNodeArgs),
    BenchLocal(BenchLocalArgs),
    DriveAcs(DriveAcsArgs),
    DriveHoneyBadger(DriveHoneyBadgerArgs),
    HbWorker(HbWorkerArgs),
}

struct RunNodeArgs {
    protocol: Protocol,
    pid: usize,
    nodes: usize,
    faulty: usize,
    sid: String,
    addresses_json: String,
    crypto_json: String,
    config_json: String,
    transactions_per_node: usize,
    tx_input: String,
    start_at_ms: Option<u64>,
    result_path: Option<String>,
}

struct BenchLocalArgs {
    protocol: Protocol,
    sid: String,
    nodes: usize,
    faulty: usize,
    rounds: usize,
    batch_size: usize,
    round_timeout: f64,
    global_timeout: f64,
    transactions_per_node: usize,
    tx_input: String,
    transport_backend: String,
    log_level: String,
    config_json: String,
    result_path: Option<String>,
}

struct DriveAcsArgs {
    protocol: Protocol,
    sid: String,
    nodes: usize,
    faulty: usize,
    rounds: usize,
    global_timeout: f64,
    config_json: String,
    result_path: Option<String>,
}

struct DriveHoneyBadgerArgs {
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

struct HbWorkerArgs {
    pid: usize,
    nodes: usize,
    faulty: usize,
    acs_protocol: Protocol,
    acs_crypto_json: String,
    hb_crypto_json: String,
    config_json: String,
    ipc_mode: HbWorkerIpcMode,
}

struct SpawnedNode {
    pid: usize,
    child: std::process::Child,
    result_path: PathBuf,
    stderr_path: PathBuf,
}

struct PyAcsHost {
    pid: usize,
    inner: Py<PyAny>,
}

struct HbNodeRuntime {
    acs_host: PyAcsHost,
    tpke_private_share: HbPkePrivateKeyShare,
}

struct HbWorkerProcess {
    pid: usize,
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
}

struct HbWorkerSpawnArgs<'a> {
    binary_path: &'a Path,
    pid: usize,
    nodes: usize,
    faulty: usize,
    acs_protocol: Protocol,
    acs_crypto_json: &'a str,
    hb_crypto_json: &'a str,
    config_json: &'a str,
}

#[derive(Clone, Copy)]
enum HbWorkerIpcMode {
    Json,
    Binary,
}

struct PyAcsHostStats {
    worker_ident: u64,
    rounds_started: usize,
    rounds_finished: usize,
    processed_commands: usize,
    bridge_queue_size: usize,
    worker_running: bool,
    worker_error: Option<String>,
}

enum PyAcsEvent {
    Send {
        round_id: usize,
        recipient: usize,
        channel: String,
        instance_id: Option<usize>,
        message: Py<PyAny>,
    },
    Decision {
        round_id: usize,
        values: Vec<Option<Vec<u8>>>,
    },
    Failure {
        round_id: isize,
        error: String,
        exception_type: String,
    },
    Carryovers {
        round_id: usize,
    },
}

enum HbWorkerEvent {
    Send {
        round_id: usize,
        recipient: usize,
        payload: Vec<u8>,
    },
    Decision {
        round_id: usize,
        values: Vec<Option<Vec<u8>>>,
    },
    Failure {
        round_id: isize,
        error: String,
        exception_type: String,
    },
    Carryovers {
        round_id: usize,
    },
}

#[derive(Serialize, Deserialize)]
enum HbWorkerRequest {
    Stats,
    StartRound {
        round_id: usize,
        sid: String,
        local_input: Vec<u8>,
    },
    DeliverBatch {
        payloads: Vec<Vec<u8>>,
    },
    DrainEvents {
        limit: usize,
    },
    TpkeLocalBundle {
        selected_batches: Vec<Vec<u8>>,
    },
    Shutdown,
}

#[derive(Serialize, Deserialize)]
struct HbWorkerStatsPayload {
    pid: usize,
    worker_ident: u64,
    rounds_started: usize,
    rounds_finished: usize,
    processed_commands: usize,
    bridge_queue_size: usize,
    worker_running: bool,
    worker_error: Option<String>,
}

#[derive(Serialize, Deserialize)]
enum HbWorkerEventPayload {
    Send {
        round_id: usize,
        recipient: usize,
        payload: Vec<u8>,
    },
    Decision {
        round_id: usize,
        values: Vec<Option<Vec<u8>>>,
    },
    Failure {
        round_id: isize,
        error: String,
        exception_type: String,
    },
    Carryovers {
        round_id: usize,
    },
}

#[derive(Serialize, Deserialize)]
enum HbWorkerResponse {
    Ack,
    Stats(HbWorkerStatsPayload),
    Events(Vec<HbWorkerEventPayload>),
    TpkeLocalBundle {
        bundle: HbShareBundle,
        elapsed_seconds: f64,
    },
}

struct AcsRoundOutcome {
    canonical: Vec<Option<Vec<u8>>>,
    send_events: usize,
}

struct HbBlockOutcome {
    block_payload: Vec<u8>,
    tpke_bundle_events: usize,
    local_share_seconds: f64,
    combine_seconds: f64,
}

type HbShareBundle = Vec<Option<Vec<u8>>>;

const GENESIS_CHAIN_DIGEST: [u8; 32] = [0; 32];
const ACS_IDLE_BACKOFF: Duration = Duration::from_micros(50);
const ACS_EVENT_DRAIN_LIMIT: usize = 4096;

fn write_bincode_frame<W, T>(writer: &mut W, value: &T) -> Result<(), String>
where
    W: Write,
    T: Serialize,
{
    let payload = bincode::serialize(value).map_err(|err| err.to_string())?;
    let len = u32::try_from(payload.len()).map_err(|_| String::from("IPC frame too large"))?;
    writer
        .write_all(&len.to_le_bytes())
        .and_then(|_| writer.write_all(&payload))
        .and_then(|_| writer.flush())
        .map_err(|err| err.to_string())
}

fn read_bincode_frame<R, T>(reader: &mut R) -> Result<Option<T>, String>
where
    R: Read,
    T: for<'de> Deserialize<'de>,
{
    let mut len_bytes = [0u8; 4];
    match reader.read_exact(&mut len_bytes) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err.to_string()),
    }

    let len = u32::from_le_bytes(len_bytes) as usize;
    let mut payload = vec![0u8; len];
    reader
        .read_exact(&mut payload)
        .map_err(|err| err.to_string())?;
    let value = bincode::deserialize(&payload).map_err(|err| err.to_string())?;
    Ok(Some(value))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let command = cli::parse_cli(std::env::args())?;
    match command {
        CliCommand::RunNode(args) => bench_local::run_rust_hosted_node(args).map_err(Into::into),
        CliCommand::BenchLocal(args) => bench_local::run_bench_local(args).map_err(Into::into),
        CliCommand::DriveAcs(args) => drive_acs::run_drive_acs(args).map_err(Into::into),
        CliCommand::DriveHoneyBadger(args) => {
            drive_hb::run_drive_honeybadger(args).map_err(Into::into)
        }
        CliCommand::HbWorker(args) => hb_worker::run_hb_worker(args).map_err(Into::into),
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
    for candidate in venv_site_packages_candidates() {
        path.insert(0, candidate)?;
    }
    path.insert(0, ".")?;
    path.insert(0, "src")?;
    Ok(())
}

fn dict_item<'py>(dict: &Bound<'py, PyDict>, key: &str) -> PyResult<Bound<'py, PyAny>> {
    dict.get_item(key)?
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err(format!("missing key: {key}")))
}

fn parse_acs_event(dict: Bound<'_, PyDict>) -> PyResult<PyAcsEvent> {
    let kind = dict_item(&dict, "kind")?.extract::<String>()?;
    match kind.as_str() {
        "send" => Ok(PyAcsEvent::Send {
            round_id: dict_item(&dict, "round_id")?.extract()?,
            recipient: dict_item(&dict, "recipient")?.extract()?,
            channel: dict_item(&dict, "channel")?.extract()?,
            instance_id: dict_item(&dict, "instance_id")?.extract()?,
            message: dict_item(&dict, "message")?.unbind(),
        }),
        "decision" => {
            let values = dict_item(&dict, "values")?;
            let parsed = values
                .try_iter()?
                .map(|item| {
                    let value = item?;
                    if value.is_none() {
                        Ok(None)
                    } else {
                        value.extract::<Vec<u8>>().map(Some)
                    }
                })
                .collect::<PyResult<Vec<_>>>()?;
            Ok(PyAcsEvent::Decision {
                round_id: dict_item(&dict, "round_id")?.extract()?,
                values: parsed,
            })
        }
        "failure" => Ok(PyAcsEvent::Failure {
            round_id: dict_item(&dict, "round_id")?.extract()?,
            error: dict_item(&dict, "error")?.extract()?,
            exception_type: dict_item(&dict, "exception_type")?.extract()?,
        }),
        "carryovers" => Ok(PyAcsEvent::Carryovers {
            round_id: dict_item(&dict, "round_id")?.extract()?,
        }),
        _ => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "unknown ACS event kind: {kind}"
        ))),
    }
}

fn stats_payload_from_stats(pid: usize, stats: PyAcsHostStats) -> HbWorkerStatsPayload {
    HbWorkerStatsPayload {
        pid,
        worker_ident: stats.worker_ident,
        rounds_started: stats.rounds_started,
        rounds_finished: stats.rounds_finished,
        processed_commands: stats.processed_commands,
        bridge_queue_size: stats.bridge_queue_size,
        worker_running: stats.worker_running,
        worker_error: stats.worker_error,
    }
}

fn stats_from_payload(payload: HbWorkerStatsPayload) -> PyAcsHostStats {
    PyAcsHostStats {
        worker_ident: payload.worker_ident,
        rounds_started: payload.rounds_started,
        rounds_finished: payload.rounds_finished,
        processed_commands: payload.processed_commands,
        bridge_queue_size: payload.bridge_queue_size,
        worker_running: payload.worker_running,
        worker_error: payload.worker_error,
    }
}

fn worker_event_from_payload(payload: HbWorkerEventPayload) -> HbWorkerEvent {
    match payload {
        HbWorkerEventPayload::Send {
            round_id,
            recipient,
            payload,
        } => HbWorkerEvent::Send {
            round_id,
            recipient,
            payload,
        },
        HbWorkerEventPayload::Decision { round_id, values } => {
            HbWorkerEvent::Decision { round_id, values }
        }
        HbWorkerEventPayload::Failure {
            round_id,
            error,
            exception_type,
        } => HbWorkerEvent::Failure {
            round_id,
            error,
            exception_type,
        },
        HbWorkerEventPayload::Carryovers { round_id } => HbWorkerEvent::Carryovers { round_id },
    }
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

fn json_usize_field(value: &Value, key: &str) -> Result<usize, String> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .map(|value| value as usize)
        .ok_or_else(|| format!("missing usize field: {key}"))
}

fn json_string_list_field(value: &Value, key: &str) -> Result<Vec<String>, String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing list field: {key}"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(String::from)
                .ok_or_else(|| format!("non-string item in field: {key}"))
        })
        .collect()
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

fn encode_protocol_envelope(
    sender: usize,
    round_id: usize,
    channel: &str,
    instance_id: Option<usize>,
    message: &Py<PyAny>,
) -> Result<Vec<u8>, String> {
    Python::attach(|py| -> PyResult<Vec<u8>> {
        prepend_python_paths(py)?;
        let module = PyModule::import(py, "honey.protocol.messages")?;
        let channel_enum = module.getattr("Channel")?.getattr(channel)?;
        let envelope = module.getattr("ProtocolEnvelope")?.call1((
            round_id,
            channel_enum,
            instance_id,
            message.bind(py),
        ))?;
        envelope.call_method1("to_bytes", (sender,))?.extract()
    })
    .map_err(|err| err.to_string())
}

fn debug_drive_acs(message: &str) {
    if std::env::var_os("HONEY_DEBUG_ACS").is_some() {
        eprintln!("[drive-acs] {message}");
    }
}

fn serialize_crypto_payloads(
    protocol: Protocol,
    nodes: usize,
    faulty: usize,
) -> Result<Vec<String>, String> {
    Python::attach(|py| -> PyResult<Vec<String>> {
        prepend_python_paths(py)?;
        let materials = PyModule::import(py, "honey.host.crypto_material")?;
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
