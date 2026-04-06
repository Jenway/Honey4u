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
    let command = parse_cli(std::env::args())?;
    match command {
        CliCommand::RunNode(args) => run_rust_hosted_node(args).map_err(Into::into),
        CliCommand::BenchLocal(args) => run_bench_local(args).map_err(Into::into),
        CliCommand::DriveAcs(args) => run_drive_acs(args).map_err(Into::into),
        CliCommand::DriveHoneyBadger(args) => run_drive_honeybadger(args).map_err(Into::into),
        CliCommand::HbWorker(args) => run_hb_worker(args).map_err(Into::into),
    }
}

fn parse_cli<I>(mut argv: I) -> Result<CliCommand, String>
where
    I: Iterator<Item = String>,
{
    let _bin = argv.next();
    let Some(command) = argv.next() else {
        return Err(String::from("missing command"));
    };

    match command.as_str() {
        "run-node" => parse_run_node_args(argv).map(CliCommand::RunNode),
        "bench-local" => parse_bench_local_args(argv).map(CliCommand::BenchLocal),
        "drive-acs" => parse_drive_acs_args(argv).map(CliCommand::DriveAcs),
        "drive-hb" => parse_drive_honeybadger_args(argv).map(CliCommand::DriveHoneyBadger),
        "hb-worker" => parse_hb_worker_args(argv).map(CliCommand::HbWorker),
        _ if command.starts_with("--") => {
            let mut forwarded = vec![command];
            forwarded.extend(argv);
            parse_run_node_args(forwarded.into_iter()).map(CliCommand::RunNode)
        }
        _ => Err(format!("unknown command: {command}")),
    }
}

fn parse_run_node_args<I>(mut argv: I) -> Result<RunNodeArgs, String>
where
    I: Iterator<Item = String>,
{
    let mut protocol = Protocol::HoneyBadger;
    let mut pid = 0usize;
    let mut nodes = 4usize;
    let mut faulty = 1usize;
    let mut rounds = 1usize;
    let mut sid = String::from("local:hb");
    let mut addresses_json: Option<String> = None;
    let mut crypto_json: Option<String> = None;
    let mut config_json: Option<String> = None;
    let mut transactions_per_node = 1usize;
    let mut tx_input = String::from("json_str");
    let mut start_at_ms: Option<u64> = None;
    let mut result_path: Option<String> = None;

    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "--protocol" => {
                protocol = Protocol::parse(&take_value(&mut argv, "--protocol")?)?;
            }
            "--pid" => {
                pid = parse_usize_flag(&mut argv, "--pid")?;
            }
            "--nodes" => {
                nodes = parse_usize_flag(&mut argv, "--nodes")?;
            }
            "--faulty" => {
                faulty = parse_usize_flag(&mut argv, "--faulty")?;
            }
            "--rounds" => {
                rounds = parse_usize_flag(&mut argv, "--rounds")?;
            }
            "--sid" => {
                sid = take_value(&mut argv, "--sid")?;
            }
            "--addresses-json" => {
                addresses_json = Some(take_value(&mut argv, "--addresses-json")?);
            }
            "--crypto-json" => {
                crypto_json = Some(take_value(&mut argv, "--crypto-json")?);
            }
            "--config-json" => {
                config_json = Some(take_value(&mut argv, "--config-json")?);
            }
            "--transactions-per-node" => {
                transactions_per_node = parse_usize_flag(&mut argv, "--transactions-per-node")?;
            }
            "--tx-input" => {
                tx_input = take_value(&mut argv, "--tx-input")?;
            }
            "--start-at-ms" => {
                start_at_ms = Some(parse_u64_flag(&mut argv, "--start-at-ms")?);
            }
            "--result-path" => {
                result_path = Some(take_value(&mut argv, "--result-path")?);
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }

    if nodes == 0 {
        return Err(String::from("--nodes must be > 0"));
    }
    if pid >= nodes {
        return Err(format!("--pid {pid} must be < --nodes {nodes}"));
    }
    if rounds == 0 {
        return Err(String::from("--rounds must be > 0"));
    }

    Ok(RunNodeArgs {
        protocol,
        pid,
        nodes,
        faulty,
        sid,
        addresses_json: addresses_json
            .ok_or_else(|| String::from("--addresses-json is required"))?,
        crypto_json: crypto_json.ok_or_else(|| String::from("--crypto-json is required"))?,
        config_json: config_json.ok_or_else(|| String::from("--config-json is required"))?,
        transactions_per_node,
        tx_input,
        start_at_ms,
        result_path,
    })
}

fn parse_bench_local_args<I>(mut argv: I) -> Result<BenchLocalArgs, String>
where
    I: Iterator<Item = String>,
{
    let mut protocol = Protocol::HoneyBadger;
    let mut sid = String::from("bench:local:hb");
    let mut nodes = 4usize;
    let mut faulty = 1usize;
    let mut rounds = 1usize;
    let mut batch_size = 1usize;
    let mut round_timeout = 10.0f64;
    let mut global_timeout = 30.0f64;
    let mut transactions_per_node = 1usize;
    let mut tx_input = String::from("json_str");
    let mut transport_backend = String::from("tcp");
    let mut log_level = String::from("WARNING");
    let mut config_json: Option<String> = None;
    let mut result_path: Option<String> = None;

    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "--protocol" => {
                protocol = Protocol::parse(&take_value(&mut argv, "--protocol")?)?;
            }
            "--sid" => {
                sid = take_value(&mut argv, "--sid")?;
            }
            "--nodes" => {
                nodes = parse_usize_flag(&mut argv, "--nodes")?;
            }
            "--faulty" => {
                faulty = parse_usize_flag(&mut argv, "--faulty")?;
            }
            "--rounds" => {
                rounds = parse_usize_flag(&mut argv, "--rounds")?;
            }
            "--batch-size" => {
                batch_size = parse_usize_flag(&mut argv, "--batch-size")?;
            }
            "--round-timeout" => {
                round_timeout = parse_f64_flag(&mut argv, "--round-timeout")?;
            }
            "--global-timeout" => {
                global_timeout = parse_f64_flag(&mut argv, "--global-timeout")?;
            }
            "--transactions-per-node" => {
                transactions_per_node = parse_usize_flag(&mut argv, "--transactions-per-node")?;
            }
            "--tx-input" => {
                tx_input = take_value(&mut argv, "--tx-input")?;
            }
            "--transport-backend" => {
                transport_backend = take_value(&mut argv, "--transport-backend")?;
            }
            "--log-level" => {
                log_level = take_value(&mut argv, "--log-level")?;
            }
            "--config-json" => {
                config_json = Some(take_value(&mut argv, "--config-json")?);
            }
            "--result-path" => {
                result_path = Some(take_value(&mut argv, "--result-path")?);
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }

    if nodes == 0 {
        return Err(String::from("--nodes must be > 0"));
    }
    if rounds == 0 {
        return Err(String::from("--rounds must be > 0"));
    }
    if batch_size == 0 {
        return Err(String::from("--batch-size must be > 0"));
    }
    if global_timeout <= 0.0 {
        return Err(String::from("--global-timeout must be > 0"));
    }

    Ok(BenchLocalArgs {
        protocol,
        sid,
        nodes,
        faulty,
        rounds,
        batch_size,
        round_timeout,
        global_timeout,
        transactions_per_node,
        tx_input,
        transport_backend,
        log_level,
        config_json: config_json.ok_or_else(|| String::from("--config-json is required"))?,
        result_path,
    })
}

fn parse_drive_acs_args<I>(mut argv: I) -> Result<DriveAcsArgs, String>
where
    I: Iterator<Item = String>,
{
    let mut protocol = Protocol::HoneyBadger;
    let mut sid = String::from("drive:acs");
    let mut nodes = 4usize;
    let mut faulty = 1usize;
    let mut rounds = 1usize;
    let mut global_timeout = 30.0f64;
    let mut config_json = String::from("{}");
    let mut result_path: Option<String> = None;

    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "--protocol" => {
                protocol = Protocol::parse(&take_value(&mut argv, "--protocol")?)?;
            }
            "--sid" => {
                sid = take_value(&mut argv, "--sid")?;
            }
            "--nodes" => {
                nodes = parse_usize_flag(&mut argv, "--nodes")?;
            }
            "--faulty" => {
                faulty = parse_usize_flag(&mut argv, "--faulty")?;
            }
            "--rounds" => {
                rounds = parse_usize_flag(&mut argv, "--rounds")?;
            }
            "--global-timeout" => {
                global_timeout = parse_f64_flag(&mut argv, "--global-timeout")?;
            }
            "--config-json" => {
                config_json = take_value(&mut argv, "--config-json")?;
            }
            "--result-path" => {
                result_path = Some(take_value(&mut argv, "--result-path")?);
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }

    if nodes == 0 {
        return Err(String::from("--nodes must be > 0"));
    }
    if rounds == 0 {
        return Err(String::from("--rounds must be > 0"));
    }
    if global_timeout <= 0.0 {
        return Err(String::from("--global-timeout must be > 0"));
    }

    Ok(DriveAcsArgs {
        protocol,
        sid,
        nodes,
        faulty,
        rounds,
        global_timeout,
        config_json,
        result_path,
    })
}

fn parse_drive_honeybadger_args<I>(mut argv: I) -> Result<DriveHoneyBadgerArgs, String>
where
    I: Iterator<Item = String>,
{
    let mut sid = String::from("drive:hb");
    let mut acs_protocol = Protocol::HoneyBadger;
    let mut nodes = 4usize;
    let mut faulty = 1usize;
    let mut rounds = 1usize;
    let mut batch_size = 1usize;
    let mut global_timeout = 30.0f64;
    let mut config_json = String::from("{}");
    let mut result_path: Option<String> = None;

    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "--sid" => {
                sid = take_value(&mut argv, "--sid")?;
            }
            "--acs-protocol" => {
                acs_protocol = Protocol::parse(&take_value(&mut argv, "--acs-protocol")?)?;
            }
            "--nodes" => {
                nodes = parse_usize_flag(&mut argv, "--nodes")?;
            }
            "--faulty" => {
                faulty = parse_usize_flag(&mut argv, "--faulty")?;
            }
            "--rounds" => {
                rounds = parse_usize_flag(&mut argv, "--rounds")?;
            }
            "--batch-size" => {
                batch_size = parse_usize_flag(&mut argv, "--batch-size")?;
            }
            "--global-timeout" => {
                global_timeout = parse_f64_flag(&mut argv, "--global-timeout")?;
            }
            "--config-json" => {
                config_json = take_value(&mut argv, "--config-json")?;
            }
            "--result-path" => {
                result_path = Some(take_value(&mut argv, "--result-path")?);
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }

    if nodes == 0 {
        return Err(String::from("--nodes must be > 0"));
    }
    if rounds == 0 {
        return Err(String::from("--rounds must be > 0"));
    }
    if batch_size == 0 {
        return Err(String::from("--batch-size must be > 0"));
    }
    if global_timeout <= 0.0 {
        return Err(String::from("--global-timeout must be > 0"));
    }

    Ok(DriveHoneyBadgerArgs {
        sid,
        acs_protocol,
        nodes,
        faulty,
        rounds,
        batch_size,
        global_timeout,
        config_json,
        result_path,
    })
}

fn parse_hb_worker_args<I>(mut argv: I) -> Result<HbWorkerArgs, String>
where
    I: Iterator<Item = String>,
{
    let mut pid = 0usize;
    let mut nodes = 4usize;
    let mut faulty = 1usize;
    let mut acs_protocol = Protocol::HoneyBadger;
    let mut acs_crypto_json: Option<String> = None;
    let mut hb_crypto_json: Option<String> = None;
    let mut config_json = String::from("{}");
    let mut ipc_mode = HbWorkerIpcMode::Json;

    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "--pid" => {
                pid = parse_usize_flag(&mut argv, "--pid")?;
            }
            "--nodes" => {
                nodes = parse_usize_flag(&mut argv, "--nodes")?;
            }
            "--faulty" => {
                faulty = parse_usize_flag(&mut argv, "--faulty")?;
            }
            "--acs-protocol" => {
                acs_protocol = Protocol::parse(&take_value(&mut argv, "--acs-protocol")?)?;
            }
            "--acs-crypto-json" => {
                acs_crypto_json = Some(take_value(&mut argv, "--acs-crypto-json")?);
            }
            "--hb-crypto-json" => {
                hb_crypto_json = Some(take_value(&mut argv, "--hb-crypto-json")?);
            }
            "--config-json" => {
                config_json = take_value(&mut argv, "--config-json")?;
            }
            "--ipc-mode" => {
                ipc_mode = HbWorkerIpcMode::parse(&take_value(&mut argv, "--ipc-mode")?)?;
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }

    if nodes == 0 {
        return Err(String::from("--nodes must be > 0"));
    }
    if pid >= nodes {
        return Err(format!("--pid {pid} must be < --nodes {nodes}"));
    }

    Ok(HbWorkerArgs {
        pid,
        nodes,
        faulty,
        acs_protocol,
        acs_crypto_json: acs_crypto_json
            .ok_or_else(|| String::from("--acs-crypto-json is required"))?,
        hb_crypto_json: hb_crypto_json
            .ok_or_else(|| String::from("--hb-crypto-json is required"))?,
        config_json,
        ipc_mode,
    })
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

fn run_rust_hosted_node(args: RunNodeArgs) -> Result<(), String> {
    Python::attach(|py| -> PyResult<()> {
        prepend_python_paths(py)?;

        let rust_host = PyModule::import(py, "honey.runtime.launch.rust_host")?;
        let result = rust_host.getattr("run_protocol_node")?.call1((
            args.protocol.as_str(),
            args.sid,
            args.pid,
            args.nodes,
            args.faulty,
            args.addresses_json,
            args.crypto_json,
            args.config_json,
            args.transactions_per_node,
            args.tx_input,
            args.start_at_ms,
        ))?;

        let json = PyModule::import(py, "json")?;
        let rendered = json
            .getattr("dumps")?
            .call1((result,))?
            .extract::<String>()?;
        write_output(args.result_path.as_deref(), &rendered)
            .map_err(pyo3::exceptions::PyValueError::new_err)?;
        Ok(())
    })
    .map_err(|err| err.to_string())
}

fn run_bench_local(args: BenchLocalArgs) -> Result<(), String> {
    if args.transport_backend != "tcp" {
        return Err(format!(
            "unsupported transport backend for rust-hosted benchmark: {}",
            args.transport_backend
        ));
    }
    if args.round_timeout <= 0.0 {
        return Err(String::from("--round-timeout must be > 0"));
    }

    let _ = args.batch_size;
    let _ = &args.log_level;

    let addresses = allocate_loopback_addresses(args.nodes)?;
    let addresses_json = serde_json::to_string(&addresses).map_err(|err| err.to_string())?;
    let crypto_payloads = serialize_crypto_payloads(args.protocol, args.nodes, args.faulty)?;
    let result_dir = build_result_dir(
        &format!("{}-rust-hosted", args.protocol.as_str()),
        &args.sid,
    )?;
    let start_at_ms = current_time_millis()?
        .checked_add(5_000)
        .ok_or_else(|| String::from("start time overflow"))?;
    let binary = std::env::current_exe().map_err(|err| err.to_string())?;
    let mut processes = Vec::new();

    for (pid, crypto_json) in crypto_payloads.into_iter().enumerate() {
        let result_path = result_dir.join(format!("node-{pid}.json"));
        let stdout_path = result_dir.join(format!("node-{pid}.out.log"));
        let stderr_path = result_dir.join(format!("node-{pid}.err.log"));
        let stdout_handle = File::create(&stdout_path).map_err(|err| err.to_string())?;
        let stderr_handle = File::create(&stderr_path).map_err(|err| err.to_string())?;

        let child = Command::new(&binary)
            .arg("run-node")
            .arg("--protocol")
            .arg(args.protocol.as_str())
            .arg("--pid")
            .arg(pid.to_string())
            .arg("--nodes")
            .arg(args.nodes.to_string())
            .arg("--faulty")
            .arg(args.faulty.to_string())
            .arg("--rounds")
            .arg(args.rounds.to_string())
            .arg("--sid")
            .arg(&args.sid)
            .arg("--addresses-json")
            .arg(&addresses_json)
            .arg("--crypto-json")
            .arg(&crypto_json)
            .arg("--config-json")
            .arg(&args.config_json)
            .arg("--transactions-per-node")
            .arg(args.transactions_per_node.to_string())
            .arg("--tx-input")
            .arg(&args.tx_input)
            .arg("--start-at-ms")
            .arg(start_at_ms.to_string())
            .arg("--result-path")
            .arg(&result_path)
            .stdout(Stdio::from(stdout_handle))
            .stderr(Stdio::from(stderr_handle))
            .spawn()
            .map_err(|err| err.to_string())?;

        processes.push(SpawnedNode {
            pid,
            child,
            result_path,
            stderr_path,
        });
    }

    let deadline = Instant::now() + Duration::from_secs_f64(args.global_timeout);
    while Instant::now() < deadline {
        if processes.iter().all(|process| process.result_path.exists()) {
            break;
        }

        let mut observed_failure = false;
        for process in &mut processes {
            if let Some(status) = process.child.try_wait().map_err(|err| err.to_string())?
                && !status.success()
            {
                observed_failure = true;
                break;
            }
        }
        if observed_failure {
            break;
        }

        thread::sleep(Duration::from_millis(50));
    }

    let all_results_ready = processes.iter().all(|process| process.result_path.exists());
    let mut errors = Vec::new();
    let mut results: Vec<Option<Value>> = (0..args.nodes).map(|_| None).collect();

    for process in &mut processes {
        let status = match process.child.try_wait().map_err(|err| err.to_string())? {
            Some(status) => status,
            None if all_results_ready => process.child.wait().map_err(|err| err.to_string())?,
            None => {
                let _ = process.child.kill();
                process.child.wait().map_err(|err| err.to_string())?
            }
        };

        if !status.success() {
            let stderr = read_log_file(&process.stderr_path);
            errors.push(format!(
                "pid={}: returncode={}: {}",
                process.pid,
                status.code().unwrap_or(-1),
                stderr.trim()
            ));
            continue;
        }

        if !process.result_path.exists() {
            let stderr = read_log_file(&process.stderr_path);
            errors.push(format!(
                "pid={}: missing result file: {}",
                process.pid,
                stderr.trim()
            ));
            continue;
        }

        let content = fs::read_to_string(&process.result_path).map_err(|err| err.to_string())?;
        let parsed = serde_json::from_str::<Value>(&content).map_err(|err| err.to_string())?;
        results[process.pid] = Some(parsed);
    }

    if !all_results_ready && errors.is_empty() {
        errors.push(format!(
            "benchmark timed out after {:.3}s before all node results were written",
            args.global_timeout
        ));
    }

    let rendered = if errors.is_empty() {
        let flattened: Vec<Value> = results
            .into_iter()
            .enumerate()
            .map(|(pid, value)| value.ok_or_else(|| format!("pid={pid}: missing decoded result")))
            .collect::<Result<_, _>>()?;
        serde_json::to_string(&flattened).map_err(|err| err.to_string())?
    } else {
        let _ = fs::remove_dir_all(&result_dir);
        return Err(format!(
            "Rust-hosted benchmark failed: {}",
            errors.join("; ")
        ));
    };

    if let Some(result_path) = args.result_path {
        write_output(Some(&result_path), &rendered).map_err(|err| err.to_string())?;
    } else {
        write_output(None, &rendered).map_err(|err| err.to_string())?;
    }

    let _ = fs::remove_dir_all(&result_dir);
    Ok(())
}

trait RustDrivenAcsHost {
    fn pid(&self) -> usize;
    fn start_round(&self, round_id: usize, sid: &str, local_input: &[u8]) -> Result<(), String>;
    fn deliver_decoded(
        &self,
        sender: usize,
        round_id: usize,
        channel: &str,
        instance_id: Option<usize>,
        message: &Py<PyAny>,
    ) -> Result<(), String>;
    fn drain_events(&self, limit: usize) -> Result<Vec<PyAcsEvent>, String>;
    fn stats(&self) -> Result<PyAcsHostStats, String>;
    fn shutdown(&self) -> Result<(), String>;
}

impl PyAcsHost {
    fn new(
        protocol: Protocol,
        pid: usize,
        nodes: usize,
        faulty: usize,
        crypto_json: &str,
        config_json: &str,
    ) -> Result<Self, String> {
        Python::attach(|py| -> PyResult<Self> {
            prepend_python_paths(py)?;
            let module = PyModule::import(py, "honey.runtime.acs_host")?;
            let kwargs = PyDict::new(py);
            kwargs.set_item("protocol", protocol.as_str())?;
            kwargs.set_item("pid", pid)?;
            kwargs.set_item("nodes", nodes)?;
            kwargs.set_item("faulty", faulty)?;
            kwargs.set_item("crypto_json", crypto_json)?;
            kwargs.set_item("config_json", config_json)?;
            let host = module
                .getattr("build_persistent_acs_host_from_json")?
                .call((), Some(&kwargs))?;
            Ok(Self {
                pid,
                inner: host.unbind(),
            })
        })
        .map_err(|err| err.to_string())
    }

    fn start_round(&self, round_id: usize, sid: &str, local_input: &[u8]) -> Result<(), String> {
        Python::attach(|py| -> PyResult<()> {
            let kwargs = PyDict::new(py);
            kwargs.set_item("round_id", round_id)?;
            kwargs.set_item("sid", sid)?;
            kwargs.set_item("local_input", local_input)?;
            self.inner
                .bind(py)
                .call_method("submit_start_round", (), Some(&kwargs))?;
            Ok(())
        })
        .map_err(|err| err.to_string())
    }

    fn deliver_raw(&self, payload: &[u8]) -> Result<(), String> {
        Python::attach(|py| -> PyResult<()> {
            self.inner
                .bind(py)
                .call_method1("submit_deliver", (payload,))?;
            Ok(())
        })
        .map_err(|err| err.to_string())
    }

    fn deliver_raw_batch(&self, payloads: &[Vec<u8>]) -> Result<(), String> {
        if payloads.is_empty() {
            return Ok(());
        }

        Python::attach(|py| -> PyResult<()> {
            self.inner
                .bind(py)
                .call_method1("submit_deliver_batch", (payloads.to_vec(),))?;
            Ok(())
        })
        .map_err(|err| err.to_string())
    }

    fn deliver_decoded(
        &self,
        sender: usize,
        round_id: usize,
        channel: &str,
        instance_id: Option<usize>,
        message: &Py<PyAny>,
    ) -> Result<(), String> {
        Python::attach(|py| -> PyResult<()> {
            let kwargs = PyDict::new(py);
            kwargs.set_item("sender", sender)?;
            kwargs.set_item("round_id", round_id)?;
            kwargs.set_item("channel", channel)?;
            kwargs.set_item("instance_id", instance_id)?;
            kwargs.set_item("message", message.bind(py))?;
            self.inner
                .bind(py)
                .call_method("submit_deliver_decoded", (), Some(&kwargs))?;
            Ok(())
        })
        .map_err(|err| err.to_string())
    }

    fn drain_events(&self, limit: usize) -> Result<Vec<PyAcsEvent>, String> {
        Python::attach(|py| -> PyResult<Vec<PyAcsEvent>> {
            let events = self.inner.bind(py).call_method1("drain_events", (limit,))?;
            events
                .try_iter()?
                .map(|item| parse_acs_event(item?.cast_into::<PyDict>()?))
                .collect()
        })
        .map_err(|err| err.to_string())
    }

    fn stats(&self) -> Result<PyAcsHostStats, String> {
        Python::attach(|py| -> PyResult<PyAcsHostStats> {
            let stats = self
                .inner
                .bind(py)
                .call_method0("bridge_stats")?
                .cast_into::<PyDict>()?;
            Ok(PyAcsHostStats {
                worker_ident: dict_item(&stats, "worker_ident")?.extract()?,
                rounds_started: dict_item(&stats, "rounds_started")?.extract()?,
                rounds_finished: dict_item(&stats, "rounds_finished")?.extract()?,
                processed_commands: dict_item(&stats, "processed_commands")?.extract()?,
                bridge_queue_size: dict_item(&stats, "bridge_queue_size")?.extract()?,
                worker_running: dict_item(&stats, "worker_running")?.extract()?,
                worker_error: dict_item(&stats, "worker_error")?.extract()?,
            })
        })
        .map_err(|err| err.to_string())
    }

    fn shutdown(&self) -> Result<(), String> {
        Python::attach(|py| -> PyResult<()> {
            self.inner.bind(py).call_method0("close_bridge")?;
            Ok(())
        })
        .map_err(|err| err.to_string())
    }
}

impl RustDrivenAcsHost for PyAcsHost {
    fn pid(&self) -> usize {
        self.pid
    }

    fn start_round(&self, round_id: usize, sid: &str, local_input: &[u8]) -> Result<(), String> {
        PyAcsHost::start_round(self, round_id, sid, local_input)
    }

    fn deliver_decoded(
        &self,
        sender: usize,
        round_id: usize,
        channel: &str,
        instance_id: Option<usize>,
        message: &Py<PyAny>,
    ) -> Result<(), String> {
        PyAcsHost::deliver_decoded(self, sender, round_id, channel, instance_id, message)
    }

    fn drain_events(&self, limit: usize) -> Result<Vec<PyAcsEvent>, String> {
        PyAcsHost::drain_events(self, limit)
    }

    fn stats(&self) -> Result<PyAcsHostStats, String> {
        PyAcsHost::stats(self)
    }

    fn shutdown(&self) -> Result<(), String> {
        PyAcsHost::shutdown(self)
    }
}

impl HbNodeRuntime {
    fn new(acs_host: PyAcsHost, tpke_private_share: HbPkePrivateKeyShare) -> Self {
        Self {
            acs_host,
            tpke_private_share,
        }
    }

    fn tpke_private_share(&self) -> &HbPkePrivateKeyShare {
        &self.tpke_private_share
    }
}

impl RustDrivenAcsHost for HbNodeRuntime {
    fn pid(&self) -> usize {
        self.acs_host.pid
    }

    fn start_round(&self, round_id: usize, sid: &str, local_input: &[u8]) -> Result<(), String> {
        self.acs_host.start_round(round_id, sid, local_input)
    }

    fn deliver_decoded(
        &self,
        sender: usize,
        round_id: usize,
        channel: &str,
        instance_id: Option<usize>,
        message: &Py<PyAny>,
    ) -> Result<(), String> {
        self.acs_host
            .deliver_decoded(sender, round_id, channel, instance_id, message)
    }

    fn drain_events(&self, limit: usize) -> Result<Vec<PyAcsEvent>, String> {
        self.acs_host.drain_events(limit)
    }

    fn stats(&self) -> Result<PyAcsHostStats, String> {
        self.acs_host.stats()
    }

    fn shutdown(&self) -> Result<(), String> {
        self.acs_host.shutdown()
    }
}

impl HbWorkerProcess {
    fn spawn(args: HbWorkerSpawnArgs<'_>) -> Result<Self, String> {
        let mut child = Command::new(args.binary_path)
            .arg("hb-worker")
            .arg("--pid")
            .arg(args.pid.to_string())
            .arg("--nodes")
            .arg(args.nodes.to_string())
            .arg("--faulty")
            .arg(args.faulty.to_string())
            .arg("--acs-protocol")
            .arg(args.acs_protocol.as_str())
            .arg("--acs-crypto-json")
            .arg(args.acs_crypto_json)
            .arg("--hb-crypto-json")
            .arg(args.hb_crypto_json)
            .arg("--config-json")
            .arg(args.config_json)
            .arg("--ipc-mode")
            .arg(HbWorkerIpcMode::Binary.as_str())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|err| format!("failed to spawn hb-worker pid={}: {err}", args.pid))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| format!("failed to open hb-worker stdin for pid={}", args.pid))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| format!("failed to open hb-worker stdout for pid={}", args.pid))?;

        Ok(Self {
            pid: args.pid,
            child,
            stdin,
            stdout: BufReader::new(stdout),
        })
    }

    fn request(&mut self, request: HbWorkerRequest) -> Result<HbWorkerResponse, String> {
        write_bincode_frame(&mut self.stdin, &request)
            .map_err(|err| format!("hb-worker pid={} request failed: {err}", self.pid))?;

        let response = read_bincode_frame::<_, Result<HbWorkerResponse, String>>(&mut self.stdout)
            .map_err(|err| format!("hb-worker pid={} response read failed: {err}", self.pid))?;
        let Some(response) = response else {
            let status = self
                .child
                .wait()
                .map_err(|err| format!("hb-worker pid={} wait failed: {err}", self.pid))?;
            return Err(format!(
                "hb-worker pid={} exited before responding: {}",
                self.pid, status
            ));
        };
        response.map_err(|err| format!("hb-worker pid={} returned error: {err}", self.pid))
    }

    fn start_round(
        &mut self,
        round_id: usize,
        sid: &str,
        local_input: &[u8],
    ) -> Result<(), String> {
        let _ = self.request(HbWorkerRequest::StartRound {
            round_id,
            sid: sid.to_string(),
            local_input: local_input.to_vec(),
        })?;
        Ok(())
    }

    fn deliver_batch(&mut self, payloads: &[Vec<u8>]) -> Result<(), String> {
        if payloads.is_empty() {
            return Ok(());
        }

        let _ = self.request(HbWorkerRequest::DeliverBatch {
            payloads: payloads.to_vec(),
        })?;
        Ok(())
    }

    fn drain_events(&mut self, limit: usize) -> Result<Vec<HbWorkerEvent>, String> {
        match self.request(HbWorkerRequest::DrainEvents { limit })? {
            HbWorkerResponse::Events(events) => {
                Ok(events.into_iter().map(worker_event_from_payload).collect())
            }
            _ => Err(format!(
                "hb-worker pid={} returned non-events response",
                self.pid
            )),
        }
    }

    fn stats(&mut self) -> Result<PyAcsHostStats, String> {
        match self.request(HbWorkerRequest::Stats)? {
            HbWorkerResponse::Stats(stats) => Ok(stats_from_payload(stats)),
            _ => Err(format!(
                "hb-worker pid={} returned non-stats response",
                self.pid
            )),
        }
    }

    fn tpke_local_bundle(
        &mut self,
        selected_batches: &[Vec<u8>],
    ) -> Result<(HbShareBundle, f64), String> {
        match self.request(HbWorkerRequest::TpkeLocalBundle {
            selected_batches: selected_batches.to_vec(),
        })? {
            HbWorkerResponse::TpkeLocalBundle {
                bundle,
                elapsed_seconds,
            } => Ok((bundle, elapsed_seconds)),
            _ => Err(format!(
                "hb-worker pid={} returned non-tpke response",
                self.pid
            )),
        }
    }

    fn shutdown(&mut self) -> Result<(), String> {
        if let Some(status) = self
            .child
            .try_wait()
            .map_err(|err| format!("hb-worker pid={} try_wait failed: {err}", self.pid))?
        {
            return if status.success() {
                Ok(())
            } else {
                Err(format!(
                    "hb-worker pid={} exited unexpectedly: {}",
                    self.pid, status
                ))
            };
        }

        let shutdown_result = self.request(HbWorkerRequest::Shutdown);
        let status = self
            .child
            .wait()
            .map_err(|err| format!("hb-worker pid={} wait failed: {err}", self.pid))?;
        match shutdown_result {
            Ok(_) if status.success() => Ok(()),
            Ok(_) => Err(format!(
                "hb-worker pid={} exited with non-zero status after shutdown: {}",
                self.pid, status
            )),
            Err(err) => Err(err),
        }
    }
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

fn parse_honeybadger_public_key(payloads: &[String]) -> Result<HbPkePublicParams, String> {
    let mut canonical_public_key: Option<Vec<u8>> = None;

    for (pid, payload) in payloads.iter().enumerate() {
        let decoded = serde_json::from_str::<Value>(payload).map_err(|err| err.to_string())?;
        let public_key = decode_hex(json_string_field(&decoded, "enc_pk")?)?;
        if let Some(expected) = canonical_public_key.as_ref() {
            if expected != &public_key {
                return Err(format!(
                    "crypto payload for pid={pid} carries a different enc_pk"
                ));
            }
        } else {
            canonical_public_key = Some(public_key);
        }
    }

    let public_key =
        canonical_public_key.ok_or_else(|| String::from("missing HoneyBadger enc_pk"))?;
    decode_pke_public_params(&public_key)
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

fn build_honeybadger_round_batch(
    round_id: usize,
    pid: usize,
    batch_size: usize,
) -> Result<Vec<u8>, String> {
    let mut items = Vec::with_capacity(batch_size);
    for tx_index in 0..batch_size {
        items.push(encode_hb_json_string(&format!(
            "hb-rust-driven-round-{round_id}-node-{pid}-tx-{tx_index}"
        ))?);
    }
    encode_hb_tx_batch(items)
}

fn drive_acs_debug_enabled() -> bool {
    std::env::var_os("HONEY_DEBUG_ACS").is_some()
}

fn start_worker_rounds_parallel(
    workers: &mut [HbWorkerProcess],
    round_id: usize,
    round_sid: &str,
    local_inputs: &[Vec<u8>],
) -> Result<(), String> {
    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers.len());
        for (worker, local_input) in workers.iter_mut().zip(local_inputs) {
            handles.push(scope.spawn(move || worker.start_round(round_id, round_sid, local_input)));
        }
        for handle in handles {
            handle
                .join()
                .map_err(|_| String::from("worker start_round thread panicked"))??;
        }
        Ok::<(), String>(())
    })
}

fn collect_worker_stats_parallel(
    workers: &mut [HbWorkerProcess],
) -> Result<Vec<(usize, PyAcsHostStats)>, String> {
    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers.len());
        for worker in workers.iter_mut() {
            handles.push(scope.spawn(move || worker.stats().map(|stats| (worker.pid, stats))));
        }

        let mut stats = Vec::with_capacity(handles.len());
        for handle in handles {
            stats.push(
                handle
                    .join()
                    .map_err(|_| String::from("worker stats thread panicked"))??,
            );
        }
        Ok::<Vec<(usize, PyAcsHostStats)>, String>(stats)
    })
}

fn drain_worker_events_parallel(
    workers: &mut [HbWorkerProcess],
    limit: usize,
) -> Result<Vec<(usize, Vec<HbWorkerEvent>)>, String> {
    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers.len());
        for worker in workers.iter_mut() {
            handles.push(scope.spawn(move || {
                worker
                    .drain_events(limit)
                    .map(|events| (worker.pid, events))
            }));
        }

        let mut drained = Vec::with_capacity(handles.len());
        for handle in handles {
            drained.push(
                handle
                    .join()
                    .map_err(|_| String::from("worker drain_events thread panicked"))??,
            );
        }
        Ok::<Vec<(usize, Vec<HbWorkerEvent>)>, String>(drained)
    })
}

fn flush_worker_deliveries_parallel(
    workers: &mut [HbWorkerProcess],
    deliveries_by_recipient: &mut [Vec<Vec<u8>>],
) -> Result<usize, String> {
    thread::scope(|scope| {
        let mut handles = Vec::new();
        for (recipient, worker) in workers.iter_mut().enumerate() {
            if deliveries_by_recipient[recipient].is_empty() {
                continue;
            }
            let payloads = std::mem::take(&mut deliveries_by_recipient[recipient]);
            handles.push(scope.spawn(move || worker.deliver_batch(&payloads)));
        }

        let non_empty_recipients = handles.len();
        for handle in handles {
            handle
                .join()
                .map_err(|_| String::from("worker deliver_batch thread panicked"))??;
        }
        Ok::<usize, String>(non_empty_recipients)
    })
}

fn run_acs_round<T: RustDrivenAcsHost>(
    hosts: &[T],
    round_id: usize,
    round_sid: &str,
    local_inputs: &[Vec<u8>],
    global_timeout: f64,
) -> Result<AcsRoundOutcome, String> {
    if local_inputs.len() != hosts.len() {
        return Err(format!(
            "round {round_id}: expected {} local ACS inputs, got {}",
            hosts.len(),
            local_inputs.len()
        ));
    }

    debug_drive_acs(&format!("round:start round={round_id}"));
    for (host, local_input) in hosts.iter().zip(local_inputs) {
        debug_drive_acs(&format!(
            "round:start_round:call round={round_id} pid={}",
            host.pid()
        ));
        host.start_round(round_id, round_sid, local_input)?;
        debug_drive_acs(&format!(
            "round:start_round:done round={round_id} pid={}",
            host.pid()
        ));
    }
    for host in hosts {
        let stats = host.stats()?;
        debug_drive_acs(&format!(
            "round:stats round={round_id} pid={} running={} commands={} queue={} started={} finished={} worker_error={:?}",
            host.pid(),
            stats.worker_running,
            stats.processed_commands,
            stats.bridge_queue_size,
            stats.rounds_started,
            stats.rounds_finished,
            stats.worker_error
        ));
    }

    let deadline = Instant::now() + Duration::from_secs_f64(global_timeout);
    let mut send_events = 0usize;
    let mut decisions: Vec<Option<Vec<Option<Vec<u8>>>>> = vec![None; hosts.len()];

    while Instant::now() < deadline {
        let mut progressed = false;

        for (pid, host) in hosts.iter().enumerate() {
            for event in host.drain_events(512)? {
                progressed = true;
                match event {
                    PyAcsEvent::Send {
                        round_id: event_round_id,
                        recipient,
                        channel,
                        instance_id,
                        message,
                    } => {
                        if event_round_id != round_id {
                            return Err(format!(
                                "drive-acs round {round_id}: send event carried mismatched round_id {event_round_id}"
                            ));
                        }
                        if recipient >= hosts.len() {
                            return Err(format!(
                                "drive-acs round {round_id}: invalid recipient {recipient}"
                            ));
                        }
                        hosts[recipient].deliver_decoded(
                            pid,
                            round_id,
                            &channel,
                            instance_id,
                            &message,
                        )?;
                        send_events += 1;
                    }
                    PyAcsEvent::Decision {
                        round_id: event_round_id,
                        values,
                    } => {
                        if event_round_id != round_id {
                            return Err(format!(
                                "drive-acs round {round_id}: decision event carried mismatched round_id {event_round_id}"
                            ));
                        }
                        debug_drive_acs(&format!("round:decision round={round_id} pid={pid}"));
                        decisions[pid] = Some(values);
                    }
                    PyAcsEvent::Failure {
                        round_id: event_round_id,
                        error,
                        exception_type,
                    } => {
                        return Err(format!(
                            "drive-acs round {round_id}: node {pid} failed in event round {event_round_id} with {exception_type}: {error}"
                        ));
                    }
                    PyAcsEvent::Carryovers { round_id: _ } => {}
                }
            }
        }

        if decisions.iter().all(Option::is_some) {
            break;
        }
        if !progressed {
            thread::sleep(ACS_IDLE_BACKOFF);
        }
    }

    if decisions.iter().any(Option::is_none) {
        return Err(format!(
            "drive-acs timed out after {:.3}s in round {round_id}",
            global_timeout
        ));
    }

    let canonical = decisions[0]
        .clone()
        .ok_or_else(|| format!("drive-acs round {round_id}: missing canonical decision"))?;
    for (pid, decision) in decisions.iter().enumerate().skip(1) {
        if decision.as_ref() != Some(&canonical) {
            return Err(format!(
                "drive-acs round {round_id}: node {pid} decision diverged"
            ));
        }
    }

    settle_acs_round(hosts, round_id, &mut send_events)?;
    Ok(AcsRoundOutcome {
        canonical,
        send_events,
    })
}

fn run_acs_round_workers(
    workers: &mut [HbWorkerProcess],
    round_id: usize,
    round_sid: &str,
    local_inputs: &[Vec<u8>],
    global_timeout: f64,
) -> Result<AcsRoundOutcome, String> {
    if local_inputs.len() != workers.len() {
        return Err(format!(
            "round {round_id}: expected {} local ACS inputs, got {}",
            workers.len(),
            local_inputs.len()
        ));
    }

    debug_drive_acs(&format!("round:start round={round_id}"));
    for worker in workers.iter() {
        debug_drive_acs(&format!(
            "round:start_round:call round={round_id} pid={}",
            worker.pid
        ));
    }
    start_worker_rounds_parallel(workers, round_id, round_sid, local_inputs)?;
    for worker in workers.iter() {
        debug_drive_acs(&format!(
            "round:start_round:done round={round_id} pid={}",
            worker.pid
        ));
    }
    if drive_acs_debug_enabled() {
        for (pid, stats) in collect_worker_stats_parallel(workers)? {
            debug_drive_acs(&format!(
                "round:stats round={round_id} pid={} running={} commands={} queue={} started={} finished={} worker_error={:?}",
                pid,
                stats.worker_running,
                stats.processed_commands,
                stats.bridge_queue_size,
                stats.rounds_started,
                stats.rounds_finished,
                stats.worker_error
            ));
        }
    }

    let deadline = Instant::now() + Duration::from_secs_f64(global_timeout);
    let mut send_events = 0usize;
    let mut decisions: Vec<Option<Vec<Option<Vec<u8>>>>> = vec![None; workers.len()];

    while Instant::now() < deadline {
        let mut progressed = false;
        let mut deliveries_by_recipient = vec![Vec::new(); workers.len()];

        for (pid, events) in drain_worker_events_parallel(workers, ACS_EVENT_DRAIN_LIMIT)? {
            for event in events {
                progressed = true;
                match event {
                    HbWorkerEvent::Send {
                        round_id: event_round_id,
                        recipient,
                        payload,
                    } => {
                        if event_round_id != round_id {
                            return Err(format!(
                                "drive-acs round {round_id}: send event carried mismatched round_id {event_round_id}"
                            ));
                        }
                        if recipient >= workers.len() {
                            return Err(format!(
                                "drive-acs round {round_id}: invalid recipient {recipient}"
                            ));
                        }
                        deliveries_by_recipient[recipient].push(payload);
                        send_events += 1;
                    }
                    HbWorkerEvent::Decision {
                        round_id: event_round_id,
                        values,
                    } => {
                        if event_round_id != round_id {
                            return Err(format!(
                                "drive-acs round {round_id}: decision event carried mismatched round_id {event_round_id}"
                            ));
                        }
                        debug_drive_acs(&format!("round:decision round={round_id} pid={pid}"));
                        decisions[pid] = Some(values);
                    }
                    HbWorkerEvent::Failure {
                        round_id: event_round_id,
                        error,
                        exception_type,
                    } => {
                        return Err(format!(
                            "drive-acs round {round_id}: node {pid} failed in event round {event_round_id} with {exception_type}: {error}"
                        ));
                    }
                    HbWorkerEvent::Carryovers {
                        round_id: event_round_id,
                    } => {
                        if event_round_id != round_id {
                            return Err(format!(
                                "drive-acs round {round_id}: carryovers event carried mismatched round_id {event_round_id}"
                            ));
                        }
                    }
                }
            }
        }

        let delivered_batches =
            flush_worker_deliveries_parallel(workers, &mut deliveries_by_recipient)?;
        if delivered_batches > 0 {
            progressed = true;
        }

        if decisions.iter().all(Option::is_some) {
            break;
        }
        if !progressed {
            thread::sleep(ACS_IDLE_BACKOFF);
        }
    }

    if decisions.iter().any(Option::is_none) {
        return Err(format!(
            "drive-acs timed out after {:.3}s in round {round_id}",
            global_timeout
        ));
    }

    let canonical = decisions[0]
        .clone()
        .ok_or_else(|| format!("drive-acs round {round_id}: missing canonical decision"))?;
    for (pid, decision) in decisions.iter().enumerate().skip(1) {
        if decision.as_ref() != Some(&canonical) {
            return Err(format!(
                "drive-acs round {round_id}: node {pid} decision diverged"
            ));
        }
    }

    settle_acs_round_workers(workers, round_id, &mut send_events)?;
    Ok(AcsRoundOutcome {
        canonical,
        send_events,
    })
}

fn drive_honeybadger_block_round_workers(
    public_key: &HbPkePublicParams,
    workers: &mut [HbWorkerProcess],
    selected_batches: &[Vec<u8>],
) -> Result<HbBlockOutcome, String> {
    if selected_batches.is_empty() {
        return Err(String::from("HoneyBadger round selected no ACS batches"));
    }

    let local_share_start = Instant::now();
    let share_bundles = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers.len());
        for worker in workers.iter_mut() {
            handles.push(scope.spawn(move || {
                worker
                    .tpke_local_bundle(selected_batches)
                    .map(|(bundle, _elapsed_seconds)| (worker.pid, bundle))
            }));
        }

        let mut bundles = Vec::with_capacity(handles.len());
        for handle in handles {
            let bundle = handle
                .join()
                .map_err(|_| String::from("HoneyBadger tpke_local_bundle worker panicked"))??;
            bundles.push(bundle);
        }
        Ok::<Vec<(usize, HbShareBundle)>, String>(bundles)
    })?;
    let local_share_seconds = local_share_start.elapsed().as_secs_f64();

    let combine_start = Instant::now();
    let mut decryptor = HbBatchDecryptor::new(public_key.clone(), selected_batches.to_vec())?;
    let mut tpke_bundle_events = 0usize;
    for (sender_id, bundle) in share_bundles {
        decryptor.ingest_bundle(sender_id, bundle)?;
        tpke_bundle_events += 1;
    }

    if !decryptor.is_complete() {
        return Err(String::from(
            "HoneyBadger TPKE stage did not complete for canonical decryptor",
        ));
    }

    let canonical_plaintexts = decryptor
        .plaintexts()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let canonical_block = merge_hb_tx_batches_bytes(canonical_plaintexts)?;
    let combine_seconds = combine_start.elapsed().as_secs_f64();

    Ok(HbBlockOutcome {
        block_payload: canonical_block,
        tpke_bundle_events,
        local_share_seconds,
        combine_seconds,
    })
}

fn run_drive_acs(args: DriveAcsArgs) -> Result<(), String> {
    debug_drive_acs("serialize_crypto_payloads:start");
    let crypto_payloads = serialize_crypto_payloads(args.protocol, args.nodes, args.faulty)?;
    debug_drive_acs("serialize_crypto_payloads:done");
    let mut hosts = Vec::with_capacity(crypto_payloads.len());
    for (pid, payload) in crypto_payloads.iter().enumerate() {
        debug_drive_acs(&format!("host:new:start pid={pid}"));
        match PyAcsHost::new(
            args.protocol,
            pid,
            args.nodes,
            args.faulty,
            payload,
            &args.config_json,
        ) {
            Ok(host) => {
                debug_drive_acs(&format!("host:new:done pid={pid}"));
                hosts.push(host)
            }
            Err(err) => {
                for host in &hosts {
                    let _ = host.shutdown();
                }
                return Err(err);
            }
        }
    }

    let result = drive_acs_rounds(&hosts, &args);

    let mut shutdown_errors = Vec::new();
    for host in &hosts {
        if let Err(err) = host.shutdown() {
            shutdown_errors.push(format!("pid={}: {err}", host.pid));
        }
    }

    let rendered = result?;
    if !shutdown_errors.is_empty() {
        return Err(format!(
            "drive-acs shutdown failed: {}",
            shutdown_errors.join("; ")
        ));
    }

    write_output(args.result_path.as_deref(), &rendered)
}

fn drive_acs_rounds(hosts: &[PyAcsHost], args: &DriveAcsArgs) -> Result<String, String> {
    let mut rounds = Vec::with_capacity(args.rounds);

    for round_id in 0..args.rounds {
        let round_sid = format!("{}:{round_id}:", args.sid);
        let local_inputs = hosts
            .iter()
            .map(|host| {
                Ok(format!(
                    "{}-round-{round_id}-node-{}",
                    args.protocol.as_str(),
                    host.pid
                )
                .into_bytes())
            })
            .collect::<Result<Vec<_>, String>>()?;
        let outcome = run_acs_round(
            hosts,
            round_id,
            &round_sid,
            &local_inputs,
            args.global_timeout,
        )?;

        rounds.push(json!({
            "round_id": round_id,
            "selected_count": outcome.canonical.iter().filter(|value| value.is_some()).count(),
            "send_events": outcome.send_events,
        }));
    }

    let nodes = hosts
        .iter()
        .map(|host| {
            let stats = host.stats()?;
            Ok(json!({
                "pid": host.pid,
                "worker_ident": stats.worker_ident,
                "rounds_started": stats.rounds_started,
                "rounds_finished": stats.rounds_finished,
                "processed_commands": stats.processed_commands,
                "bridge_queue_size": stats.bridge_queue_size,
                "worker_running": stats.worker_running,
                "worker_error": stats.worker_error,
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;

    serde_json::to_string(&json!({
        "protocol": args.protocol.as_str(),
        "sid": args.sid,
        "nodes": nodes,
        "rounds": rounds,
    }))
    .map_err(|err| err.to_string())
}

fn run_drive_honeybadger(args: DriveHoneyBadgerArgs) -> Result<(), String> {
    debug_drive_acs("serialize_hb_crypto_payloads:start");
    let hb_crypto_payloads =
        serialize_crypto_payloads(Protocol::HoneyBadger, args.nodes, args.faulty)?;
    debug_drive_acs("serialize_hb_crypto_payloads:done");
    let public_key = parse_honeybadger_public_key(&hb_crypto_payloads)?;
    let acs_crypto_payloads = if matches!(args.acs_protocol, Protocol::HoneyBadger) {
        hb_crypto_payloads.clone()
    } else {
        debug_drive_acs("serialize_acs_crypto_payloads:start");
        let payloads = serialize_crypto_payloads(args.acs_protocol, args.nodes, args.faulty)?;
        debug_drive_acs("serialize_acs_crypto_payloads:done");
        payloads
    };
    let binary_path = std::env::current_exe()
        .map_err(|err| format!("failed to resolve honey-node path: {err}"))?;
    let mut workers = Vec::with_capacity(args.nodes);

    for pid in 0..args.nodes {
        debug_drive_acs(&format!("host:new:start pid={pid}"));
        match HbWorkerProcess::spawn(HbWorkerSpawnArgs {
            binary_path: &binary_path,
            pid,
            nodes: args.nodes,
            faulty: args.faulty,
            acs_protocol: args.acs_protocol,
            acs_crypto_json: &acs_crypto_payloads[pid],
            hb_crypto_json: &hb_crypto_payloads[pid],
            config_json: &args.config_json,
        }) {
            Ok(worker) => {
                debug_drive_acs(&format!("host:new:done pid={pid}"));
                workers.push(worker);
            }
            Err(err) => {
                for worker in &mut workers {
                    let _ = worker.shutdown();
                }
                return Err(err);
            }
        }
    }

    let result = drive_honeybadger_rounds_workers(&mut workers, &args, &public_key);

    let mut shutdown_errors = Vec::new();
    for worker in &mut workers {
        if let Err(err) = worker.shutdown() {
            shutdown_errors.push(format!("pid={}: {err}", worker.pid));
        }
    }

    let rendered = result?;
    if !shutdown_errors.is_empty() {
        return Err(format!(
            "drive-hb shutdown failed: {}",
            shutdown_errors.join("; ")
        ));
    }

    write_output(args.result_path.as_deref(), &rendered)
}

fn drive_honeybadger_rounds_workers(
    workers: &mut [HbWorkerProcess],
    args: &DriveHoneyBadgerArgs,
    public_key: &HbPkePublicParams,
) -> Result<String, String> {
    let mut rounds = Vec::with_capacity(args.rounds);
    let mut chain_digest = GENESIS_CHAIN_DIGEST;
    let mut chain_digest_hex: Option<String> = None;

    for round_id in 0..args.rounds {
        let round_wall_start = Instant::now();
        let round_sid = format!("{}:{round_id}:", args.sid);
        let round_build_start = Instant::now();
        let local_inputs = workers
            .iter()
            .map(|worker| {
                let batch = build_honeybadger_round_batch(round_id, worker.pid, args.batch_size)?;
                seal_hb_encrypted_batch(public_key, &batch)
            })
            .collect::<Result<Vec<_>, String>>()?;
        let build_seconds = round_build_start.elapsed().as_secs_f64();
        let acs_start = Instant::now();
        let outcome = run_acs_round_workers(
            workers,
            round_id,
            &round_sid,
            &local_inputs,
            args.global_timeout,
        )?;
        let acs_seconds = acs_start.elapsed().as_secs_f64();
        let selected_batches = outcome
            .canonical
            .iter()
            .flatten()
            .cloned()
            .collect::<Vec<_>>();
        let selected_pids = outcome
            .canonical
            .iter()
            .enumerate()
            .filter_map(|(pid, value)| value.as_ref().map(|_| pid))
            .collect::<Vec<_>>();

        if selected_batches.len() < args.nodes - args.faulty {
            return Err(format!(
                "drive-hb round {round_id}: expected at least {} ACS batches, got {}",
                args.nodes - args.faulty,
                selected_batches.len()
            ));
        }

        let tpke_start = Instant::now();
        let block_outcome =
            drive_honeybadger_block_round_workers(public_key, workers, &selected_batches)?;
        let tpke_seconds = tpke_start.elapsed().as_secs_f64();
        let protocol_seconds = acs_seconds + tpke_seconds;
        let wall_seconds = round_wall_start.elapsed().as_secs_f64();
        let delivered_count = decode_hb_tx_batch(&block_outcome.block_payload)?.len();
        let block_digest = sha256_hex(&block_outcome.block_payload);
        chain_digest = compute_chain_digest(&chain_digest, round_id, &block_outcome.block_payload);
        chain_digest_hex = Some(hex_encode(&chain_digest));

        rounds.push(json!({
            "round_id": round_id,
            "selected_count": selected_batches.len(),
            "selected_pids": selected_pids,
            "acs_send_events": outcome.send_events,
            "tpke_bundle_events": block_outcome.tpke_bundle_events,
            "delivered_count": delivered_count,
            "block_size": block_outcome.block_payload.len(),
            "block_digest": block_digest,
            "chain_digest": chain_digest_hex,
            "build_seconds": build_seconds,
            "acs_seconds": acs_seconds,
            "tpke_seconds": tpke_seconds,
            "tpke_local_share_seconds": block_outcome.local_share_seconds,
            "tpke_combine_seconds": block_outcome.combine_seconds,
            "protocol_seconds": protocol_seconds,
            "wall_seconds": wall_seconds,
        }));
    }

    let nodes = workers
        .iter_mut()
        .map(|worker| {
            let stats = worker.stats()?;
            Ok(json!({
                "pid": worker.pid,
                "worker_ident": stats.worker_ident,
                "rounds_started": stats.rounds_started,
                "rounds_finished": stats.rounds_finished,
                "processed_commands": stats.processed_commands,
                "bridge_queue_size": stats.bridge_queue_size,
                "worker_running": stats.worker_running,
                "worker_error": stats.worker_error,
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;

    serde_json::to_string(&json!({
        "protocol": "hb",
        "acs_protocol": args.acs_protocol.as_str(),
        "sid": args.sid,
        "chain_digest": chain_digest_hex,
        "nodes": nodes,
        "rounds": rounds,
    }))
    .map_err(|err| err.to_string())
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

fn run_hb_worker(args: HbWorkerArgs) -> Result<(), String> {
    let acs_host = PyAcsHost::new(
        args.acs_protocol,
        args.pid,
        args.nodes,
        args.faulty,
        &args.acs_crypto_json,
        &args.config_json,
    )?;
    let (public_key, private_share) = parse_honeybadger_crypto_payload(&args.hb_crypto_json)?;
    let runtime = HbNodeRuntime::new(acs_host, private_share);

    let shutdown_requested = match args.ipc_mode {
        HbWorkerIpcMode::Json => run_hb_worker_json(&runtime, &public_key)?,
        HbWorkerIpcMode::Binary => run_hb_worker_binary(&runtime, &public_key)?,
    };

    if !shutdown_requested {
        let _ = runtime.shutdown();
    }

    Ok(())
}

fn run_hb_worker_json(
    runtime: &HbNodeRuntime,
    public_key: &HbPkePublicParams,
) -> Result<bool, String> {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    let mut shutdown_requested = false;

    for line in BufReader::new(stdin.lock()).lines() {
        let line = line.map_err(|err| err.to_string())?;
        if line.trim().is_empty() {
            continue;
        }

        let response = match handle_hb_worker_command(runtime, public_key, &line) {
            Ok((payload, should_shutdown)) => {
                shutdown_requested = should_shutdown;
                payload
            }
            Err(err) => json!({"ok": false, "error": err}),
        };

        let rendered = serde_json::to_string(&response).map_err(|err| err.to_string())?;
        writeln!(stdout, "{rendered}").map_err(|err| err.to_string())?;
        stdout.flush().map_err(|err| err.to_string())?;

        if shutdown_requested {
            break;
        }
    }

    Ok(shutdown_requested)
}

fn run_hb_worker_binary(
    runtime: &HbNodeRuntime,
    public_key: &HbPkePublicParams,
) -> Result<bool, String> {
    let stdin = io::stdin();
    let mut stdin = stdin.lock();
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    let mut shutdown_requested = false;

    while let Some(request) = read_bincode_frame::<_, HbWorkerRequest>(&mut stdin)? {
        let response = handle_hb_worker_request(runtime, public_key, request);
        let should_shutdown = matches!(&response, Ok((_payload, true)));
        write_bincode_frame(&mut stdout, &response)?;
        if should_shutdown {
            shutdown_requested = true;
            break;
        }
    }

    Ok(shutdown_requested)
}

fn handle_hb_worker_command(
    runtime: &HbNodeRuntime,
    public_key: &HbPkePublicParams,
    line: &str,
) -> Result<(Value, bool), String> {
    let command = serde_json::from_str::<Value>(line).map_err(|err| err.to_string())?;
    let kind = json_string_field(&command, "kind")?;

    match kind {
        "stats" => {
            let stats = runtime.stats()?;
            Ok((
                json!({
                    "ok": true,
                    "stats": {
                        "pid": runtime.pid(),
                        "worker_ident": stats.worker_ident,
                        "rounds_started": stats.rounds_started,
                        "rounds_finished": stats.rounds_finished,
                        "processed_commands": stats.processed_commands,
                        "bridge_queue_size": stats.bridge_queue_size,
                        "worker_running": stats.worker_running,
                        "worker_error": stats.worker_error,
                    }
                }),
                false,
            ))
        }
        "start_round" => {
            let round_id = json_usize_field(&command, "round_id")?;
            let sid = json_string_field(&command, "sid")?;
            let local_input = decode_hex(json_string_field(&command, "local_input_hex")?)?;
            runtime.start_round(round_id, sid, &local_input)?;
            Ok((json!({"ok": true}), false))
        }
        "deliver" => {
            let payload = decode_hex(json_string_field(&command, "payload_hex")?)?;
            runtime.acs_host.deliver_raw(&payload)?;
            Ok((json!({"ok": true}), false))
        }
        "deliver_batch" => {
            let payloads = json_string_list_field(&command, "payloads_hex")?
                .into_iter()
                .map(|payload| decode_hex(&payload))
                .collect::<Result<Vec<_>, _>>()?;
            runtime.acs_host.deliver_raw_batch(&payloads)?;
            Ok((json!({"ok": true}), false))
        }
        "drain_events" => {
            let limit = command.get("limit").and_then(Value::as_u64).unwrap_or(128) as usize;
            let rendered_events = runtime
                .drain_events(limit)?
                .into_iter()
                .map(|event| match event {
                    PyAcsEvent::Send {
                        round_id,
                        recipient,
                        channel,
                        instance_id,
                        message,
                    } => Ok(json!({
                        "kind": "send",
                        "round_id": round_id,
                        "recipient": recipient,
                        "payload_hex": hex_encode(&encode_protocol_envelope(
                            runtime.pid(),
                            round_id,
                            &channel,
                            instance_id,
                            &message,
                        )?),
                    })),
                    PyAcsEvent::Decision { round_id, values } => Ok(json!({
                        "kind": "decision",
                        "round_id": round_id,
                        "values_hex": values
                            .into_iter()
                            .map(|value| value.map(|bytes| hex_encode(&bytes)))
                            .collect::<Vec<_>>(),
                    })),
                    PyAcsEvent::Failure {
                        round_id,
                        error,
                        exception_type,
                    } => Ok(json!({
                        "kind": "failure",
                        "round_id": round_id,
                        "error": error,
                        "exception_type": exception_type,
                    })),
                    PyAcsEvent::Carryovers { round_id } => Ok(json!({
                        "kind": "carryovers",
                        "round_id": round_id,
                    })),
                })
                .collect::<Result<Vec<_>, String>>()?;
            Ok((json!({"ok": true, "events": rendered_events}), false))
        }
        "tpke_local_bundle" => {
            let selected_batches = json_string_list_field(&command, "selected_batches_hex")?
                .into_iter()
                .map(|payload| decode_hex(&payload))
                .collect::<Result<Vec<_>, _>>()?;
            let start = Instant::now();
            let decryptor = HbBatchDecryptor::new(public_key.clone(), selected_batches)?;
            let bundle = decryptor.local_shares(runtime.tpke_private_share())?;
            Ok((
                json!({
                    "ok": true,
                    "bundle_hex": bundle.into_iter().map(|share| hex_encode(&share)).collect::<Vec<_>>(),
                    "elapsed_seconds": start.elapsed().as_secs_f64(),
                }),
                false,
            ))
        }
        "shutdown" => {
            runtime.shutdown()?;
            Ok((json!({"ok": true}), true))
        }
        _ => Err(format!("unknown hb-worker command kind: {kind}")),
    }
}

fn handle_hb_worker_request(
    runtime: &HbNodeRuntime,
    public_key: &HbPkePublicParams,
    request: HbWorkerRequest,
) -> Result<(HbWorkerResponse, bool), String> {
    match request {
        HbWorkerRequest::Stats => {
            let stats = runtime.stats()?;
            Ok((
                HbWorkerResponse::Stats(stats_payload_from_stats(runtime.pid(), stats)),
                false,
            ))
        }
        HbWorkerRequest::StartRound {
            round_id,
            sid,
            local_input,
        } => {
            runtime.start_round(round_id, &sid, &local_input)?;
            Ok((HbWorkerResponse::Ack, false))
        }
        HbWorkerRequest::DeliverBatch { payloads } => {
            runtime.acs_host.deliver_raw_batch(&payloads)?;
            Ok((HbWorkerResponse::Ack, false))
        }
        HbWorkerRequest::DrainEvents { limit } => {
            let events = runtime
                .drain_events(limit)?
                .into_iter()
                .map(|event| match event {
                    PyAcsEvent::Send {
                        round_id,
                        recipient,
                        channel,
                        instance_id,
                        message,
                    } => Ok(HbWorkerEventPayload::Send {
                        round_id,
                        recipient,
                        payload: encode_protocol_envelope(
                            runtime.pid(),
                            round_id,
                            &channel,
                            instance_id,
                            &message,
                        )?,
                    }),
                    PyAcsEvent::Decision { round_id, values } => {
                        Ok(HbWorkerEventPayload::Decision { round_id, values })
                    }
                    PyAcsEvent::Failure {
                        round_id,
                        error,
                        exception_type,
                    } => Ok(HbWorkerEventPayload::Failure {
                        round_id,
                        error,
                        exception_type,
                    }),
                    PyAcsEvent::Carryovers { round_id } => {
                        Ok(HbWorkerEventPayload::Carryovers { round_id })
                    }
                })
                .collect::<Result<Vec<_>, String>>()?;
            Ok((HbWorkerResponse::Events(events), false))
        }
        HbWorkerRequest::TpkeLocalBundle { selected_batches } => {
            let start = Instant::now();
            let decryptor = HbBatchDecryptor::new(public_key.clone(), selected_batches)?;
            let bundle = decryptor
                .local_shares(runtime.tpke_private_share())?
                .into_iter()
                .map(Some)
                .collect::<Vec<_>>();
            Ok((
                HbWorkerResponse::TpkeLocalBundle {
                    bundle,
                    elapsed_seconds: start.elapsed().as_secs_f64(),
                },
                false,
            ))
        }
        HbWorkerRequest::Shutdown => {
            runtime.shutdown()?;
            Ok((HbWorkerResponse::Ack, true))
        }
    }
}

fn settle_acs_round_workers(
    workers: &mut [HbWorkerProcess],
    round_id: usize,
    send_events: &mut usize,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_millis(100);
    while Instant::now() < deadline {
        let mut progressed = false;
        let mut deliveries_by_recipient = vec![Vec::new(); workers.len()];

        for (pid, events) in drain_worker_events_parallel(workers, ACS_EVENT_DRAIN_LIMIT)? {
            for event in events {
                progressed = true;
                match event {
                    HbWorkerEvent::Send {
                        round_id: event_round_id,
                        recipient,
                        payload,
                    } => {
                        if event_round_id != round_id {
                            return Err(format!(
                                "drive-acs round {round_id}: send event carried mismatched round_id {event_round_id} during settle"
                            ));
                        }
                        if recipient >= workers.len() {
                            return Err(format!(
                                "drive-acs round {round_id}: invalid recipient {recipient} during settle"
                            ));
                        }
                        deliveries_by_recipient[recipient].push(payload);
                        *send_events += 1;
                    }
                    HbWorkerEvent::Failure {
                        round_id: event_round_id,
                        error,
                        exception_type,
                    } => {
                        return Err(format!(
                            "drive-acs round {round_id}: node {pid} failed during settle in event round {event_round_id} with {exception_type}: {error}"
                        ));
                    }
                    HbWorkerEvent::Decision { .. } => {}
                    HbWorkerEvent::Carryovers {
                        round_id: event_round_id,
                    } => {
                        if event_round_id != round_id {
                            return Err(format!(
                                "drive-acs round {round_id}: carryovers event carried mismatched round_id {event_round_id} during settle"
                            ));
                        }
                    }
                }
            }
        }

        let delivered_batches =
            flush_worker_deliveries_parallel(workers, &mut deliveries_by_recipient)?;
        if delivered_batches > 0 {
            progressed = true;
        }

        if !progressed {
            let queues_empty = collect_worker_stats_parallel(workers)?
                .into_iter()
                .all(|(_pid, stats)| stats.bridge_queue_size == 0);
            if queues_empty {
                break;
            }
        }
        thread::sleep(ACS_IDLE_BACKOFF);
    }
    Ok(())
}

fn settle_acs_round<T: RustDrivenAcsHost>(
    hosts: &[T],
    round_id: usize,
    send_events: &mut usize,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_millis(100);
    while Instant::now() < deadline {
        let mut progressed = false;
        for (pid, host) in hosts.iter().enumerate() {
            for event in host.drain_events(512)? {
                progressed = true;
                match event {
                    PyAcsEvent::Send {
                        round_id: event_round_id,
                        recipient,
                        channel,
                        instance_id,
                        message,
                    } => {
                        if event_round_id != round_id {
                            return Err(format!(
                                "drive-acs round {round_id}: send event carried mismatched round_id {event_round_id} during settle"
                            ));
                        }
                        if recipient >= hosts.len() {
                            return Err(format!(
                                "drive-acs round {round_id}: invalid recipient {recipient} during settle"
                            ));
                        }
                        hosts[recipient].deliver_decoded(
                            pid,
                            round_id,
                            &channel,
                            instance_id,
                            &message,
                        )?;
                        *send_events += 1;
                    }
                    PyAcsEvent::Failure {
                        round_id: event_round_id,
                        error,
                        exception_type,
                    } => {
                        return Err(format!(
                            "drive-acs round {round_id}: node {pid} failed during settle in event round {event_round_id} with {exception_type}: {error}"
                        ));
                    }
                    PyAcsEvent::Decision { .. } | PyAcsEvent::Carryovers { .. } => {}
                }
            }
        }

        let queues_empty = hosts
            .iter()
            .map(|host| host.stats())
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .all(|stats| stats.bridge_queue_size == 0);
        if !progressed && queues_empty {
            break;
        }
        thread::sleep(ACS_IDLE_BACKOFF);
    }
    Ok(())
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
        let materials = PyModule::import(py, "honey.runtime.launch.crypto_material")?;
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
