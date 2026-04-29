#![recursion_limit = "256"]

use honey_acs::AcsBackendKind;

use honey_node::keygen::{generate_dumbo_crypto_payloads_json, generate_hb_crypto_payloads_json};
use honey_wire::phase_stats::{DriverPhaseStats, driver_phase_stats_json};
use serde::Deserialize;
use serde_json::{Value, json};
use std::fs::{self, File};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod drive_dumbo;
mod drive_hb;
pub mod stats;
pub mod suite;
pub mod tps;
pub mod tps_cmd;

pub use drive_dumbo::run_drive_dumbo_multiprocess;

// Re-export commonly-used types for main.rs

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BenchDriverMode {
    Benchmark,
    HoneyBadger,
    Dumbo,
}

impl BenchDriverMode {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "benchmark" => Ok(Self::Benchmark),
            "hb" | "honeybadger" => Ok(Self::HoneyBadger),
            "dumbo" => Ok(Self::Dumbo),
            _ => Err(format!("unsupported bench-driver mode: {value}")),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct BenchDriverConfigFile {
    mode: Option<String>,
    sid: Option<String>,
    protocol: Option<String>,
    acs_backend: Option<String>,
    nodes: Option<usize>,
    faulty: Option<usize>,
    rounds: Option<usize>,
    batch_size: Option<usize>,
    global_timeout: Option<f64>,
    result_path: Option<String>,
    ledger_dir: Option<String>,
    tx_json: Option<toml::Value>,
    config: Option<toml::Value>,
}

pub struct BenchDriverArgs {
    pub mode: BenchDriverMode,
    pub sid: String,
    pub backend: AcsBackendKind,
    pub acs_backend: AcsBackendKind,
    pub nodes: usize,
    pub faulty: usize,
    pub rounds: usize,
    pub batch_size: usize,
    pub global_timeout: f64,
    pub config_json: String,
    pub result_path: Option<String>,
    pub ledger_dir: Option<String>,
    pub tx_json: Option<String>,
}

pub struct BenchHoneyBadgerArgs {
    pub sid: String,
    pub acs_backend: AcsBackendKind,
    pub nodes: usize,
    pub faulty: usize,
    pub rounds: usize,
    pub batch_size: usize,
    pub global_timeout: f64,
    pub config_json: String,
    pub result_path: Option<String>,
}

pub struct BenchDumboArgs {
    pub sid: String,
    pub acs_backend: AcsBackendKind,
    pub nodes: usize,
    pub faulty: usize,
    pub rounds: usize,
    pub batch_size: usize,
    pub global_timeout: f64,
    pub config_json: String,
    pub result_path: Option<String>,
    pub ledger_dir: Option<String>,
    pub tx_json: Option<String>,
}

struct SpawnedNode {
    pid: usize,
    child: std::process::Child,
    result_path: PathBuf,
    stderr_path: PathBuf,
}

fn node_command(binary: &Path) -> Command {
    let mut command = Command::new(binary);
    configure_embedded_python_env(&mut command);
    command
}

#[cfg(target_os = "windows")]
fn configure_embedded_python_env(command: &mut Command) {
    let Some(venv_root) = discover_venv_root() else {
        return;
    };
    let python_home = python_home_from_venv(&venv_root);
    if let Some(home) = python_home.as_ref() {
        command.env("PYTHONHOME", home);
    }

    let mut python_paths = Vec::new();
    if let Some(home) = python_home.as_ref() {
        python_paths.push(home.join("Lib"));
    }
    let venv_site = venv_root.join("Lib").join("site-packages");
    if venv_site.exists() {
        python_paths.push(venv_site);
    }
    if let Ok(root) = std::env::current_dir() {
        python_paths.push(
            root.join("honey-acs")
                .join("packages")
                .join("honey-acs")
                .join("src"),
        );
        python_paths.push(root.join("src"));
        python_paths.push(root);
    }
    if let Some(existing) = std::env::var_os("PYTHONPATH") {
        python_paths.extend(std::env::split_paths(&existing));
    }
    if let Ok(joined) = std::env::join_paths(python_paths) {
        command.env("PYTHONPATH", joined);
    }
    command.env("VIRTUAL_ENV", venv_root);
}

#[cfg(not(target_os = "windows"))]
fn configure_embedded_python_env(_command: &mut Command) {}

#[cfg(target_os = "windows")]
fn discover_venv_root() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("VIRTUAL_ENV") {
        let root = PathBuf::from(path);
        if root.join("pyvenv.cfg").exists() {
            return Some(root);
        }
    }
    if let Some(path) = std::env::var_os("PYO3_PYTHON") {
        let path = PathBuf::from(path);
        if let Some(root) = path.parent().and_then(|parent| parent.parent())
            && root.join("pyvenv.cfg").exists()
        {
            return Some(root.to_path_buf());
        }
    }
    let root = std::env::current_dir().ok()?.join(".venv");
    root.join("pyvenv.cfg").exists().then_some(root)
}

#[cfg(target_os = "windows")]
fn python_home_from_venv(venv_root: &Path) -> Option<PathBuf> {
    let config = fs::read_to_string(venv_root.join("pyvenv.cfg")).ok()?;
    for line in config.lines() {
        let Some(home) = line.strip_prefix("home = ") else {
            continue;
        };
        let home = PathBuf::from(home.trim());
        if home.join("Lib").join("encodings").exists() {
            return Some(home);
        }
    }
    None
}

pub fn run_config_path(config_path: &Path, node_binary: &Path) -> Result<(), String> {
    let args = load_bench_driver_args(config_path)?;
    run_with_args(args, node_binary)
}

pub fn run_with_args(args: BenchDriverArgs, node_binary: &Path) -> Result<(), String> {
    match args.mode {
        BenchDriverMode::Benchmark => run_bench_rust_driver(args, node_binary),
        BenchDriverMode::HoneyBadger => drive_hb::run_drive_honeybadger(
            BenchHoneyBadgerArgs {
                sid: args.sid,
                acs_backend: args.acs_backend,
                nodes: args.nodes,
                faulty: args.faulty,
                rounds: args.rounds,
                batch_size: args.batch_size,
                global_timeout: args.global_timeout,
                config_json: args.config_json,
                result_path: args.result_path,
            },
            node_binary,
        ),
        BenchDriverMode::Dumbo => drive_dumbo::run_drive_dumbo(
            BenchDumboArgs {
                sid: args.sid,
                acs_backend: args.acs_backend,
                nodes: args.nodes,
                faulty: args.faulty,
                rounds: args.rounds,
                batch_size: args.batch_size,
                global_timeout: args.global_timeout,
                config_json: args.config_json,
                result_path: args.result_path,
                ledger_dir: args.ledger_dir,
                tx_json: args.tx_json,
            },
            node_binary,
        ),
    }
}

fn load_bench_driver_args(path: &Path) -> Result<BenchDriverArgs, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read bench config '{}': {err}", path.display()))?;
    let file_config: BenchDriverConfigFile = toml::from_str(&content)
        .map_err(|err| format!("failed to parse bench config '{}': {err}", path.display()))?;
    build_args(file_config)
}

fn build_args(file_config: BenchDriverConfigFile) -> Result<BenchDriverArgs, String> {
    let mode = match file_config.mode.as_deref() {
        Some(value) => BenchDriverMode::parse(value)?,
        None => BenchDriverMode::Benchmark,
    };
    let protocol = file_config
        .protocol
        .as_deref()
        .map(AcsBackendKind::parse)
        .transpose()?
        .unwrap_or(AcsBackendKind::PythonHb);
    let acs_backend = file_config
        .acs_backend
        .as_deref()
        .map(AcsBackendKind::parse)
        .transpose()?
        .unwrap_or(AcsBackendKind::PythonHb);
    let nodes = file_config.nodes.unwrap_or(4);
    let faulty = file_config.faulty.unwrap_or(1);
    let rounds = file_config.rounds.unwrap_or(1);
    let batch_size = file_config.batch_size.unwrap_or(1);
    let global_timeout = file_config.global_timeout.unwrap_or(30.0);
    let config_json = resolve_json_field(file_config.config.as_ref(), "config", "{}")?;
    let tx_json = resolve_optional_json_field(file_config.tx_json.as_ref(), "tx_json")?;

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
    if !matches!(mode, BenchDriverMode::Dumbo)
        && (file_config.ledger_dir.is_some() || tx_json.is_some())
    {
        return Err(String::from(
            "ledger_dir/tx_json are supported only with mode \"dumbo\"",
        ));
    }

    Ok(BenchDriverArgs {
        mode,
        sid: file_config
            .sid
            .unwrap_or_else(|| String::from("bench:driver:hb")),
        backend: protocol,
        acs_backend,
        nodes,
        faulty,
        rounds,
        batch_size,
        global_timeout,
        config_json,
        result_path: file_config.result_path,
        ledger_dir: file_config.ledger_dir,
        tx_json,
    })
}

fn resolve_json_field(
    file_value: Option<&toml::Value>,
    field_name: &str,
    default: &str,
) -> Result<String, String> {
    match file_value {
        Some(value) => toml_value_to_json_string(value, field_name),
        None => Ok(String::from(default)),
    }
}

fn resolve_optional_json_field(
    file_value: Option<&toml::Value>,
    field_name: &str,
) -> Result<Option<String>, String> {
    file_value
        .map(|value| toml_value_to_json_string(value, field_name))
        .transpose()
}

fn toml_value_to_json_string(value: &toml::Value, field_name: &str) -> Result<String, String> {
    let json_value =
        toml_to_json_value(value).map_err(|err| format!("invalid {field_name}: {err}"))?;
    serde_json::to_string(&json_value).map_err(|err| format!("invalid {field_name}: {err}"))
}

fn toml_to_json_value(value: &toml::Value) -> Result<Value, String> {
    match value {
        toml::Value::String(value) => Ok(Value::String(value.clone())),
        toml::Value::Integer(value) => Ok(json!(value)),
        toml::Value::Float(value) => Ok(json!(value)),
        toml::Value::Boolean(value) => Ok(json!(value)),
        toml::Value::Datetime(value) => Ok(Value::String(value.to_string())),
        toml::Value::Array(values) => values
            .iter()
            .map(toml_to_json_value)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        toml::Value::Table(table) => table
            .iter()
            .map(|(key, value)| Ok((key.clone(), toml_to_json_value(value)?)))
            .collect::<Result<serde_json::Map<String, Value>, String>>()
            .map(Value::Object),
    }
}

fn run_bench_rust_driver(args: BenchDriverArgs, node_binary: &Path) -> Result<(), String> {
    let addresses = allocate_loopback_addresses(args.nodes)?;
    let addresses_json = serde_json::to_string(&addresses).map_err(|err| err.to_string())?;
    let hb_crypto_payloads =
        serialize_crypto_payloads(AcsBackendKind::PythonHb, args.nodes, args.faulty)?;
    let acs_crypto_payloads = serialize_crypto_payloads(args.acs_backend, args.nodes, args.faulty)?;
    let result_dir = build_result_dir("hb-rust-driver", &args.sid)?;
    let start_at_ms = current_time_millis()?
        .checked_add(5_000)
        .ok_or_else(|| String::from("start time overflow"))?;
    let mut processes = Vec::new();

    for pid in 0..args.nodes {
        let result_path = result_dir.join(format!("node-{pid}.json"));
        let stdout_path = result_dir.join(format!("node-{pid}.out.log"));
        let stderr_path = result_dir.join(format!("node-{pid}.err.log"));
        let stdout_handle = File::create(&stdout_path).map_err(|err| err.to_string())?;
        let stderr_handle = File::create(&stderr_path).map_err(|err| err.to_string())?;

        let child = node_command(node_binary)
            .arg("--pid")
            .arg(pid.to_string())
            .arg("--sid")
            .arg(&args.sid)
            .arg("--acs-backend")
            .arg(args.acs_backend.as_str())
            .arg("--nodes")
            .arg(args.nodes.to_string())
            .arg("--faulty")
            .arg(args.faulty.to_string())
            .arg("--rounds")
            .arg(args.rounds.to_string())
            .arg("--batch-size")
            .arg(args.batch_size.to_string())
            .arg("--global-timeout")
            .arg(args.global_timeout.to_string())
            .arg("--addresses-json")
            .arg(&addresses_json)
            .arg("--hb-crypto-json")
            .arg(&hb_crypto_payloads[pid])
            .arg("--acs-crypto-json")
            .arg(&acs_crypto_payloads[pid])
            .arg("--config-json")
            .arg(&args.config_json)
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
            let stderr = read_node_failure_summary(&process.result_path)
                .unwrap_or_else(|| read_log_file(&process.stderr_path));
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
            "benchmark timed out after {:.3}s before all rust-driver node results were written",
            args.global_timeout
        ));
    }
    if !errors.is_empty() {
        return Err(format!(
            "Rust-driver benchmark failed ({}): {}",
            failed_result_dir_hint(&result_dir),
            errors.join("; "),
        ));
    }

    let flattened = results
        .into_iter()
        .enumerate()
        .map(|(pid, value)| value.ok_or_else(|| format!("pid={pid}: missing decoded result")))
        .collect::<Result<Vec<_>, _>>()?;
    let rendered = serde_json::to_string(&flattened).map_err(|err| err.to_string())?;
    write_output(args.result_path.as_deref(), &rendered)?;
    let _ = fs::remove_dir_all(&result_dir);
    Ok(())
}

fn serialize_crypto_payloads(
    protocol: AcsBackendKind,
    nodes: usize,
    faulty: usize,
) -> Result<Vec<String>, String> {
    match protocol {
        AcsBackendKind::PythonHb => generate_hb_crypto_payloads_json(nodes, faulty),
        AcsBackendKind::PythonDumbo
        | AcsBackendKind::RustFin
        | AcsBackendKind::RustDumbo
        | AcsBackendKind::RustHb => generate_dumbo_crypto_payloads_json(nodes, faulty),
    }
}

fn allocate_loopback_addresses(num_nodes: usize) -> Result<Vec<(String, u16)>, String> {
    let mut listeners = Vec::with_capacity(num_nodes);
    for _ in 0..num_nodes {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|err| err.to_string())?;
        listeners.push(listener);
    }
    listeners
        .iter()
        .map(|listener| {
            listener
                .local_addr()
                .map(|addr| (String::from("127.0.0.1"), addr.port()))
                .map_err(|err| err.to_string())
        })
        .collect()
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

fn read_node_failure_summary(path: &Path) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    let parsed = serde_json::from_str::<Value>(&content).ok()?;
    if parsed.get("status").and_then(Value::as_str) != Some("error") {
        return None;
    }

    let error = parsed.get("error")?.as_object()?;
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("node failed");
    let kind = error
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let stage = error.get("stage").and_then(Value::as_str);
    let round_id = error.get("round_id").and_then(Value::as_u64);
    let host_stats_error = parsed.get("host_stats_error").and_then(Value::as_str);
    let shutdown_error = parsed.get("shutdown_error").and_then(Value::as_str);

    let mut summary = format!("failure_json kind={kind}: {message}");
    if let Some(round_id) = round_id {
        summary.push_str(&format!(" [round={round_id}]"));
    }
    if let Some(stage) = stage {
        summary.push_str(&format!(" [stage={stage}]"));
    }
    if let Some(host_stats_error) = host_stats_error {
        summary.push_str(&format!(" [host_stats_error={host_stats_error}]"));
    }
    if let Some(shutdown_error) = shutdown_error {
        summary.push_str(&format!(" [shutdown_error={shutdown_error}]"));
    }
    Some(summary)
}

fn failed_result_dir_hint(result_dir: &Path) -> String {
    format!("artifacts kept at {}", result_dir.display())
}

fn write_output(result_path: Option<&str>, rendered: &str) -> Result<(), String> {
    if let Some(result_path) = result_path {
        fs::write(result_path, rendered).map_err(|err| err.to_string())?;
    } else {
        println!("{rendered}");
    }
    Ok(())
}

fn debug_acs_driver(message: &str) {
    if std::env::var_os("HONEY_DEBUG_ACS").is_some() {
        eprintln!("[honey-bench] {message}");
    }
}

pub fn resolve_node_binary() -> Result<std::path::PathBuf, String> {
    if let Some(value) = std::env::var_os("HONEY_NODE_BINARY") {
        let path = std::path::PathBuf::from(value);
        if path.exists() {
            return Ok(path);
        }
        return Err(format!(
            "HONEY_NODE_BINARY points to missing path: {}",
            path.display()
        ));
    }
    let current = std::env::current_exe().map_err(|err| err.to_string())?;
    let sibling = current.with_file_name("honey-node");
    if sibling.exists() {
        return Ok(sibling);
    }
    let sibling_exe = current.with_file_name("honey-node.exe");
    if sibling_exe.exists() {
        return Ok(sibling_exe);
    }
    Err(format!(
        "could not locate honey-node; set HONEY_NODE_BINARY or build sibling binary at {}",
        sibling.display()
    ))
}
