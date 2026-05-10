#![recursion_limit = "256"]

use honey_node::keygen::generate_dumbo_crypto_payloads_json as generate_acs_crypto_payloads_json;
use honey_node::keygen::generate_hb_crypto_payloads_json;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs::{self, File};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod drive;
pub mod stats;
pub mod suite;

pub use drive::run_drive_multiprocess;

const BENCH_RESULTS_DIR: &str = "honey-bench/results";
const BENCH_TMP_RESULTS_DIR: &str = "honey-bench/results/.tmp_multiprocess_results";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BinaryBuildInfo {
    pub package: String,
    pub version: String,
    pub quic: bool,
    pub python_backend: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BenchmarkProtocolFamily {
    HoneyBadger,
    Dumbo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BenchBackendKind {
    PythonHb,
    PythonDumbo,
    RustFin,
    RustDumbo,
    RustHb,
}

impl BenchBackendKind {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "python_hb" => Ok(Self::PythonHb),
            "python_dumbo" => Ok(Self::PythonDumbo),
            "rust" | "rust_fin" => Ok(Self::RustFin),
            "rust_dumbo" => Ok(Self::RustDumbo),
            "rust_hb" => Ok(Self::RustHb),
            other => Err(format!("unsupported acs_backend: {other}")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PythonHb => "python_hb",
            Self::PythonDumbo => "python_dumbo",
            Self::RustFin => "rust_fin",
            Self::RustDumbo => "rust_dumbo",
            Self::RustHb => "rust_hb",
        }
    }

    pub fn benchmark_protocol_family(self) -> BenchmarkProtocolFamily {
        match self {
            Self::PythonHb | Self::RustHb => BenchmarkProtocolFamily::HoneyBadger,
            Self::PythonDumbo | Self::RustFin | Self::RustDumbo => BenchmarkProtocolFamily::Dumbo,
        }
    }

    pub fn requires_python_backend(self) -> bool {
        matches!(self, Self::PythonHb | Self::PythonDumbo)
    }
}

pub struct BenchDriveArgs {
    pub sid: String,
    pub acs_backend: BenchBackendKind,
    pub nodes: usize,
    pub faulty: usize,
    pub rounds: usize,
    pub batch_size: usize,
    pub global_timeout: f64,
    pub config_json: String,
    pub ledger_dir: Option<String>,
    pub tx_json: Option<String>,
}

pub fn current_build_info() -> BinaryBuildInfo {
    BinaryBuildInfo {
        package: String::from("honey-bench"),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        quic: false,
        python_backend: false,
    }
}

pub fn current_build_info_json() -> String {
    serde_json::to_string(&current_build_info()).expect("build info JSON should serialize")
}

struct SpawnedNode {
    pid: usize,
    os_pid: u32,
    child: std::process::Child,
    result_path: PathBuf,
    stderr_path: PathBuf,
}

struct MultiprocessRunConfig<'a> {
    label: &'a str,
    node_binary: &'a Path,
    sid: &'a str,
    acs_backend: BenchBackendKind,
    nodes: usize,
    faulty: usize,
    rounds: usize,
    batch_size: usize,
    global_timeout: f64,
    config_json: &'a str,
    hb_crypto_payloads: &'a [String],
    acs_crypto_payloads: &'a [String],
}

struct CompletedNodeRun {
    result_dir: PathBuf,
    node_jsons: Vec<Value>,
    canonical_chain: String,
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

fn serialize_crypto_payloads(
    protocol: BenchBackendKind,
    nodes: usize,
    faulty: usize,
) -> Result<Vec<String>, String> {
    match protocol {
        BenchBackendKind::PythonHb => generate_hb_crypto_payloads_json(nodes, faulty),
        BenchBackendKind::PythonDumbo => generate_acs_crypto_payloads_json(nodes, faulty),
        BenchBackendKind::RustFin | BenchBackendKind::RustDumbo | BenchBackendKind::RustHb => {
            generate_acs_crypto_payloads_json(nodes, faulty)
        }
    }
}

fn serialize_hb_crypto_payloads(nodes: usize, faulty: usize) -> Result<Vec<String>, String> {
    generate_hb_crypto_payloads_json(nodes, faulty)
}

fn transport_label(config_json: &str) -> &'static str {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(config_json)
        && let Some(transport) = value.get("transport").and_then(|v| v.as_str())
    {
        return match transport {
            "quic" => "quic-loopback-mp",
            _ => "tcp-loopback-mp",
        };
    }
    "tcp-loopback-mp"
}

fn enable_pool_reuse(config_json: &str) -> Result<bool, String> {
    let config: Value = serde_json::from_str(config_json).map_err(|err| err.to_string())?;
    Ok(config
        .get("enable_broadcast_pool_reuse")
        .and_then(Value::as_bool)
        .unwrap_or(false))
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
    let scratch_root = PathBuf::from(BENCH_TMP_RESULTS_DIR);
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

#[cfg(target_os = "windows")]
fn kill_tree_command(parent_os_pid: u32) -> String {
    format!("taskkill /PID {parent_os_pid} /T /F")
}

#[cfg(not(target_os = "windows"))]
fn kill_tree_command(parent_os_pid: u32) -> String {
    format!("kill -TERM {parent_os_pid}")
}

fn log_spawned_workers(config: &MultiprocessRunConfig<'_>, processes: &[SpawnedNode]) {
    let worker_list = processes
        .iter()
        .map(|process| format!("node{}=os{}", process.pid, process.os_pid))
        .collect::<Vec<_>>()
        .join(",");
    eprintln!(
        "[workers] label={} sid={} bench_os_pid={} worker_pids={} kill_tree=\"{}\"",
        config.label,
        config.sid,
        std::process::id(),
        worker_list,
        kill_tree_command(std::process::id()),
    );
}

fn run_multiprocess_nodes(config: MultiprocessRunConfig<'_>) -> Result<CompletedNodeRun, String> {
    let addresses = allocate_loopback_addresses(config.nodes)?;
    let addresses_json = serde_json::to_string(&addresses).map_err(|err| err.to_string())?;
    let result_prefix = format!("bench-driver-{}-mp", config.label);
    let result_dir = build_result_dir(&result_prefix, config.sid)?;
    let start_at_ms = current_time_millis()?
        .checked_add(5_000)
        .ok_or_else(|| format!("bench-driver:{}: start time overflow", config.label))?;

    let mut processes: Vec<SpawnedNode> = Vec::with_capacity(config.nodes);
    for pid in 0..config.nodes {
        let result_path = result_dir.join(format!("node-{pid}.json"));
        let stdout_path = result_dir.join(format!("node-{pid}.out.log"));
        let stderr_path = result_dir.join(format!("node-{pid}.err.log"));
        let stdout_handle = File::create(&stdout_path)
            .map_err(|err| format!("bench-driver:{} pid={pid}: stdout log: {err}", config.label))?;
        let stderr_handle = File::create(&stderr_path)
            .map_err(|err| format!("bench-driver:{} pid={pid}: stderr log: {err}", config.label))?;

        let child = node_command(config.node_binary)
            .arg("--pid")
            .arg(pid.to_string())
            .arg("--sid")
            .arg(config.sid)
            .arg("--acs-backend")
            .arg(config.acs_backend.as_str())
            .arg("--nodes")
            .arg(config.nodes.to_string())
            .arg("--faulty")
            .arg(config.faulty.to_string())
            .arg("--rounds")
            .arg(config.rounds.to_string())
            .arg("--batch-size")
            .arg(config.batch_size.to_string())
            .arg("--global-timeout")
            .arg(config.global_timeout.to_string())
            .arg("--addresses-json")
            .arg(&addresses_json)
            .arg("--hb-crypto-json")
            .arg(&config.hb_crypto_payloads[pid])
            .arg("--acs-crypto-json")
            .arg(&config.acs_crypto_payloads[pid])
            .arg("--config-json")
            .arg(config.config_json)
            .arg("--start-at-ms")
            .arg(start_at_ms.to_string())
            .arg("--result-path")
            .arg(&result_path)
            .stdout(Stdio::from(stdout_handle))
            .stderr(Stdio::from(stderr_handle))
            .spawn()
            .map_err(|err| format!("bench-driver:{}: spawn pid={pid}: {err}", config.label))?;
        let os_pid = child.id();

        processes.push(SpawnedNode {
            pid,
            os_pid,
            child,
            result_path,
            stderr_path,
        });
    }
    log_spawned_workers(&config, &processes);

    let deadline = Instant::now() + Duration::from_secs_f64(config.global_timeout + 10.0);
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
    let mut node_jsons: Vec<Option<Value>> = (0..config.nodes).map(|_| None).collect();

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
        node_jsons[process.pid] = Some(parsed);
    }

    if !all_results_ready && errors.is_empty() {
        errors.push(format!(
            "bench-driver:{} timed out after {:.3}s",
            config.label, config.global_timeout
        ));
    }

    if !errors.is_empty() {
        return Err(format!(
            "bench-driver:{} failed ({}): {}",
            config.label,
            failed_result_dir_hint(&result_dir),
            errors.join("; "),
        ));
    }

    let node_jsons = node_jsons
        .into_iter()
        .enumerate()
        .map(|(pid, value)| value.ok_or_else(|| format!("pid={pid}: missing decoded result")))
        .collect::<Result<Vec<_>, _>>()?;
    let canonical = node_jsons
        .first()
        .ok_or_else(|| format!("bench-driver:{}: no node results", config.label))?;
    let canonical_chain = canonical
        .get("chain_digest")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();

    for node_json in node_jsons.iter().skip(1) {
        let node_chain = node_json
            .get("chain_digest")
            .and_then(Value::as_str)
            .unwrap_or("");
        if node_chain != canonical_chain {
            return Err(format!(
                "bench-driver:{}: chain_digest diverged: node0={} vs node_other={} ({})",
                config.label,
                canonical_chain,
                node_chain,
                failed_result_dir_hint(&result_dir),
            ));
        }
    }

    Ok(CompletedNodeRun {
        result_dir,
        node_jsons,
        canonical_chain,
    })
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

fn debug_acs_driver(message: &str) {
    if std::env::var_os("HONEY_DEBUG_ACS").is_some() {
        eprintln!("[honey-bench] {message}");
    }
}

pub(crate) fn suggested_node_build_command(node_binary: &Path, info: &BinaryBuildInfo) -> String {
    let profile = node_binary
        .parent()
        .and_then(|parent| parent.file_name())
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let mut command = String::from("cargo build -p honey-node");
    if profile.eq_ignore_ascii_case("release") {
        command.push_str(" --release");
    }
    let mut features = Vec::new();
    if info.quic {
        features.push("quic");
    }
    if info.python_backend {
        features.push("python-backend");
    }
    if !features.is_empty() {
        command.push_str(" --features \"");
        command.push_str(&features.join(" "));
        command.push('"');
    }
    command
}

pub(crate) fn format_build_info(info: &BinaryBuildInfo) -> String {
    let mut fields = vec![
        format!("package={}", info.package),
        format!("version={}", info.version),
    ];
    let mut features = Vec::new();
    if info.quic {
        features.push("quic");
    }
    if info.python_backend {
        features.push("python-backend");
    }
    if features.is_empty() {
        fields.push(String::from("features=[]"));
    } else {
        fields.push(format!("features=[{}]", features.join(",")));
    }
    fields.join(" ")
}

pub(crate) fn load_node_binary_build_info(node_binary: &Path) -> Result<BinaryBuildInfo, String> {
    let output = Command::new(node_binary)
        .arg("--print-build-info")
        .output()
        .map_err(|err| {
            format!(
                "failed to inspect node binary '{}': {err}",
                node_binary.display()
            )
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "node binary '{}' does not support build-info probing; stderr: {}",
            node_binary.display(),
            stderr.trim()
        ));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|err| format!("node binary build info was not valid UTF-8: {err}"))?;
    serde_json::from_str::<BinaryBuildInfo>(&stdout)
        .map_err(|err| format!("node binary build info was not valid JSON: {err}"))
}

pub fn validate_node_binary(node_binary: &Path) -> Result<(), String> {
    let actual = load_node_binary_build_info(node_binary).map_err(|message| {
        format!(
            "{message}\nrebuild sibling binaries with:\n  {}",
            suggested_node_build_command(node_binary, &BinaryBuildInfo::default())
        )
    })?;
    if actual.package != "honey-node" {
        return Err(format!(
            "node binary '{}' is not a honey-node executable: {}\nrebuild with:\n  {}",
            node_binary.display(),
            format_build_info(&actual),
            suggested_node_build_command(node_binary, &actual),
        ));
    }
    Ok(())
}

pub fn resolve_node_binary(explicit_path: Option<&Path>) -> Result<std::path::PathBuf, String> {
    if let Some(path) = explicit_path {
        if path.exists() {
            return Ok(path.to_path_buf());
        }
        return Err(format!(
            "--node-binary points to missing path: {}",
            path.display()
        ));
    }
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
    std::env::current_exe().map_err(|err| err.to_string())
}
