#![recursion_limit = "256"]

use honey_acs::AcsBackendKind;
#[cfg(not(feature = "python-backend"))]
use honey_node::keygen::generate_dumbo_crypto_payloads_json as generate_acs_crypto_payloads_json;
#[cfg(feature = "python-backend")]
use honey_node::keygen::generate_dumbo_crypto_payloads_json as generate_acs_crypto_payloads_json;
use honey_node::keygen::generate_hb_crypto_payloads_json;
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

pub use drive_dumbo::run_drive_dumbo_multiprocess;

const BENCH_RESULTS_DIR: &str = "honey-bench/results";
const BENCH_TMP_RESULTS_DIR: &str = "honey-bench/results/.tmp_multiprocess_results";

pub struct BenchHoneyBadgerArgs {
    pub sid: String,
    pub acs_backend: AcsBackendKind,
    pub nodes: usize,
    pub faulty: usize,
    pub rounds: usize,
    pub batch_size: usize,
    pub global_timeout: f64,
    pub config_json: String,
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
    if !cfg!(feature = "python-backend") {
        return;
    }
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
    protocol: AcsBackendKind,
    nodes: usize,
    faulty: usize,
) -> Result<Vec<String>, String> {
    match protocol {
        #[cfg(feature = "python-backend")]
        AcsBackendKind::PythonHb => generate_hb_crypto_payloads_json(nodes, faulty),
        #[cfg(feature = "python-backend")]
        AcsBackendKind::PythonDumbo => generate_acs_crypto_payloads_json(nodes, faulty),
        AcsBackendKind::RustFin | AcsBackendKind::RustDumbo | AcsBackendKind::RustHb => {
            generate_acs_crypto_payloads_json(nodes, faulty)
        }
    }
}

fn serialize_hb_crypto_payloads(nodes: usize, faulty: usize) -> Result<Vec<String>, String> {
    generate_hb_crypto_payloads_json(nodes, faulty)
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
