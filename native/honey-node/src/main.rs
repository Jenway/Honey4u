use pyo3::prelude::*;
use pyo3::types::{PyList, PyModule};
use std::fs;
use std::path::PathBuf;

#[derive(Clone, Copy)]
enum Protocol {
    HoneyBadger,
    Dumbo,
}

struct CliArgs {
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args(std::env::args())?;
    run_rust_hosted_node(args)?;
    Ok(())
}

fn parse_args<I>(mut argv: I) -> Result<CliArgs, String>
where
    I: Iterator<Item = String>,
{
    let _bin = argv.next();
    let mut protocol = Protocol::HoneyBadger;
    let mut pid = 0usize;
    let mut nodes = 4usize;
    let mut faulty = 1usize;
    let mut rounds = 1usize;
    let mut sid = String::from("embedded:hb");
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
                let value = argv
                    .next()
                    .ok_or_else(|| String::from("--protocol requires a value"))?;
                protocol = match value.as_str() {
                    "hb" | "honeybadger" => Protocol::HoneyBadger,
                    "dumbo" => Protocol::Dumbo,
                    _ => return Err(format!("unsupported protocol: {value}")),
                };
            }
            "--pid" => {
                let value = argv
                    .next()
                    .ok_or_else(|| String::from("--pid requires a value"))?;
                pid = value
                    .parse::<usize>()
                    .map_err(|_| format!("invalid --pid value: {value}"))?;
            }
            "--nodes" => {
                let value = argv
                    .next()
                    .ok_or_else(|| String::from("--nodes requires a value"))?;
                nodes = value
                    .parse::<usize>()
                    .map_err(|_| format!("invalid --nodes value: {value}"))?;
            }
            "--faulty" => {
                let value = argv
                    .next()
                    .ok_or_else(|| String::from("--faulty requires a value"))?;
                faulty = value
                    .parse::<usize>()
                    .map_err(|_| format!("invalid --faulty value: {value}"))?;
            }
            "--rounds" => {
                let value = argv
                    .next()
                    .ok_or_else(|| String::from("--rounds requires a value"))?;
                rounds = value
                    .parse::<usize>()
                    .map_err(|_| format!("invalid --rounds value: {value}"))?;
            }
            "--sid" => {
                sid = argv
                    .next()
                    .ok_or_else(|| String::from("--sid requires a value"))?;
            }
            "--addresses-json" => {
                addresses_json = Some(
                    argv.next()
                        .ok_or_else(|| String::from("--addresses-json requires a value"))?,
                );
            }
            "--crypto-json" => {
                crypto_json = Some(
                    argv.next()
                        .ok_or_else(|| String::from("--crypto-json requires a value"))?,
                );
            }
            "--config-json" => {
                config_json = Some(
                    argv.next()
                        .ok_or_else(|| String::from("--config-json requires a value"))?,
                );
            }
            "--transactions-per-node" => {
                let value = argv
                    .next()
                    .ok_or_else(|| String::from("--transactions-per-node requires a value"))?;
                transactions_per_node = value
                    .parse::<usize>()
                    .map_err(|_| format!("invalid --transactions-per-node value: {value}"))?;
            }
            "--tx-input" => {
                tx_input = argv
                    .next()
                    .ok_or_else(|| String::from("--tx-input requires a value"))?;
            }
            "--start-at-ms" => {
                let value = argv
                    .next()
                    .ok_or_else(|| String::from("--start-at-ms requires a value"))?;
                start_at_ms = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| format!("invalid --start-at-ms value: {value}"))?,
                );
            }
            "--result-path" => {
                result_path = Some(
                    argv.next()
                        .ok_or_else(|| String::from("--result-path requires a value"))?,
                );
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

    Ok(CliArgs {
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

fn protocol_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::HoneyBadger => "hb",
        Protocol::Dumbo => "dumbo",
    }
}

fn run_rust_hosted_node(args: CliArgs) -> PyResult<()> {
    Python::attach(|py| {
        let sys = PyModule::import(py, "sys")?;
        let path = sys.getattr("path")?.cast_into::<PyList>()?;
        for candidate in venv_site_packages_candidates() {
            path.insert(0, candidate)?;
        }
        path.insert(0, ".")?;
        path.insert(0, "src")?;

        let rust_host = PyModule::import(py, "honey.runtime.rust_host")?;
        let result = rust_host.getattr("run_protocol_node")?.call1((
            protocol_name(args.protocol),
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
        if let Some(result_path) = args.result_path {
            fs::write(result_path, &rendered)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        } else {
            println!("{rendered}");
        }
        Ok(())
    })
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
