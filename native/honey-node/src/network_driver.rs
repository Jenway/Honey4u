use super::*;
use honey_node::transport::LocalTcpTransport;
use serde_json::Value;

mod config;
mod result;
mod round;
mod types;
mod wire;

use config::{
    parse_broadcast_pool_config, parse_byzantine_node_config, parse_network_fault_config,
};
use result::build_node_result_json;
use round::{run_driver_rounds, wait_until_start};
use wire::parse_addresses_json;

pub(super) const DRIVER_NETWORK_BATCH_LIMIT: usize = 512;
pub(super) const DRIVER_IDLE_BACKOFF: Duration = Duration::from_micros(50);
pub(super) const BATCH_REF_TAG: u8 = 1;

pub(crate) fn run_rust_driver_node(args: RunDriverNodeArgs) -> Result<(), String> {
    let broadcast_pool_config = parse_broadcast_pool_config(&args.config_json)?;
    let network_fault_config = parse_network_fault_config(&args.config_json, args.pid)?;
    let byzantine_node_config = parse_byzantine_node_config(&args.config_json, args.pid)?;
    let addresses = parse_addresses_json(&args.addresses_json)?;
    let mut transport = LocalTcpTransport::new(args.pid, addresses, network_fault_config)
        .map_err(|err| err.to_string())?;
    let host = build_acs_host(
        args.acs_protocol,
        args.pid,
        args.nodes,
        args.faulty,
        &args.acs_crypto_json,
        &args.config_json,
    )?;
    let (public_key, private_share) = parse_honeybadger_crypto_payload(&args.hb_crypto_json)?;
    wait_until_start(args.start_at_ms)?;

    let result = run_driver_rounds(
        host.as_ref(),
        &transport,
        &public_key,
        &private_share,
        &args,
        &broadcast_pool_config,
        byzantine_node_config,
    );
    let host_stats = host.stats();
    let host_shutdown = host.shutdown();
    let rendered = match result {
        Ok((run_result, queue_peaks)) => {
            let host_stats = host_stats?;
            build_node_result_json(
                args.pid,
                args.batch_size,
                run_result,
                host_stats,
                &transport,
                &queue_peaks,
            )?
        }
        Err(err) => {
            let _ = transport.close();
            if let Err(shutdown_err) = host_shutdown {
                return Err(format!(
                    "{err}; driver host shutdown failed: {shutdown_err}"
                ));
            }
            return Err(err);
        }
    };

    transport.close().map_err(|err| err.to_string())?;
    host_shutdown?;
    write_output(args.result_path.as_deref(), &rendered)
}

pub(crate) fn run_bench_rust_driver(args: BenchDriverArgs) -> Result<(), String> {
    let addresses = allocate_loopback_addresses(args.nodes)?;
    let addresses_json = serde_json::to_string(&addresses).map_err(|err| err.to_string())?;
    let hb_crypto_payloads =
        serialize_crypto_payloads(Protocol::HoneyBadger, args.nodes, args.faulty)?;
    let acs_crypto_payloads =
        serialize_crypto_payloads(args.acs_protocol, args.nodes, args.faulty)?;
    let result_dir = build_result_dir("hb-rust-driver", &args.sid)?;
    let start_at_ms = current_time_millis()?
        .checked_add(5_000)
        .ok_or_else(|| String::from("start time overflow"))?;
    let binary = std::env::current_exe().map_err(|err| err.to_string())?;
    let mut processes = Vec::new();

    for pid in 0..args.nodes {
        let result_path = result_dir.join(format!("node-{pid}.json"));
        let stdout_path = result_dir.join(format!("node-{pid}.out.log"));
        let stderr_path = result_dir.join(format!("node-{pid}.err.log"));
        let stdout_handle = File::create(&stdout_path).map_err(|err| err.to_string())?;
        let stderr_handle = File::create(&stderr_path).map_err(|err| err.to_string())?;

        let child = Command::new(&binary)
            .arg("run-driver-node")
            .arg("--pid")
            .arg(pid.to_string())
            .arg("--sid")
            .arg(&args.sid)
            .arg("--acs-protocol")
            .arg(args.acs_protocol.as_str())
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
            "benchmark timed out after {:.3}s before all rust-driver node results were written",
            args.global_timeout
        ));
    }

    if !errors.is_empty() {
        let _ = fs::remove_dir_all(&result_dir);
        return Err(format!(
            "Rust-driver benchmark failed: {}",
            errors.join("; ")
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
