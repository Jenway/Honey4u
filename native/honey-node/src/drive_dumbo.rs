use super::*;

/// Drive Dumbo BFT by spawning N independent `run-driver-node` OS subprocesses.
///
/// Each subprocess manages its own Python ACS host, TPKE key share, and TCP
/// connections. TPKE partial-decryption shares are exchanged directly between
/// sibling subprocesses over real TCP using the `HbShareBundle` wire frame,
/// matching the distributed `bench-driver` execution model.
fn run_drive_dumbo_multiprocess(args: &DriveDumboArgs) -> Result<String, String> {
    if args.tx_json.is_some() {
        return Err(String::from(
            "drive-dumbo-mp does not support --tx-json; only deterministic per-node dummy transactions are supported",
        ));
    }
    let config: Value = serde_json::from_str(&args.config_json).map_err(|e| e.to_string())?;
    let enable_pool_reuse = config
        .get("enable_broadcast_pool_reuse")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    debug_drive_acs("dumbo-mp:serialize_hb_crypto_payloads:start");
    let hb_crypto_payloads =
        serialize_crypto_payloads(Protocol::HoneyBadger, args.nodes, args.faulty)?;
    debug_drive_acs("dumbo-mp:serialize_hb_crypto_payloads:done");

    debug_drive_acs("dumbo-mp:serialize_acs_crypto_payloads:start");
    let acs_crypto_payloads = serialize_crypto_payloads(Protocol::Dumbo, args.nodes, args.faulty)?;
    debug_drive_acs("dumbo-mp:serialize_acs_crypto_payloads:done");

    let addresses = allocate_loopback_addresses(args.nodes)?;
    let addresses_json = serde_json::to_string(&addresses).map_err(|e| e.to_string())?;

    let result_dir = build_result_dir("drive-dumbo-mp", &args.sid)?;
    let start_at_ms = current_time_millis()?
        .checked_add(5_000)
        .ok_or_else(|| String::from("drive-dumbo-mp: start time overflow"))?;

    let binary = std::env::current_exe()
        .map_err(|e| format!("drive-dumbo-mp: cannot determine binary path: {e}"))?;

    let mut processes: Vec<SpawnedNode> = Vec::with_capacity(args.nodes);
    for pid in 0..args.nodes {
        let result_path = result_dir.join(format!("node-{pid}.json"));
        let stdout_path = result_dir.join(format!("node-{pid}.out.log"));
        let stderr_path = result_dir.join(format!("node-{pid}.err.log"));
        let stdout_hdl = File::create(&stdout_path)
            .map_err(|e| format!("drive-dumbo-mp pid={pid}: stdout log: {e}"))?;
        let stderr_hdl = File::create(&stderr_path)
            .map_err(|e| format!("drive-dumbo-mp pid={pid}: stderr log: {e}"))?;

        let child = Command::new(&binary)
            .arg("run-driver-node")
            .arg("--pid")
            .arg(pid.to_string())
            .arg("--sid")
            .arg(&args.sid)
            .arg("--acs-protocol")
            .arg("dumbo")
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
            .stdout(Stdio::from(stdout_hdl))
            .stderr(Stdio::from(stderr_hdl))
            .spawn()
            .map_err(|e| format!("drive-dumbo-mp: spawn pid={pid}: {e}"))?;

        processes.push(SpawnedNode {
            pid,
            child,
            result_path,
            stderr_path,
        });
    }

    let deadline = Instant::now() + Duration::from_secs_f64(args.global_timeout + 10.0);
    while Instant::now() < deadline {
        if processes.iter().all(|p| p.result_path.exists()) {
            break;
        }
        let mut any_failed = false;
        for process in &mut processes {
            if let Some(status) = process.child.try_wait().map_err(|e| e.to_string())?
                && !status.success()
            {
                any_failed = true;
                break;
            }
        }
        if any_failed {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }

    let all_ready = processes.iter().all(|p| p.result_path.exists());
    let mut errors: Vec<String> = Vec::new();
    let mut node_jsons: Vec<Option<Value>> = (0..args.nodes).map(|_| None).collect();

    for process in &mut processes {
        let status = match process.child.try_wait().map_err(|e| e.to_string())? {
            Some(s) => s,
            None if all_ready => process.child.wait().map_err(|e| e.to_string())?,
            None => {
                let _ = process.child.kill();
                process.child.wait().map_err(|e| e.to_string())?
            }
        };
        if !status.success() {
            let stderr = read_log_file(&process.stderr_path);
            errors.push(format!(
                "pid={}: rc={}: {}",
                process.pid,
                status.code().unwrap_or(-1),
                stderr.trim()
            ));
            continue;
        }
        if !process.result_path.exists() {
            let stderr = read_log_file(&process.stderr_path);
            errors.push(format!(
                "pid={}: result file missing: {}",
                process.pid,
                stderr.trim()
            ));
            continue;
        }
        let content = fs::read_to_string(&process.result_path)
            .map_err(|e| format!("pid={}: read: {e}", process.pid))?;
        let parsed = serde_json::from_str::<Value>(&content)
            .map_err(|e| format!("pid={}: parse JSON: {e}", process.pid))?;
        node_jsons[process.pid] = Some(parsed);
    }

    if !all_ready && errors.is_empty() {
        errors.push(format!(
            "drive-dumbo-mp timed out after {:.3}s",
            args.global_timeout
        ));
    }
    if !errors.is_empty() {
        let _ = fs::remove_dir_all(&result_dir);
        return Err(format!("drive-dumbo-mp failed: {}", errors.join("; ")));
    }

    let node_jsons: Vec<Value> = node_jsons
        .into_iter()
        .enumerate()
        .map(|(pid, value)| value.ok_or_else(|| format!("pid={pid}: missing result")))
        .collect::<Result<_, _>>()?;

    let canonical = &node_jsons[0];
    let canonical_rounds = canonical
        .get("round_details")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let canonical_chain = canonical
        .get("chain_digest")
        .and_then(Value::as_str)
        .unwrap_or("");

    for node_json in node_jsons.iter().skip(1) {
        let node_chain = node_json
            .get("chain_digest")
            .and_then(Value::as_str)
            .unwrap_or("");
        if node_chain != canonical_chain {
            let _ = fs::remove_dir_all(&result_dir);
            return Err(format!(
                "drive-dumbo-mp: chain_digest diverged: node0={canonical_chain} vs node_other={node_chain}"
            ));
        }
    }

    if let Some(dir) = &args.ledger_dir {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("drive-dumbo-mp: create ledger dir '{dir}': {e}"))?;
    }

    let rounds: Vec<Value> = canonical_rounds
        .iter()
        .enumerate()
        .map(|(round_id, canonical_round)| {
            let selected_pids = canonical_round
                .get("selected_pids")
                .and_then(Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|value| value.as_u64().map(|v| v as usize))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let selected_count = selected_pids.len();
            let delivered_count = canonical_round
                .get("delivered_count")
                .and_then(Value::as_u64)
                .map(|value| value as usize)
                .unwrap_or(0);
            let wall_seconds = canonical_round
                .get("wall_seconds")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let block_digest = canonical_round
                .get("block_digest")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let chain_digest = canonical_round
                .get("chain_digest")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let build_seconds = canonical_round
                .get("build_seconds")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let acs_seconds = canonical_round
                .get("acs_seconds")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let tpke_seconds = canonical_round
                .get("tpke_seconds")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let block_size = canonical_round
                .get("block_size")
                .and_then(Value::as_u64)
                .map(|value| value as usize)
                .unwrap_or(0);
            let mut acs_send_events = 0usize;
            for node_json in &node_jsons {
                let node_round = node_json
                    .get("round_details")
                    .and_then(Value::as_array)
                    .and_then(|rounds| rounds.get(round_id));
                if let Some(node_round) = node_round {
                    acs_send_events += node_round
                        .get("acs_outbound_events")
                        .and_then(Value::as_u64)
                        .map(|value| value as usize)
                        .unwrap_or(0);
                }
            }

            if let Some(dir) = &args.ledger_dir {
                let block_path =
                    std::path::Path::new(dir).join(format!("block_{round_id:06}.json"));
                let entry = json!({
                    "round_id": round_id,
                    "chain_digest": chain_digest,
                    "block_digest": block_digest,
                    "delivered_count": delivered_count,
                    "selected_count": selected_count,
                    "selected_pids": selected_pids,
                    "wall_seconds": wall_seconds,
                });
                let _ = std::fs::write(&block_path, entry.to_string());
            }

            json!({
                "round_id": round_id,
                "selected_count": selected_count,
                "delivered_count": delivered_count,
                "selected_pids": selected_pids,
                "acs_send_events": acs_send_events,
                "tpke_bundle_events": args.nodes,
                "block_size": block_size,
                "block_digest": block_digest,
                "chain_digest": chain_digest,
                "build_seconds": build_seconds,
                "acs_seconds": acs_seconds,
                "tpke_seconds": tpke_seconds,
                "block_resolve_seconds": 0.0,
                "wall_seconds": wall_seconds,
                "acs_drive_stats": canonical_round
                    .get("driver_phase_stats")
                    .cloned()
                    .unwrap_or_else(|| json!({})),
                "acs_settle_stats": {},
            })
        })
        .collect();

    let nodes_out: Vec<Value> = node_jsons
        .iter()
        .enumerate()
        .map(|(pid, node_json)| {
            let host_stats = node_json.get("host_stats").cloned().unwrap_or(json!({}));
            let transport_stats = node_json.get("transport_stats").cloned().unwrap_or(json!({}));
            json!({
                "pid": pid,
                "worker_ident": host_stats["worker_ident"].as_u64().unwrap_or(0),
                "rounds_started": host_stats["rounds_started"].as_u64().unwrap_or(0),
                "rounds_finished": host_stats["rounds_finished"].as_u64().unwrap_or(0),
                "processed_commands": host_stats["processed_commands"].as_u64().unwrap_or(0),
                "start_round_calls": host_stats["start_round_calls"].as_u64().unwrap_or(0),
                "push_inbound_batch_calls": host_stats["push_inbound_batch_calls"].as_u64().unwrap_or(0),
                "push_inbound_batch_items": host_stats["push_inbound_batch_items"].as_u64().unwrap_or(0),
                "push_inbound_wire_batch_calls": host_stats["push_inbound_wire_batch_calls"].as_u64().unwrap_or(0),
                "push_inbound_wire_batch_items": host_stats["push_inbound_wire_batch_items"].as_u64().unwrap_or(0),
                "pull_outbound_batch_calls": host_stats["pull_outbound_batch_calls"].as_u64().unwrap_or(0),
                "pull_outbound_batch_items": host_stats["pull_outbound_batch_items"].as_u64().unwrap_or(0),
                "pull_outbound_wire_batch_calls": host_stats["pull_outbound_wire_batch_calls"].as_u64().unwrap_or(0),
                "pull_outbound_wire_batch_items": host_stats["pull_outbound_wire_batch_items"].as_u64().unwrap_or(0),
                "exchange_batches_calls": host_stats["exchange_batches_calls"].as_u64().unwrap_or(0),
                "exchange_inbound_items": host_stats["exchange_inbound_items"].as_u64().unwrap_or(0),
                "exchange_outbound_items": host_stats["exchange_outbound_items"].as_u64().unwrap_or(0),
                "stats_calls": host_stats["stats_calls"].as_u64().unwrap_or(0),
                "bridge_queue_size": host_stats["bridge_queue_size"].as_u64().unwrap_or(0),
                "worker_running": host_stats["worker_running"].as_bool().unwrap_or(false),
                "worker_error": host_stats.get("worker_error"),
                "exchange_deliver_seconds": host_stats["exchange_deliver_seconds"].as_f64().unwrap_or(0.0),
                "exchange_pump_seconds": host_stats["exchange_pump_seconds"].as_f64().unwrap_or(0.0),
                "exchange_drain_seconds": host_stats["exchange_drain_seconds"].as_f64().unwrap_or(0.0),
                "exchange_total_seconds": host_stats["exchange_total_seconds"].as_f64().unwrap_or(0.0),
                "mempool_size": 0u64,
                "transport_sent_frames": transport_stats["sent_frames"].as_u64().unwrap_or(0),
                "transport_recv_frames": transport_stats["recv_frames"].as_u64().unwrap_or(0),
                "transport_connect_retries": transport_stats["connect_retries"].as_u64().unwrap_or(0),
            })
        })
        .collect();

    let _ = fs::remove_dir_all(&result_dir);

    serde_json::to_string(&json!({
        "protocol": "dumbo",
        "sid": args.sid,
        "nodes_count": args.nodes,
        "faulty": args.faulty,
        "enable_pool_reuse": enable_pool_reuse,
        "has_tpke": true,
        "transport": "tcp-loopback-mp",
        "chain_digest": canonical_chain,
        "nodes": nodes_out,
        "rounds": rounds,
    }))
    .map_err(|e| e.to_string())
}

pub(crate) fn run_drive_dumbo(args: DriveDumboArgs) -> Result<(), String> {
    let rendered = run_drive_dumbo_multiprocess(&args)?;
    write_output(args.result_path.as_deref(), &rendered)
}
