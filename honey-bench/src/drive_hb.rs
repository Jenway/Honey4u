use super::*;
use honey_wire::phase_stats::{aggregate_driver_phase_stats, driver_phase_stats_from_value};

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

fn json_array_field<'a>(value: &'a Value, key: &str) -> Result<&'a [Value], String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| format!("missing array field: {key}"))
}

fn json_object_field<'a>(
    value: &'a Value,
    key: &str,
) -> Result<&'a serde_json::Map<String, Value>, String> {
    value
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("missing object field: {key}"))
}

fn json_usize_field(value: &Value, key: &str) -> Result<usize, String> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .map(|v| v as usize)
        .ok_or_else(|| format!("missing usize field: {key}"))
}

fn json_f64_field(value: &Value, key: &str) -> Result<f64, String> {
    value
        .get(key)
        .and_then(Value::as_f64)
        .ok_or_else(|| format!("missing f64 field: {key}"))
}

fn json_string_owned_field(value: &Value, key: &str) -> Result<String, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("missing string field: {key}"))
}

fn run_drive_honeybadger_multiprocess(
    args: &BenchHoneyBadgerArgs,
    node_binary: &Path,
) -> Result<String, String> {
    debug_acs_driver("hb-mp:serialize_hb_crypto_payloads:start");
    let hb_crypto_payloads = serialize_hb_crypto_payloads(args.nodes, args.faulty)?;
    debug_acs_driver("hb-mp:serialize_hb_crypto_payloads:done");
    let acs_crypto_payloads = if !args.acs_backend.is_dumbo() {
        hb_crypto_payloads.clone()
    } else {
        debug_acs_driver("hb-mp:serialize_acs_crypto_payloads:start");
        let payloads = serialize_crypto_payloads(args.acs_backend, args.nodes, args.faulty)?;
        debug_acs_driver("hb-mp:serialize_acs_crypto_payloads:done");
        payloads
    };

    let addresses = allocate_loopback_addresses(args.nodes)?;
    let addresses_json = serde_json::to_string(&addresses).map_err(|err| err.to_string())?;
    let result_dir = build_result_dir("bench-driver-hb-mp", &args.sid)?;
    let start_at_ms = current_time_millis()?
        .checked_add(5_000)
        .ok_or_else(|| String::from("bench-driver:hb: start time overflow"))?;
    let binary = node_binary;

    let mut processes: Vec<SpawnedNode> = Vec::with_capacity(args.nodes);
    for pid in 0..args.nodes {
        let result_path = result_dir.join(format!("node-{pid}.json"));
        let stdout_path = result_dir.join(format!("node-{pid}.out.log"));
        let stderr_path = result_dir.join(format!("node-{pid}.err.log"));
        let stdout_handle = File::create(&stdout_path)
            .map_err(|err| format!("bench-driver:hb pid={pid}: stdout log: {err}"))?;
        let stderr_handle = File::create(&stderr_path)
            .map_err(|err| format!("bench-driver:hb pid={pid}: stderr log: {err}"))?;

        let child = node_command(binary)
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
            .map_err(|err| format!("bench-driver:hb: spawn pid={pid}: {err}"))?;

        processes.push(SpawnedNode {
            pid,
            child,
            result_path,
            stderr_path,
        });
    }

    let deadline = Instant::now() + Duration::from_secs_f64(args.global_timeout + 10.0);
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
    let mut node_jsons: Vec<Option<Value>> = (0..args.nodes).map(|_| None).collect();

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
            "bench-driver:hb timed out after {:.3}s",
            args.global_timeout
        ));
    }

    if !errors.is_empty() {
        return Err(format!(
            "bench-driver:hb failed ({}): {}",
            failed_result_dir_hint(&result_dir),
            errors.join("; "),
        ));
    }

    let node_jsons = node_jsons
        .into_iter()
        .enumerate()
        .map(|(pid, value)| value.ok_or_else(|| format!("pid={pid}: missing decoded result")))
        .collect::<Result<Vec<_>, _>>()?;

    let canonical = &node_jsons[0];
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
            return Err(format!(
                "bench-driver:hb: chain_digest diverged: node0={canonical_chain} vs node_other={node_chain} ({})",
                failed_result_dir_hint(&result_dir),
            ));
        }
    }

    let canonical_rounds = json_array_field(canonical, "round_details")?;
    let rounds = canonical_rounds
        .iter()
        .enumerate()
        .map(|(round_id, canonical_round)| -> Result<Value, String> {
            let canonical_selected = json_array_field(canonical_round, "selected_pids")?
                .iter()
                .map(|value| {
                    value
                        .as_u64()
                        .map(|v| v as usize)
                        .ok_or_else(|| String::from("invalid selected pid"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let canonical_block_digest = json_string_owned_field(canonical_round, "block_digest")?;
            let canonical_chain_digest = json_string_owned_field(canonical_round, "chain_digest")?;

            let mut build_seconds = 0.0f64;
            let mut acs_seconds = 0.0f64;
            let mut tpke_seconds = 0.0f64;
            let mut protocol_seconds = 0.0f64;
            let mut wall_seconds = 0.0f64;
            let mut tpke_local_share_seconds = 0.0f64;
            let mut tpke_combine_seconds = 0.0f64;
            let mut acs_send_events = 0usize;
            let mut delivered_count = usize::MAX;
            let mut driver_stats = Vec::with_capacity(node_jsons.len());

            for (pid, node_json) in node_jsons.iter().enumerate() {
                let node_rounds = json_array_field(node_json, "round_details")?;
                let node_round = node_rounds.get(round_id).ok_or_else(|| {
                    format!("bench-driver:hb: pid={pid} missing round detail {round_id}")
                })?;
                let node_selected = json_array_field(node_round, "selected_pids")?
                    .iter()
                    .map(|value| {
                        value
                            .as_u64()
                            .map(|v| v as usize)
                            .ok_or_else(|| String::from("invalid selected pid"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let node_block_digest = json_string_owned_field(node_round, "block_digest")?;
                let node_chain_digest = json_string_owned_field(node_round, "chain_digest")?;
                if node_selected != canonical_selected {
                    return Err(format!(
                        "bench-driver:hb: round {round_id} selected_pids diverged at pid={pid}"
                    ));
                }
                if node_block_digest != canonical_block_digest {
                    return Err(format!(
                        "bench-driver:hb: round {round_id} block_digest diverged at pid={pid}"
                    ));
                }
                if node_chain_digest != canonical_chain_digest {
                    return Err(format!(
                        "bench-driver:hb: round {round_id} chain_digest diverged at pid={pid}"
                    ));
                }

                build_seconds = build_seconds.max(json_f64_field(node_round, "build_seconds")?);
                acs_seconds = acs_seconds.max(json_f64_field(node_round, "acs_seconds")?);
                tpke_seconds = tpke_seconds.max(json_f64_field(node_round, "tpke_seconds")?);
                protocol_seconds =
                    protocol_seconds.max(json_f64_field(node_round, "protocol_seconds")?);
                wall_seconds = wall_seconds.max(json_f64_field(node_round, "wall_seconds")?);
                tpke_local_share_seconds = tpke_local_share_seconds
                    .max(json_f64_field(node_round, "tpke_partial_open_seconds")?);
                tpke_combine_seconds =
                    tpke_combine_seconds.max(json_f64_field(node_round, "tpke_combine_seconds")?);
                acs_send_events += json_usize_field(node_round, "acs_outbound_events")?;
                delivered_count =
                    delivered_count.min(json_usize_field(node_round, "delivered_count")?);
                driver_stats.push(driver_phase_stats_from_value(
                    node_round.get("driver_phase_stats").ok_or_else(|| {
                        format!(
                            "bench-driver:hb: round {round_id} missing driver_phase_stats at pid={pid}"
                        )
                    })?,
                )?);
            }

            if delivered_count == usize::MAX {
                delivered_count = 0;
            }

            let aggregated_drive_stats = aggregate_driver_phase_stats(&driver_stats, args.nodes);

            Ok(json!({
                "round_id": round_id,
                "selected_count": canonical_selected.len(),
                "selected_pids": canonical_selected,
                "acs_send_events": acs_send_events,
                "acs_drive_stats": driver_phase_stats_json(&aggregated_drive_stats),
                "acs_settle_stats": driver_phase_stats_json(&DriverPhaseStats::default()),
                "tpke_bundle_events": args.nodes,
                "delivered_count": delivered_count,
                "block_size": json_usize_field(canonical_round, "block_size")?,
                "block_digest": canonical_block_digest,
                "chain_digest": canonical_chain_digest,
                "build_seconds": build_seconds,
                "acs_seconds": acs_seconds,
                "tpke_seconds": tpke_seconds,
                "tpke_local_share_seconds": tpke_local_share_seconds,
                "tpke_combine_seconds": tpke_combine_seconds,
                "protocol_seconds": protocol_seconds,
                "wall_seconds": wall_seconds,
            }))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let nodes = node_jsons
        .iter()
        .enumerate()
        .map(|(pid, node_json)| -> Result<Value, String> {
            let host_stats = Value::Object(json_object_field(node_json, "host_stats")?.clone());
            Ok(json!({
                "pid": pid,
                "worker_ident": json_usize_field(&host_stats, "worker_ident")?,
                "rounds_started": json_usize_field(&host_stats, "rounds_started")?,
                "rounds_finished": json_usize_field(&host_stats, "rounds_finished")?,
                "processed_commands": json_usize_field(&host_stats, "processed_commands")?,
                "start_round_calls": json_usize_field(&host_stats, "start_round_calls")?,
                "push_inbound_wire_batch_calls": json_usize_field(&host_stats, "push_inbound_wire_batch_calls")?,
                "push_inbound_wire_batch_items": json_usize_field(&host_stats, "push_inbound_wire_batch_items")?,
                "pull_outbound_wire_batch_calls": json_usize_field(&host_stats, "pull_outbound_wire_batch_calls")?,
                "pull_outbound_wire_batch_items": json_usize_field(&host_stats, "pull_outbound_wire_batch_items")?,
                "stats_calls": json_usize_field(&host_stats, "stats_calls")?,
                "bridge_queue_size": json_usize_field(&host_stats, "bridge_queue_size")?,
                "worker_running": host_stats.get("worker_running").and_then(Value::as_bool).unwrap_or(false),
                "worker_error": host_stats.get("worker_error").cloned().unwrap_or(Value::Null),
            }))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let _ = fs::remove_dir_all(&result_dir);

    serde_json::to_string(&json!({
        "protocol": "hb",
        "acs_backend": args.acs_backend.as_str(),
        "sid": args.sid,
        "transport": transport_label(&args.config_json),
        "chain_digest": canonical_chain,
        "nodes": nodes,
        "rounds": rounds,
    }))
    .map_err(|err| err.to_string())
}

pub fn run_drive_honeybadger(args: BenchHoneyBadgerArgs, node_binary: &Path) -> Result<(), String> {
    let rendered = run_drive_honeybadger_multiprocess(&args, node_binary)?;
    write_output(args.result_path.as_deref(), &rendered)
}
