use super::*;
use crate::drive_acs::driver_phase_stats_json;

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

fn driver_host_phase_stats_from_value(value: &Value) -> Result<DriverHostPhaseStats, String> {
    Ok(DriverHostPhaseStats {
        pid: json_usize_field(value, "pid")?,
        push_calls: json_usize_field(value, "push_calls")?,
        push_items: json_usize_field(value, "push_items")?,
        max_push_batch: json_usize_field(value, "max_push_batch")?,
        push_seconds: json_f64_field(value, "push_seconds")?,
        pull_calls: json_usize_field(value, "pull_calls")?,
        empty_pull_calls: json_usize_field(value, "empty_pull_calls")?,
        pulled_events: json_usize_field(value, "pulled_events")?,
        max_pull_batch: json_usize_field(value, "max_pull_batch")?,
        pull_limit_hits: json_usize_field(value, "pull_limit_hits")?,
        pull_seconds: json_f64_field(value, "pull_seconds")?,
    })
}

fn driver_phase_stats_from_value(value: &Value) -> Result<DriverPhaseStats, String> {
    let host_stats = json_array_field(value, "host_stats")?
        .iter()
        .map(driver_host_phase_stats_from_value)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(DriverPhaseStats {
        sweep_count: json_usize_field(value, "sweep_count")?,
        active_sweeps: json_usize_field(value, "active_sweeps")?,
        idle_sweeps: json_usize_field(value, "idle_sweeps")?,
        idle_backoff_count: json_usize_field(value, "idle_backoff_count")?,
        total_pending_deliveries: json_usize_field(value, "total_pending_deliveries")?,
        max_pending_deliveries: json_usize_field(value, "max_pending_deliveries")?,
        total_pushed_items: json_usize_field(value, "total_pushed_items")?,
        total_pulled_events: json_usize_field(value, "total_pulled_events")?,
        max_pull_batch: json_usize_field(value, "max_pull_batch")?,
        pull_limit_hits: json_usize_field(value, "pull_limit_hits")?,
        total_push_seconds: json_f64_field(value, "total_push_seconds")?,
        total_pull_seconds: json_f64_field(value, "total_pull_seconds")?,
        send_events: value
            .get("send_events")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize,
        send_payload_bytes: value
            .get("send_payload_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize,
        decision_events: value
            .get("decision_events")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize,
        failure_events: value
            .get("failure_events")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize,
        carryover_events: value
            .get("carryover_events")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize,
        broadcast_output_events: value
            .get("broadcast_output_events")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize,
        broadcast_output_payload_bytes: value
            .get("broadcast_output_payload_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize,
        broadcast_output_roothash_bytes: value
            .get("broadcast_output_roothash_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize,
        host_stats,
    })
}

fn aggregate_driver_phase_stats(
    stats_by_node: &[DriverPhaseStats],
    host_count: usize,
) -> DriverPhaseStats {
    let mut aggregated = DriverPhaseStats {
        host_stats: (0..host_count)
            .map(|pid| DriverHostPhaseStats {
                pid,
                ..DriverHostPhaseStats::default()
            })
            .collect(),
        ..DriverPhaseStats::default()
    };

    for stats in stats_by_node {
        aggregated.sweep_count += stats.sweep_count;
        aggregated.active_sweeps += stats.active_sweeps;
        aggregated.idle_sweeps += stats.idle_sweeps;
        aggregated.idle_backoff_count += stats.idle_backoff_count;
        aggregated.total_pending_deliveries += stats.total_pending_deliveries;
        aggregated.max_pending_deliveries = aggregated
            .max_pending_deliveries
            .max(stats.max_pending_deliveries);
        aggregated.total_pushed_items += stats.total_pushed_items;
        aggregated.total_pulled_events += stats.total_pulled_events;
        aggregated.max_pull_batch = aggregated.max_pull_batch.max(stats.max_pull_batch);
        aggregated.pull_limit_hits += stats.pull_limit_hits;
        aggregated.total_push_seconds += stats.total_push_seconds;
        aggregated.total_pull_seconds += stats.total_pull_seconds;
        aggregated.send_events += stats.send_events;
        aggregated.send_payload_bytes += stats.send_payload_bytes;
        aggregated.decision_events += stats.decision_events;
        aggregated.failure_events += stats.failure_events;
        aggregated.carryover_events += stats.carryover_events;
        aggregated.broadcast_output_events += stats.broadcast_output_events;
        aggregated.broadcast_output_payload_bytes += stats.broadcast_output_payload_bytes;
        aggregated.broadcast_output_roothash_bytes += stats.broadcast_output_roothash_bytes;

        for (index, host_stats) in stats.host_stats.iter().enumerate() {
            let aggregated_host = &mut aggregated.host_stats[index];
            aggregated_host.push_calls += host_stats.push_calls;
            aggregated_host.push_items += host_stats.push_items;
            aggregated_host.max_push_batch = aggregated_host
                .max_push_batch
                .max(host_stats.max_push_batch);
            aggregated_host.push_seconds += host_stats.push_seconds;
            aggregated_host.pull_calls += host_stats.pull_calls;
            aggregated_host.empty_pull_calls += host_stats.empty_pull_calls;
            aggregated_host.pulled_events += host_stats.pulled_events;
            aggregated_host.max_pull_batch = aggregated_host
                .max_pull_batch
                .max(host_stats.max_pull_batch);
            aggregated_host.pull_limit_hits += host_stats.pull_limit_hits;
            aggregated_host.pull_seconds += host_stats.pull_seconds;
        }
    }

    aggregated
}

fn run_drive_honeybadger_multiprocess(args: &DriveHoneyBadgerArgs) -> Result<String, String> {
    debug_drive_acs("hb-mp:serialize_hb_crypto_payloads:start");
    let hb_crypto_payloads =
        serialize_crypto_payloads(Protocol::HoneyBadger, args.nodes, args.faulty)?;
    debug_drive_acs("hb-mp:serialize_hb_crypto_payloads:done");
    let acs_crypto_payloads = if matches!(args.acs_protocol, Protocol::HoneyBadger) {
        hb_crypto_payloads.clone()
    } else {
        debug_drive_acs("hb-mp:serialize_acs_crypto_payloads:start");
        let payloads = serialize_crypto_payloads(args.acs_protocol, args.nodes, args.faulty)?;
        debug_drive_acs("hb-mp:serialize_acs_crypto_payloads:done");
        payloads
    };

    let addresses = allocate_loopback_addresses(args.nodes)?;
    let addresses_json = serde_json::to_string(&addresses).map_err(|err| err.to_string())?;
    let result_dir = build_result_dir("drive-hb-mp", &args.sid)?;
    let start_at_ms = current_time_millis()?
        .checked_add(5_000)
        .ok_or_else(|| String::from("drive-hb-mp: start time overflow"))?;
    let binary = std::env::current_exe()
        .map_err(|err| format!("drive-hb-mp: cannot determine binary path: {err}"))?;

    let mut processes: Vec<SpawnedNode> = Vec::with_capacity(args.nodes);
    for pid in 0..args.nodes {
        let result_path = result_dir.join(format!("node-{pid}.json"));
        let stdout_path = result_dir.join(format!("node-{pid}.out.log"));
        let stderr_path = result_dir.join(format!("node-{pid}.err.log"));
        let stdout_handle = File::create(&stdout_path)
            .map_err(|err| format!("drive-hb-mp pid={pid}: stdout log: {err}"))?;
        let stderr_handle = File::create(&stderr_path)
            .map_err(|err| format!("drive-hb-mp pid={pid}: stderr log: {err}"))?;

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
            .map_err(|err| format!("drive-hb-mp: spawn pid={pid}: {err}"))?;

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
        node_jsons[process.pid] = Some(parsed);
    }

    if !all_results_ready && errors.is_empty() {
        errors.push(format!(
            "drive-hb-mp timed out after {:.3}s",
            args.global_timeout
        ));
    }

    if !errors.is_empty() {
        let _ = fs::remove_dir_all(&result_dir);
        return Err(format!("drive-hb-mp failed: {}", errors.join("; ")));
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
            let _ = fs::remove_dir_all(&result_dir);
            return Err(format!(
                "drive-hb-mp: chain_digest diverged: node0={canonical_chain} vs node_other={node_chain}"
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
                    format!("drive-hb-mp: pid={pid} missing round detail {round_id}")
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
                        "drive-hb-mp: round {round_id} selected_pids diverged at pid={pid}"
                    ));
                }
                if node_block_digest != canonical_block_digest {
                    return Err(format!(
                        "drive-hb-mp: round {round_id} block_digest diverged at pid={pid}"
                    ));
                }
                if node_chain_digest != canonical_chain_digest {
                    return Err(format!(
                        "drive-hb-mp: round {round_id} chain_digest diverged at pid={pid}"
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
                            "drive-hb-mp: round {round_id} missing driver_phase_stats at pid={pid}"
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
        "acs_protocol": args.acs_protocol.as_str(),
        "sid": args.sid,
        "transport": "tcp-loopback-mp",
        "chain_digest": canonical_chain,
        "nodes": nodes,
        "rounds": rounds,
    }))
    .map_err(|err| err.to_string())
}

pub(crate) fn run_drive_honeybadger(args: DriveHoneyBadgerArgs) -> Result<(), String> {
    let rendered = run_drive_honeybadger_multiprocess(&args)?;
    write_output(args.result_path.as_deref(), &rendered)
}
