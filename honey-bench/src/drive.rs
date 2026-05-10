use super::*;
use honey_wire::phase_stats::{
    DriverPhaseStats, aggregate_driver_phase_stats, driver_phase_stats_from_value,
    driver_phase_stats_json,
};

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

fn protocol_label(family: BenchmarkProtocolFamily) -> &'static str {
    match family {
        BenchmarkProtocolFamily::HoneyBadger => "hb",
        BenchmarkProtocolFamily::Dumbo => "dumbo",
    }
}

fn acs_crypto_payloads_for_run(
    args: &BenchDriveArgs,
    hb_crypto_payloads: &[String],
) -> Result<Vec<String>, String> {
    match args.acs_backend.benchmark_protocol_family() {
        BenchmarkProtocolFamily::HoneyBadger => Ok(hb_crypto_payloads.to_vec()),
        BenchmarkProtocolFamily::Dumbo => {
            debug_acs_driver("drive-mp:serialize_acs_crypto_payloads:start");
            let payloads = serialize_crypto_payloads(args.acs_backend, args.nodes, args.faulty)?;
            debug_acs_driver("drive-mp:serialize_acs_crypto_payloads:done");
            Ok(payloads)
        }
    }
}

fn summarize_rounds_strict(
    family: BenchmarkProtocolFamily,
    args: &BenchDriveArgs,
    node_jsons: &[Value],
) -> Result<Vec<Value>, String> {
    let canonical = &node_jsons[0];
    let canonical_rounds = json_array_field(canonical, "round_details")?;

    canonical_rounds
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
            let mut tpke_partial_open_seconds = 0.0f64;
            let mut tpke_combine_seconds = 0.0f64;
            let mut acs_send_events = 0usize;
            let mut reused_reference_count = 0usize;
            let mut fetch_requests_sent = 0usize;
            let mut fetch_responses_served = 0usize;
            let mut fetch_responses_received = 0usize;
            let mut fetched_reference_count = 0usize;
            let mut delivered_count = usize::MAX;
            let mut driver_stats = Vec::with_capacity(node_jsons.len());

            for (pid, node_json) in node_jsons.iter().enumerate() {
                let node_rounds = json_array_field(node_json, "round_details")?;
                let node_round = node_rounds.get(round_id).ok_or_else(|| {
                    format!("bench-driver:{}: pid={pid} missing round detail {round_id}", protocol_label(family))
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
                        "bench-driver:{}: round {round_id} selected_pids diverged at pid={pid}",
                        protocol_label(family)
                    ));
                }
                if node_block_digest != canonical_block_digest {
                    return Err(format!(
                        "bench-driver:{}: round {round_id} block_digest diverged at pid={pid}",
                        protocol_label(family)
                    ));
                }
                if node_chain_digest != canonical_chain_digest {
                    return Err(format!(
                        "bench-driver:{}: round {round_id} chain_digest diverged at pid={pid}",
                        protocol_label(family)
                    ));
                }

                build_seconds = build_seconds.max(json_f64_field(node_round, "build_seconds")?);
                acs_seconds = acs_seconds.max(json_f64_field(node_round, "acs_seconds")?);
                tpke_seconds = tpke_seconds.max(json_f64_field(node_round, "tpke_seconds")?);
                protocol_seconds =
                    protocol_seconds.max(json_f64_field(node_round, "protocol_seconds").unwrap_or(tpke_seconds + acs_seconds));
                wall_seconds = wall_seconds.max(json_f64_field(node_round, "wall_seconds")?);
                tpke_partial_open_seconds = tpke_partial_open_seconds.max(
                    json_f64_field(node_round, "tpke_partial_open_seconds").unwrap_or(0.0),
                );
                tpke_combine_seconds = tpke_combine_seconds
                    .max(json_f64_field(node_round, "tpke_combine_seconds").unwrap_or(0.0));
                acs_send_events += json_usize_field(node_round, "acs_outbound_events")?;
                reused_reference_count =
                    json_usize_field(canonical_round, "reused_reference_count").unwrap_or(0);
                fetch_requests_sent +=
                    json_usize_field(node_round, "fetch_requests_sent").unwrap_or(0);
                fetch_responses_served +=
                    json_usize_field(node_round, "fetch_responses_served").unwrap_or(0);
                fetch_responses_received +=
                    json_usize_field(node_round, "fetch_responses_received").unwrap_or(0);
                fetched_reference_count +=
                    json_usize_field(node_round, "fetched_reference_count").unwrap_or(0);
                delivered_count =
                    delivered_count.min(json_usize_field(node_round, "delivered_count")?);
                driver_stats.push(driver_phase_stats_from_value(
                    node_round.get("driver_phase_stats").ok_or_else(|| {
                        format!(
                            "bench-driver:{}: round {round_id} missing driver_phase_stats at pid={pid}",
                            protocol_label(family)
                        )
                    })?,
                )?);
            }

            if delivered_count == usize::MAX {
                delivered_count = 0;
            }

            let aggregated_drive_stats = aggregate_driver_phase_stats(&driver_stats, args.nodes);
            let block_size = json_usize_field(canonical_round, "block_size")?;

            if let Some(dir) = &args.ledger_dir {
                let block_path = std::path::Path::new(dir).join(format!("block_{round_id:06}.json"));
                let entry = json!({
                    "round_id": round_id,
                    "chain_digest": canonical_chain_digest,
                    "block_digest": canonical_block_digest,
                    "delivered_count": delivered_count,
                    "selected_count": canonical_selected.len(),
                    "selected_pids": canonical_selected,
                    "wall_seconds": wall_seconds,
                });
                let _ = std::fs::write(&block_path, entry.to_string());
            }

            Ok(json!({
                "round_id": round_id,
                "selected_count": canonical_selected.len(),
                "selected_pids": canonical_selected,
                "acs_send_events": acs_send_events,
                "acs_drive_stats": driver_phase_stats_json(&aggregated_drive_stats),
                "acs_settle_stats": driver_phase_stats_json(&DriverPhaseStats::default()),
                "tpke_bundle_events": args.nodes,
                "delivered_count": delivered_count,
                "block_size": block_size,
                "block_digest": canonical_block_digest,
                "chain_digest": canonical_chain_digest,
                "build_seconds": build_seconds,
                "acs_seconds": acs_seconds,
                "tpke_seconds": tpke_seconds,
                "protocol_seconds": protocol_seconds,
                "reused_reference_count": reused_reference_count,
                "fetch_requests_sent": fetch_requests_sent,
                "fetch_responses_served": fetch_responses_served,
                "fetch_responses_received": fetch_responses_received,
                "fetched_reference_count": fetched_reference_count,
                "tpke_partial_open_seconds": tpke_partial_open_seconds,
                "tpke_combine_seconds": tpke_combine_seconds,
                "block_resolve_seconds": 0.0,
                "wall_seconds": wall_seconds,
            }))
        })
        .collect()
}

fn project_node_stats(node_jsons: &[Value]) -> Result<Vec<Value>, String> {
    node_jsons
        .iter()
        .enumerate()
        .map(|(pid, node_json)| -> Result<Value, String> {
            let host_stats = Value::Object(json_object_field(node_json, "host_stats")?.clone());
            let transport_stats =
                Value::Object(json_object_field(node_json, "transport_stats")?.clone());
            let byzantine_stats =
                Value::Object(json_object_field(node_json, "byzantine_stats")?.clone());
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
                "mempool_size": node_json["mempool_size"].as_u64().unwrap_or(0),
                "byzantine_behavior": node_json["byzantine_behavior"].as_str().unwrap_or("none"),
                "byzantine_invalid_fetch_responses_sent": byzantine_stats["invalid_fetch_responses_sent"].as_u64().unwrap_or(0),
                "byzantine_fetch_requests_ignored": byzantine_stats["fetch_requests_ignored"].as_u64().unwrap_or(0),
                "byzantine_share_broadcast_suppressed": byzantine_stats["share_broadcast_suppressed"].as_u64().unwrap_or(0),
                "byzantine_empty_proposal_rounds": byzantine_stats["empty_proposal_rounds"].as_u64().unwrap_or(0),
                "transport_sent_frames": transport_stats["sent_frames"].as_u64().unwrap_or(0),
                "transport_recv_frames": transport_stats["recv_frames"].as_u64().unwrap_or(0),
                "transport_connect_retries": transport_stats["connect_retries"].as_u64().unwrap_or(0),
                "transport_send_retries": transport_stats["send_retries"].as_u64().unwrap_or(0),
                "transport_delayed_frames": transport_stats["delayed_frames"].as_u64().unwrap_or(0),
                "transport_total_injected_delay_ms": transport_stats["total_injected_delay_ms"].as_u64().unwrap_or(0),
                "transport_network_fault_seed": transport_stats["network_fault_seed"].as_u64().unwrap_or(0),
                "transport_configured_fixed_delay_ms": transport_stats["configured_fixed_delay_ms"].as_u64().unwrap_or(0),
                "transport_configured_jitter_ms": transport_stats["configured_jitter_ms"].as_u64().unwrap_or(0),
                "transport_configured_slow_honest_extra_delay_ms": transport_stats["configured_slow_honest_extra_delay_ms"].as_u64().unwrap_or(0),
            }))
        })
        .collect()
}

pub fn run_drive_multiprocess(args: &BenchDriveArgs, node_binary: &Path) -> Result<String, String> {
    if args.tx_json.is_some() {
        return Err(String::from(
            "bench-driver does not support tx_json; only deterministic per-node dummy transactions are supported",
        ));
    }

    let family = args.acs_backend.benchmark_protocol_family();
    let label = protocol_label(family);
    let pool_reuse_enabled = enable_pool_reuse(&args.config_json)?;

    debug_acs_driver("drive-mp:serialize_hb_crypto_payloads:start");
    let hb_crypto_payloads = serialize_hb_crypto_payloads(args.nodes, args.faulty)?;
    debug_acs_driver("drive-mp:serialize_hb_crypto_payloads:done");
    let acs_crypto_payloads = acs_crypto_payloads_for_run(args, &hb_crypto_payloads)?;

    let completed = run_multiprocess_nodes(MultiprocessRunConfig {
        label,
        node_binary,
        sid: &args.sid,
        acs_backend: args.acs_backend,
        nodes: args.nodes,
        faulty: args.faulty,
        rounds: args.rounds,
        batch_size: args.batch_size,
        global_timeout: args.global_timeout,
        config_json: &args.config_json,
        hb_crypto_payloads: &hb_crypto_payloads,
        acs_crypto_payloads: &acs_crypto_payloads,
    })?;
    let result_dir = completed.result_dir;
    let node_jsons = completed.node_jsons;
    let canonical_chain = completed.canonical_chain;

    if let Some(dir) = &args.ledger_dir {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("bench-driver:{label}: create ledger dir '{dir}': {e}"))?;
    }

    let rounds = summarize_rounds_strict(family, args, &node_jsons)?;
    let nodes = project_node_stats(&node_jsons)?;

    let _ = fs::remove_dir_all(&result_dir);

    serde_json::to_string(&json!({
        "protocol": label,
        "acs_backend": args.acs_backend.as_str(),
        "sid": args.sid,
        "nodes_count": args.nodes,
        "faulty": args.faulty,
        "enable_pool_reuse": pool_reuse_enabled,
        "has_tpke": true,
        "transport": transport_label(&args.config_json),
        "chain_digest": canonical_chain,
        "nodes": nodes,
        "rounds": rounds,
    }))
    .map_err(|err| err.to_string())
}
