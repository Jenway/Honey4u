use super::*;
use crate::drive_acs::{driver_phase_stats_json, run_acs_round};
use crate::py_host::RustDrivenAcsHost;

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

fn encode_honeybadger_proposal_ref(pid: usize) -> Vec<u8> {
    (pid as u64).to_be_bytes().to_vec()
}

fn drive_honeybadger_block_round(
    public_key: &HbPkePublicParams,
    runtimes: &[HbNodeRuntime],
    selected_batches: &[Vec<u8>],
) -> Result<HbBlockOutcome, String> {
    if selected_batches.is_empty() {
        return Err(String::from("HoneyBadger round selected no ACS batches"));
    }

    let local_share_start = Instant::now();
    let runtime_inputs = runtimes
        .iter()
        .map(|runtime| (runtime.acs_host.pid, runtime.tpke_private_share().clone()))
        .collect::<Vec<_>>();
    let mut decryptor = HbBatchDecryptor::new(public_key.clone(), selected_batches.to_vec())?;
    let share_bundles = decryptor.local_runtime_share_bundles(&runtime_inputs)?;
    let local_share_seconds = local_share_start.elapsed().as_secs_f64();

    let combine_start = Instant::now();
    let mut tpke_bundle_events = 0usize;
    for (sender_id, bundle) in share_bundles {
        decryptor.ingest_trusted_runtime_bundle(sender_id, bundle)?;
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

pub(crate) fn run_drive_honeybadger(args: DriveHoneyBadgerArgs) -> Result<(), String> {
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

    let mut runtimes: Vec<HbNodeRuntime> = Vec::with_capacity(args.nodes);
    for pid in 0..args.nodes {
        debug_drive_acs(&format!("host:new:start pid={pid}"));
        let host = match PyAcsHost::new(
            args.acs_protocol,
            pid,
            args.nodes,
            args.faulty,
            &acs_crypto_payloads[pid],
            &args.config_json,
        ) {
            Ok(host) => host,
            Err(err) => {
                for runtime in &runtimes {
                    let _ = runtime.shutdown();
                }
                return Err(err);
            }
        };
        let (_, private_share) = match parse_honeybadger_crypto_payload(&hb_crypto_payloads[pid]) {
            Ok(crypto) => crypto,
            Err(err) => {
                let _ = host.shutdown();
                for runtime in &runtimes {
                    let _ = runtime.shutdown();
                }
                return Err(err);
            }
        };
        debug_drive_acs(&format!("host:new:done pid={pid}"));
        runtimes.push(HbNodeRuntime::new(host, private_share));
    }

    let result = drive_honeybadger_rounds(&runtimes, &args, &public_key);

    let mut shutdown_errors = Vec::new();
    for runtime in &runtimes {
        if let Err(err) = runtime.shutdown() {
            shutdown_errors.push(format!("pid={}: {err}", runtime.acs_host.pid));
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

fn drive_honeybadger_rounds(
    runtimes: &[HbNodeRuntime],
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
        let sealed_batches = runtimes
            .iter()
            .map(|runtime| {
                let batch =
                    build_honeybadger_round_batch(round_id, runtime.acs_host.pid, args.batch_size)?;
                seal_hb_encrypted_batch(public_key, &batch)
            })
            .collect::<Result<Vec<_>, String>>()?;
        let proposal_refs = runtimes
            .iter()
            .map(|runtime| encode_honeybadger_proposal_ref(runtime.acs_host.pid))
            .collect::<Vec<_>>();
        let build_seconds = round_build_start.elapsed().as_secs_f64();

        let acs_start = Instant::now();
        let outcome = run_acs_round(
            runtimes,
            round_id,
            &round_sid,
            &proposal_refs,
            args.global_timeout,
        )?;
        let acs_seconds = acs_start.elapsed().as_secs_f64();
        let AcsRoundOutcome {
            selected_pids,
            send_events,
            drive_stats,
            settle_stats,
        } = outcome;
        let selected_batches = selected_pids
            .iter()
            .map(|pid| {
                sealed_batches
                    .get(*pid)
                    .cloned()
                    .ok_or_else(|| format!("drive-hb round {round_id}: invalid selected pid {pid}"))
            })
            .collect::<Result<Vec<_>, String>>()?;

        if selected_batches.len() < args.nodes - args.faulty {
            return Err(format!(
                "drive-hb round {round_id}: expected at least {} ACS batches, got {}",
                args.nodes - args.faulty,
                selected_batches.len()
            ));
        }

        let tpke_start = Instant::now();
        let block_outcome = drive_honeybadger_block_round(public_key, runtimes, &selected_batches)?;
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
            "acs_send_events": send_events,
            "acs_drive_stats": driver_phase_stats_json(&drive_stats),
            "acs_settle_stats": driver_phase_stats_json(&settle_stats),
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

    let nodes = runtimes
        .iter()
        .map(|runtime| {
            let stats = runtime.stats()?;
            Ok(json!({
                "pid": runtime.acs_host.pid,
                "worker_ident": stats.worker_ident,
                "rounds_started": stats.rounds_started,
                "rounds_finished": stats.rounds_finished,
                "processed_commands": stats.processed_commands,
                "start_round_calls": stats.start_round_calls,
                "push_inbound_batch_calls": stats.push_inbound_batch_calls,
                "push_inbound_batch_items": stats.push_inbound_batch_items,
                "exchange_batches_calls": stats.exchange_batches_calls,
                "exchange_inbound_items": stats.exchange_inbound_items,
                "exchange_outbound_items": stats.exchange_outbound_items,
                "pull_outbound_batch_calls": stats.pull_outbound_batch_calls,
                "pull_outbound_batch_items": stats.pull_outbound_batch_items,
                "stats_calls": stats.stats_calls,
                "bridge_queue_size": stats.bridge_queue_size,
                "worker_running": stats.worker_running,
                "worker_error": stats.worker_error,
                "exchange_deliver_seconds": stats.exchange_deliver_seconds,
                "exchange_pump_seconds": stats.exchange_pump_seconds,
                "exchange_drain_seconds": stats.exchange_drain_seconds,
                "exchange_total_seconds": stats.exchange_total_seconds,
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
