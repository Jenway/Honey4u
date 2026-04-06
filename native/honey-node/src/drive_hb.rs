use super::*;
use crate::drive_acs::run_acs_round_workers;

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

fn drive_honeybadger_block_round_workers(
    public_key: &HbPkePublicParams,
    workers: &mut [HbWorkerProcess],
    selected_batches: &[Vec<u8>],
) -> Result<HbBlockOutcome, String> {
    if selected_batches.is_empty() {
        return Err(String::from("HoneyBadger round selected no ACS batches"));
    }

    let local_share_start = Instant::now();
    let share_bundles = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers.len());
        for worker in workers.iter_mut() {
            handles.push(scope.spawn(move || {
                worker
                    .tpke_local_bundle(selected_batches)
                    .map(|(bundle, _elapsed_seconds)| (worker.pid, bundle))
            }));
        }

        let mut bundles = Vec::with_capacity(handles.len());
        for handle in handles {
            let bundle = handle
                .join()
                .map_err(|_| String::from("HoneyBadger tpke_local_bundle worker panicked"))??;
            bundles.push(bundle);
        }
        Ok::<Vec<(usize, HbShareBundle)>, String>(bundles)
    })?;
    let local_share_seconds = local_share_start.elapsed().as_secs_f64();

    let combine_start = Instant::now();
    let mut decryptor = HbBatchDecryptor::new(public_key.clone(), selected_batches.to_vec())?;
    let mut tpke_bundle_events = 0usize;
    for (sender_id, bundle) in share_bundles {
        decryptor.ingest_bundle(sender_id, bundle)?;
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
    let binary_path = std::env::current_exe()
        .map_err(|err| format!("failed to resolve honey-node path: {err}"))?;
    let mut workers = Vec::with_capacity(args.nodes);

    for pid in 0..args.nodes {
        debug_drive_acs(&format!("host:new:start pid={pid}"));
        match HbWorkerProcess::spawn(HbWorkerSpawnArgs {
            binary_path: &binary_path,
            pid,
            nodes: args.nodes,
            faulty: args.faulty,
            acs_protocol: args.acs_protocol,
            acs_crypto_json: &acs_crypto_payloads[pid],
            hb_crypto_json: &hb_crypto_payloads[pid],
            config_json: &args.config_json,
        }) {
            Ok(worker) => {
                debug_drive_acs(&format!("host:new:done pid={pid}"));
                workers.push(worker);
            }
            Err(err) => {
                for worker in &mut workers {
                    let _ = worker.shutdown();
                }
                return Err(err);
            }
        }
    }

    let result = drive_honeybadger_rounds_workers(&mut workers, &args, &public_key);

    let mut shutdown_errors = Vec::new();
    for worker in &mut workers {
        if let Err(err) = worker.shutdown() {
            shutdown_errors.push(format!("pid={}: {err}", worker.pid));
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

fn drive_honeybadger_rounds_workers(
    workers: &mut [HbWorkerProcess],
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
        let local_inputs = workers
            .iter()
            .map(|worker| {
                let batch = build_honeybadger_round_batch(round_id, worker.pid, args.batch_size)?;
                seal_hb_encrypted_batch(public_key, &batch)
            })
            .collect::<Result<Vec<_>, String>>()?;
        let build_seconds = round_build_start.elapsed().as_secs_f64();
        let acs_start = Instant::now();
        let outcome = run_acs_round_workers(
            workers,
            round_id,
            &round_sid,
            &local_inputs,
            args.global_timeout,
        )?;
        let acs_seconds = acs_start.elapsed().as_secs_f64();
        let selected_batches = outcome
            .canonical
            .iter()
            .flatten()
            .cloned()
            .collect::<Vec<_>>();
        let selected_pids = outcome
            .canonical
            .iter()
            .enumerate()
            .filter_map(|(pid, value)| value.as_ref().map(|_| pid))
            .collect::<Vec<_>>();

        if selected_batches.len() < args.nodes - args.faulty {
            return Err(format!(
                "drive-hb round {round_id}: expected at least {} ACS batches, got {}",
                args.nodes - args.faulty,
                selected_batches.len()
            ));
        }

        let tpke_start = Instant::now();
        let block_outcome =
            drive_honeybadger_block_round_workers(public_key, workers, &selected_batches)?;
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
            "acs_send_events": outcome.send_events,
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

    let nodes = workers
        .iter_mut()
        .map(|worker| {
            let stats = worker.stats()?;
            Ok(json!({
                "pid": worker.pid,
                "worker_ident": stats.worker_ident,
                "rounds_started": stats.rounds_started,
                "rounds_finished": stats.rounds_finished,
                "processed_commands": stats.processed_commands,
                "bridge_queue_size": stats.bridge_queue_size,
                "worker_running": stats.worker_running,
                "worker_error": stats.worker_error,
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
