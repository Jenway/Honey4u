use super::config::{BroadcastPoolBackend, BroadcastPoolConfig};
use super::types::{
    BatchArchive, DriverCarryovers, DriverNodeResult, DriverNodeRoundTelemetry, DriverRoundCtx,
    DriverRoundOutcome, QueuePeaksSnapshot,
};
use super::wire::{
    DriverWireFrame, broadcast_frame, decode_driver_frame, encode_driver_frame,
    fanout_encoded_payload, send_frame,
};
use super::{BATCH_REF_TAG, DRIVER_IDLE_BACKOFF, DRIVER_NETWORK_BATCH_LIMIT};
use crate::drive_acs::{record_pull, record_push};
use crate::pool_reuse::{
    AcsPayload, BroadcastMempool, PoolReference, decode_acs_payload, encode_bundle_acs_payload,
};
use crate::{
    AcsHost, AcsWireEvent, DriverHostPhaseStats, DriverPhaseStats, GENESIS_CHAIN_DIGEST,
    HbBatchDecryptor, HbPkePrivateKeyShare, HbPkePublicParams, ProposalArtifact, ProposalStore,
    Protocol, RunDriverNodeArgs, decode_hb_tx_batch, encode_hb_json_string, encode_hb_tx_batch,
    merge_hb_tx_batches_bytes, seal_hb_encrypted_batch,
};
use honey_node::transport::LocalTcpTransport;
use std::collections::{BTreeMap, BTreeSet};
use std::thread;
use std::time::{Duration, Instant};

fn build_driver_round_batch(
    round_id: usize,
    pid: usize,
    batch_size: usize,
) -> Result<Vec<u8>, String> {
    let mut items = Vec::with_capacity(batch_size);
    for tx_index in 0..batch_size {
        items.push(encode_hb_json_string(&format!(
            "hb-rust-driver-round-{round_id}-node-{pid}-tx-{tx_index}"
        ))?);
    }
    encode_hb_tx_batch(items)
}

fn encode_batch_ref(round_id: usize, sender: usize) -> Vec<u8> {
    let mut payload = Vec::with_capacity(7);
    payload.push(BATCH_REF_TAG);
    payload.extend_from_slice(&(round_id as u32).to_be_bytes());
    payload.extend_from_slice(&(sender as u16).to_be_bytes());
    payload
}

fn decode_batch_ref(payload: &[u8]) -> Result<(u32, u32), String> {
    if payload.len() != 7 {
        return Err(format!(
            "invalid batch ref length: expected 7 bytes, got {}",
            payload.len()
        ));
    }
    if payload[0] != BATCH_REF_TAG {
        return Err(format!("invalid batch ref tag: {}", payload[0]));
    }
    let round_id = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
    let sender = u16::from_be_bytes([payload[5], payload[6]]) as u32;
    Ok((round_id, sender))
}

fn remember_archived_batch(
    batch_archive: &mut BatchArchive,
    round_id: usize,
    sender: usize,
    sealed_batch: &[u8],
) {
    batch_archive
        .entry((round_id as u32, sender as u32))
        .or_insert_with(|| sealed_batch.to_vec());
}

fn build_acs_proposal_input(
    round_id: usize,
    pid: usize,
    pool: Option<&BroadcastMempool>,
    config: &BroadcastPoolConfig,
) -> Vec<u8> {
    let inline_payload = encode_batch_ref(round_id, pid);
    let references = if config.enable_reuse && config.enable_reference_proposals {
        pool.map(|pool| {
            pool.list_reusable(round_id as u32, config.reuse_limit_per_round)
                .into_iter()
                .map(|(item_id, entry)| PoolReference {
                    item_id,
                    origin_round: entry.round_no,
                    origin_sender: entry.sender_id,
                    roothash: entry.roothash.clone(),
                    proof_payload: entry.proof_payload.clone(),
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
    } else {
        Vec::new()
    };
    encode_bundle_acs_payload(&inline_payload, &references)
}

fn collect_selected_proposals<'a>(
    selected_proposal_ids: &[String],
    proposal_store: &'a ProposalStore,
) -> Option<Vec<&'a ProposalArtifact>> {
    let mut proposals = Vec::with_capacity(selected_proposal_ids.len());
    for proposal_id in selected_proposal_ids {
        let proposal = proposal_store.get(proposal_id)?;
        proposals.push(proposal);
    }
    Some(proposals)
}

fn selected_pids_from_proposals(selected_proposals: &[&ProposalArtifact]) -> Vec<usize> {
    selected_proposals
        .iter()
        .map(|proposal| proposal.proposer)
        .collect()
}

fn batch_refs_from_selected_proposals(
    selected_proposals: &[&ProposalArtifact],
) -> Result<Vec<(u32, u32)>, String> {
    let mut batch_refs = Vec::new();
    let mut seen_batch_refs = BTreeSet::new();
    for proposal in selected_proposals {
        match decode_acs_payload(&proposal.payload)? {
            AcsPayload::Inline(data) => {
                let batch_ref = decode_batch_ref(&data)?;
                if seen_batch_refs.insert(batch_ref) {
                    batch_refs.push(batch_ref);
                }
            }
            AcsPayload::Bundle {
                inline_payload,
                references,
            } => {
                if !references.is_empty() {
                    return Err(format!(
                        "proposal {} unexpectedly carried reusable references with pool reuse disabled",
                        proposal.proposal_id
                    ));
                }
                let batch_ref = decode_batch_ref(&inline_payload)?;
                if seen_batch_refs.insert(batch_ref) {
                    batch_refs.push(batch_ref);
                }
            }
        }
    }
    Ok(batch_refs)
}

struct ResolvedSelectedProposals {
    batch_refs: Vec<(u32, u32)>,
    consumed_reference_ids: Vec<String>,
}

fn resolve_selected_proposals(
    selected_proposals: &[&ProposalArtifact],
    pool: &mut BroadcastMempool,
    allow_fetch_fallback: bool,
) -> Result<ResolvedSelectedProposals, String> {
    let mut batch_refs = Vec::new();
    let mut seen_batch_refs = BTreeSet::new();
    let mut consumed_reference_ids = Vec::new();
    let mut visited_reference_ids = BTreeSet::new();
    for proposal in selected_proposals {
        resolve_payload_bytes(
            &proposal.payload,
            pool,
            allow_fetch_fallback,
            &mut batch_refs,
            &mut seen_batch_refs,
            &mut consumed_reference_ids,
            &mut visited_reference_ids,
        )?;
    }
    Ok(ResolvedSelectedProposals {
        batch_refs,
        consumed_reference_ids,
    })
}

fn resolve_payload_bytes(
    payload: &[u8],
    pool: &mut BroadcastMempool,
    allow_fetch_fallback: bool,
    batch_refs: &mut Vec<(u32, u32)>,
    seen_batch_refs: &mut BTreeSet<(u32, u32)>,
    consumed_reference_ids: &mut Vec<String>,
    visited_reference_ids: &mut BTreeSet<String>,
) -> Result<(), String> {
    match decode_acs_payload(payload)? {
        AcsPayload::Inline(data) => {
            let batch_ref = decode_batch_ref(&data)?;
            if seen_batch_refs.insert(batch_ref) {
                batch_refs.push(batch_ref);
            }
            Ok(())
        }
        AcsPayload::Bundle {
            inline_payload,
            references,
        } => {
            if !inline_payload.is_empty() {
                let batch_ref = decode_batch_ref(&inline_payload)?;
                if seen_batch_refs.insert(batch_ref) {
                    batch_refs.push(batch_ref);
                }
            }
            for reference in references {
                if !visited_reference_ids.insert(reference.item_id.clone()) {
                    continue;
                }
                let nested_payload = if let Some(entry) = pool.get_reusable(&reference.item_id) {
                    if entry.round_no != reference.origin_round
                        || entry.sender_id != reference.origin_sender
                        || entry.roothash != reference.roothash
                    {
                        return Err(format!(
                            "reusable entry {} metadata mismatch during payload resolution",
                            reference.item_id
                        ));
                    }
                    entry.payload.clone()
                } else if allow_fetch_fallback {
                    return Err(format!(
                        "missing reusable entry {} and pool fetch fallback is not implemented",
                        reference.item_id
                    ));
                } else {
                    return Err(format!(
                        "missing reusable entry {} during payload resolution",
                        reference.item_id
                    ));
                };
                consumed_reference_ids.push(reference.item_id.clone());
                resolve_payload_bytes(
                    &nested_payload,
                    pool,
                    allow_fetch_fallback,
                    batch_refs,
                    seen_batch_refs,
                    consumed_reference_ids,
                    visited_reference_ids,
                )?;
            }
            Ok(())
        }
    }
}

fn update_queue_peaks(transport: &LocalTcpTransport, peaks: &mut QueuePeaksSnapshot) {
    let pending_inbound = transport.pending_inbound();
    let pending_outbound = transport.pending_outbound();
    peaks.raw_inbound_messages = peaks.raw_inbound_messages.max(pending_inbound);
    peaks.raw_outbound_messages = peaks.raw_outbound_messages.max(pending_outbound);
    peaks.transport_inbound = peaks.transport_inbound.max(pending_inbound);
    peaks.transport_outbound = peaks.transport_outbound.max(pending_outbound);
}

fn drain_transport_into_round(
    transport: &LocalTcpTransport,
    round_id: usize,
    carryovers: &mut DriverCarryovers,
    batch_archive: &mut BatchArchive,
    inbound_acs_wire: &mut Vec<Vec<u8>>,
    received_batches: &mut BTreeMap<usize, Vec<u8>>,
    pending_share_bundles: &mut Vec<super::types::InboundShareBundle>,
) -> Result<usize, String> {
    let mut frame_count = 0usize;
    for payload in transport
        .recv_batch(DRIVER_NETWORK_BATCH_LIMIT)
        .map_err(|err| err.to_string())?
    {
        frame_count += 1;
        match decode_driver_frame(&payload)? {
            DriverWireFrame::AcsEnvelope {
                round_id: frame_round_id,
                payload,
            } => {
                if frame_round_id == round_id {
                    inbound_acs_wire.push(payload);
                } else if frame_round_id > round_id {
                    carryovers
                        .acs_wire_payloads
                        .entry(frame_round_id)
                        .or_default()
                        .push(payload);
                }
            }
            DriverWireFrame::HbBatch {
                sender,
                round_id: frame_round_id,
                sealed_batch,
            } => {
                remember_archived_batch(batch_archive, frame_round_id, sender, &sealed_batch);
                if frame_round_id == round_id {
                    received_batches.entry(sender).or_insert(sealed_batch);
                } else if frame_round_id > round_id {
                    carryovers
                        .sealed_batches
                        .entry(frame_round_id)
                        .or_default()
                        .entry(sender)
                        .or_insert(sealed_batch);
                }
            }
            DriverWireFrame::HbShareBundle {
                sender,
                round_id: frame_round_id,
                selected_batch_refs,
                shares,
            } => {
                let bundle = super::types::InboundShareBundle {
                    sender,
                    selected_batch_refs,
                    shares,
                };
                if frame_round_id == round_id {
                    pending_share_bundles.push(bundle);
                } else if frame_round_id > round_id {
                    carryovers
                        .share_bundles
                        .entry(frame_round_id)
                        .or_default()
                        .push(bundle);
                }
            }
        }
    }
    Ok(frame_count)
}

pub(super) fn wait_until_start(start_at_ms: Option<u64>) -> Result<(), String> {
    let Some(start_at_ms) = start_at_ms else {
        return Ok(());
    };
    let now_ms = crate::current_time_millis()?;
    if start_at_ms <= now_ms {
        return Ok(());
    }
    thread::sleep(Duration::from_millis(start_at_ms - now_ms));
    Ok(())
}

fn run_driver_round(
    ctx: &DriverRoundCtx<'_>,
    round_id: usize,
    carryovers: &mut DriverCarryovers,
    batch_archive: &mut BatchArchive,
    queue_peaks: &mut QueuePeaksSnapshot,
    rust_broadcast_mempool: &mut Option<BroadcastMempool>,
) -> Result<DriverRoundOutcome, String> {
    let round_wall_start = Instant::now();
    let round_sid = format!("{}:{round_id}:", ctx.args.sid);
    let round_build_start = Instant::now();
    let batch = build_driver_round_batch(round_id, ctx.args.pid, ctx.args.batch_size)?;
    let sealed_batch = seal_hb_encrypted_batch(ctx.public_key, &batch)?;
    let build_seconds = round_build_start.elapsed().as_secs_f64();
    remember_archived_batch(batch_archive, round_id, ctx.args.pid, &sealed_batch);

    broadcast_frame(
        ctx.transport,
        ctx.args.nodes,
        &DriverWireFrame::HbBatch {
            sender: ctx.args.pid,
            round_id,
            sealed_batch: sealed_batch.clone(),
        },
    )?;
    update_queue_peaks(ctx.transport, queue_peaks);

    let reuse_enabled =
        matches!(ctx.args.acs_protocol, Protocol::Dumbo) && ctx.broadcast_pool_config.enable_reuse;
    let proposal_input = build_acs_proposal_input(
        round_id,
        ctx.args.pid,
        rust_broadcast_mempool.as_ref(),
        ctx.broadcast_pool_config,
    );
    ctx.host
        .start_round(round_id, &round_sid, &proposal_input)?;

    let deadline = Instant::now() + Duration::from_secs_f64(ctx.args.global_timeout);
    let mut proposal_store: ProposalStore = BTreeMap::new();
    let mut selected_proposal_ids: Option<Vec<String>> = None;
    let mut selected_batch_refs: Option<Vec<(u32, u32)>> = None;
    let mut consumed_reference_ids: Vec<String> = Vec::new();
    let mut decryptor: Option<HbBatchDecryptor> = None;
    let mut inbound_acs_wire = carryovers
        .acs_wire_payloads
        .remove(&round_id)
        .unwrap_or_default();
    let mut received_batches = carryovers
        .sealed_batches
        .remove(&round_id)
        .unwrap_or_default();
    received_batches.entry(ctx.args.pid).or_insert(sealed_batch);
    let mut pending_share_bundles = carryovers
        .share_bundles
        .remove(&round_id)
        .unwrap_or_default();
    let mut seen_share_senders: BTreeSet<usize> = BTreeSet::new();
    let mut local_share_broadcasted = false;
    let mut acs_decision_at: Option<Instant> = None;
    let mut acs_pull_seconds = 0.0f64;
    let mut tpke_partial_open_seconds = 0.0f64;
    let mut tpke_combine_seconds = 0.0f64;
    let mut acs_pull_calls = 0usize;
    let mut acs_empty_pull_calls = 0usize;
    let mut acs_inbound_wire_batches = 0usize;
    let mut acs_inbound_wire_items = 0usize;
    let mut acs_outbound_events = 0usize;
    let mut tpke_combine_calls = 0usize;
    let mut stale_acs_frames_dropped = 0usize;
    let mut reused_reference_count = 0usize;
    let mut driver_stats = DriverPhaseStats {
        host_stats: (0..ctx.args.nodes)
            .map(|pid| DriverHostPhaseStats {
                pid,
                ..DriverHostPhaseStats::default()
            })
            .collect(),
        ..DriverPhaseStats::default()
    };

    while Instant::now() < deadline {
        driver_stats.sweep_count += 1;
        let pending_deliveries =
            ctx.transport.pending_inbound() + inbound_acs_wire.len() + pending_share_bundles.len();
        driver_stats.total_pending_deliveries += pending_deliveries;
        driver_stats.max_pending_deliveries =
            driver_stats.max_pending_deliveries.max(pending_deliveries);
        let mut progressed = false;
        let frame_count = drain_transport_into_round(
            ctx.transport,
            round_id,
            carryovers,
            batch_archive,
            &mut inbound_acs_wire,
            &mut received_batches,
            &mut pending_share_bundles,
        )?;
        if frame_count > 0 {
            progressed = true;
        }
        update_queue_peaks(ctx.transport, queue_peaks);

        let mut pushed_inbound = false;
        if selected_proposal_ids.is_none() && !inbound_acs_wire.is_empty() {
            let batch = std::mem::take(&mut inbound_acs_wire);
            acs_inbound_wire_batches += 1;
            acs_inbound_wire_items += batch.len();
            let push_start = Instant::now();
            ctx.host.push_inbound_wire_batch(&batch)?;
            record_push(
                &mut driver_stats,
                ctx.args.pid,
                batch.len(),
                push_start.elapsed().as_secs_f64(),
            );
            pushed_inbound = true;
            progressed = true;
        }

        let should_pull_host = if pushed_inbound {
            true
        } else {
            ctx.host.outbound_ready()?
        };
        if should_pull_host {
            let pull_start = Instant::now();
            ctx.host
                .begin_pull_outbound_wire_batch(DRIVER_NETWORK_BATCH_LIMIT)?;
            let events = ctx.host.finish_pull_outbound_wire_batch()?;
            let pull_seconds = pull_start.elapsed().as_secs_f64();
            acs_pull_seconds += pull_seconds;
            acs_pull_calls += 1;
            record_pull(
                &mut driver_stats,
                ctx.args.pid,
                events.len(),
                pull_seconds,
                DRIVER_NETWORK_BATCH_LIMIT,
            );
            if !events.is_empty() {
                progressed = true;
            } else {
                acs_empty_pull_calls += 1;
            }
            acs_outbound_events += events.len();
            for event in events {
                match event {
                    AcsWireEvent::Send {
                        round_id: event_round_id,
                        recipient,
                        payload,
                    } => {
                        if event_round_id != round_id {
                            return Err(format!(
                                "driver round {round_id}: outbound ACS event carried mismatched round_id {event_round_id}"
                            ));
                        }
                        driver_stats.send_events += 1;
                        driver_stats.send_payload_bytes += payload.len();
                        send_frame(
                            ctx.transport,
                            recipient,
                            &DriverWireFrame::AcsEnvelope { round_id, payload },
                        )?;
                    }
                    AcsWireEvent::Broadcast {
                        round_id: event_round_id,
                        payload,
                        include_self,
                    } => {
                        if event_round_id != round_id {
                            return Err(format!(
                                "driver round {round_id}: outbound ACS broadcast event carried mismatched round_id {event_round_id}"
                            ));
                        }
                        let payload_len = payload.len();
                        let frame_payload = encode_driver_frame(&DriverWireFrame::AcsEnvelope {
                            round_id,
                            payload,
                        })?;
                        let sent = fanout_encoded_payload(
                            ctx.transport,
                            ctx.args.nodes,
                            &frame_payload,
                            (!include_self).then_some(ctx.args.pid),
                        )?;
                        driver_stats.send_events += sent;
                        driver_stats.send_payload_bytes += payload_len * sent;
                    }
                    AcsWireEvent::ProposalReady {
                        round_id: event_round_id,
                        proposal,
                    } => {
                        if event_round_id != round_id {
                            return Err(format!(
                                "driver round {round_id}: proposal_ready carried mismatched round_id {event_round_id}"
                            ));
                        }
                        driver_stats.proposal_ready_events += 1;
                        driver_stats.proposal_ready_payload_bytes += proposal.payload.len();
                        driver_stats.proposal_ready_certificate_bytes += proposal.certificate.len();
                        proposal_store.insert(proposal.proposal_id.clone(), proposal);
                    }
                    AcsWireEvent::Decision {
                        round_id: event_round_id,
                        selected_proposal_ids: event_selected_proposal_ids,
                    } => {
                        if event_round_id != round_id {
                            return Err(format!(
                                "driver round {round_id}: decision carried mismatched round_id {event_round_id}"
                            ));
                        }
                        if acs_decision_at.is_none() {
                            acs_decision_at = Some(Instant::now());
                        }
                        driver_stats.decision_events += 1;
                        selected_proposal_ids = Some(event_selected_proposal_ids);
                    }
                    AcsWireEvent::Failure {
                        round_id: event_round_id,
                        error,
                        exception_type,
                    } => {
                        driver_stats.failure_events += 1;
                        return Err(format!(
                            "driver round {round_id}: ACS host failed in event round {event_round_id} with {exception_type}: {error}"
                        ));
                    }
                }
            }
        }

        if selected_proposal_ids.is_some() && !inbound_acs_wire.is_empty() {
            stale_acs_frames_dropped += inbound_acs_wire.len();
            inbound_acs_wire.clear();
            progressed = true;
        }
        update_queue_peaks(ctx.transport, queue_peaks);

        if let Some(selected_proposal_ids) = selected_proposal_ids.as_ref() {
            let Some(selected_proposals) =
                collect_selected_proposals(selected_proposal_ids, &proposal_store)
            else {
                if !progressed {
                    driver_stats.idle_sweeps += 1;
                    driver_stats.idle_backoff_count += 1;
                    thread::sleep(DRIVER_IDLE_BACKOFF);
                    continue;
                }
                driver_stats.active_sweeps += 1;
                continue;
            };
            let selected_pids = selected_pids_from_proposals(&selected_proposals);

            if selected_batch_refs.is_none() {
                selected_batch_refs = Some(if reuse_enabled {
                    let pool = rust_broadcast_mempool.as_mut().ok_or_else(|| {
                        String::from("missing Rust mempool for proposal resolution")
                    })?;
                    let resolved = resolve_selected_proposals(
                        &selected_proposals,
                        pool,
                        ctx.broadcast_pool_config.enable_fetch_fallback,
                    )?;
                    reused_reference_count = resolved.consumed_reference_ids.len();
                    consumed_reference_ids = resolved.consumed_reference_ids;
                    resolved.batch_refs
                } else {
                    batch_refs_from_selected_proposals(&selected_proposals)?
                });
            }

            let round_batch_refs = selected_batch_refs
                .clone()
                .ok_or_else(|| format!("driver round {round_id}: missing selected batch refs"))?;

            if !local_share_broadcasted
                && round_batch_refs
                    .iter()
                    .all(|batch_ref| batch_archive.contains_key(batch_ref))
            {
                let selected_batches = round_batch_refs
                    .iter()
                    .map(|batch_ref| {
                        batch_archive.get(batch_ref).cloned().ok_or_else(|| {
                            format!(
                                "driver round {round_id}: missing archived batch for origin_round={} sender={}",
                                batch_ref.0, batch_ref.1
                            )
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let mut batch_decryptor =
                    HbBatchDecryptor::new(ctx.public_key.clone(), selected_batches)?;
                let partial_open_start = Instant::now();
                let local_shares = batch_decryptor.local_shares(ctx.private_share)?;
                tpke_partial_open_seconds += partial_open_start.elapsed().as_secs_f64();
                let local_bundle = local_shares.into_iter().map(Some).collect::<Vec<_>>();

                let combine_start = Instant::now();
                let _ = batch_decryptor.ingest_bundle(ctx.args.pid, local_bundle.clone())?;
                tpke_combine_seconds += combine_start.elapsed().as_secs_f64();
                tpke_combine_calls += 1;
                seen_share_senders.insert(ctx.args.pid);

                broadcast_frame(
                    ctx.transport,
                    ctx.args.nodes,
                    &DriverWireFrame::HbShareBundle {
                        sender: ctx.args.pid,
                        round_id,
                        selected_batch_refs: round_batch_refs.clone(),
                        shares: local_bundle,
                    },
                )?;
                update_queue_peaks(ctx.transport, queue_peaks);
                decryptor = Some(batch_decryptor);
                local_share_broadcasted = true;
                progressed = true;
            }

            if let Some(batch_decryptor) = decryptor.as_mut() {
                for bundle in pending_share_bundles.drain(..) {
                    if bundle.selected_batch_refs != round_batch_refs {
                        return Err(format!(
                            "driver round {round_id}: share bundle from pid={} carried divergent selected batch refs",
                            bundle.sender
                        ));
                    }
                    if !seen_share_senders.insert(bundle.sender) {
                        continue;
                    }
                    let combine_start = Instant::now();
                    let _ = batch_decryptor.ingest_bundle(bundle.sender, bundle.shares)?;
                    tpke_combine_seconds += combine_start.elapsed().as_secs_f64();
                    tpke_combine_calls += 1;
                    progressed = true;
                }

                if batch_decryptor.is_complete() {
                    let block_payload = merge_hb_tx_batches_bytes(
                        batch_decryptor
                            .plaintexts()
                            .into_iter()
                            .flatten()
                            .collect::<Vec<_>>(),
                    )?;
                    let delivered_count = decode_hb_tx_batch(&block_payload)?.len();
                    let wall_seconds = round_wall_start.elapsed().as_secs_f64();
                    let acs_seconds = acs_decision_at
                        .map(|instant| {
                            (instant.duration_since(round_wall_start).as_secs_f64() - build_seconds)
                                .max(0.0)
                        })
                        .unwrap_or(0.0);
                    let protocol_seconds = (wall_seconds - build_seconds).max(0.0);
                    let tpke_seconds = (protocol_seconds - acs_seconds).max(0.0);
                    if let Some(pool) = rust_broadcast_mempool.as_mut() {
                        if reuse_enabled {
                            let selected_id_set = selected_proposal_ids
                                .iter()
                                .cloned()
                                .collect::<BTreeSet<_>>();
                            for proposal in proposal_store.values() {
                                if selected_id_set.contains(&proposal.proposal_id) {
                                    continue;
                                }
                                pool.add_reusable(
                                    proposal.payload.clone(),
                                    proposal.digest.clone(),
                                    proposal.certificate.clone(),
                                    round_id as u32,
                                    proposal.proposer as u32,
                                );
                            }
                        }
                        for item_id in &consumed_reference_ids {
                            pool.mark_selected(item_id, round_id as u32);
                            pool.mark_consumed(item_id, round_id as u32);
                        }
                    }
                    driver_stats.active_sweeps += 1;
                    return Ok(DriverRoundOutcome {
                        build_seconds,
                        acs_seconds,
                        tpke_seconds,
                        protocol_seconds,
                        wall_seconds,
                        acs_pull_seconds,
                        tpke_partial_open_seconds,
                        tpke_combine_seconds,
                        acs_pull_calls,
                        acs_empty_pull_calls,
                        acs_inbound_wire_batches,
                        acs_inbound_wire_items,
                        acs_outbound_events,
                        tpke_combine_calls,
                        stale_acs_frames_dropped,
                        selected_proposal_ids: selected_proposal_ids.clone(),
                        selected_pids: selected_pids.clone(),
                        reused_reference_count,
                        delivered_count,
                        block_payload,
                        driver_stats,
                    });
                }
            }
        }

        if !progressed {
            driver_stats.idle_sweeps += 1;
            driver_stats.idle_backoff_count += 1;
            thread::sleep(DRIVER_IDLE_BACKOFF);
            continue;
        }
        driver_stats.active_sweeps += 1;
    }

    Err(format!(
        "driver round {round_id}: timed out after {:.3}s",
        ctx.args.global_timeout
    ))
}

pub(super) fn run_driver_rounds(
    host: &dyn AcsHost,
    transport: &LocalTcpTransport,
    public_key: &HbPkePublicParams,
    private_share: &HbPkePrivateKeyShare,
    args: &RunDriverNodeArgs,
    broadcast_pool_config: &BroadcastPoolConfig,
) -> Result<(DriverNodeResult, QueuePeaksSnapshot), String> {
    let mut queue_peaks = QueuePeaksSnapshot::default();
    let mut carryovers = DriverCarryovers::default();
    let mut batch_archive: BatchArchive = BatchArchive::new();
    let mut round_build_latencies = Vec::with_capacity(args.rounds);
    let mut acs_latencies = Vec::with_capacity(args.rounds);
    let mut tpke_stage_latencies = Vec::with_capacity(args.rounds);
    let mut round_latencies = Vec::with_capacity(args.rounds);
    let mut round_wall_latencies = Vec::with_capacity(args.rounds);
    let mut acs_pull_latencies = Vec::with_capacity(args.rounds);
    let mut tpke_partial_open_latencies = Vec::with_capacity(args.rounds);
    let mut tpke_combine_latencies = Vec::with_capacity(args.rounds);
    let mut round_proposed_counts = Vec::with_capacity(args.rounds);
    let mut round_delivered_counts = Vec::with_capacity(args.rounds);
    let mut origin_tx_latencies_by_round = Vec::with_capacity(args.rounds);
    let mut acs_pull_calls = Vec::with_capacity(args.rounds);
    let mut acs_empty_pull_calls = Vec::with_capacity(args.rounds);
    let mut acs_inbound_wire_batches = Vec::with_capacity(args.rounds);
    let mut acs_inbound_wire_items = Vec::with_capacity(args.rounds);
    let mut acs_outbound_events = Vec::with_capacity(args.rounds);
    let mut tpke_combine_calls = Vec::with_capacity(args.rounds);
    let mut stale_acs_frames_dropped = Vec::with_capacity(args.rounds);
    let mut chain_digest = GENESIS_CHAIN_DIGEST;
    let mut per_round_selected_pids = Vec::with_capacity(args.rounds);
    let mut per_round_block_digests = Vec::with_capacity(args.rounds);
    let mut per_round_block_sizes = Vec::with_capacity(args.rounds);
    let mut per_round_chain_digests = Vec::with_capacity(args.rounds);
    let mut round_details = Vec::with_capacity(args.rounds);
    let mut rust_broadcast_mempool = match broadcast_pool_config.backend {
        BroadcastPoolBackend::Rust => Some(BroadcastMempool::new(
            broadcast_pool_config.max_size,
            broadcast_pool_config.expire_rounds,
        )),
        BroadcastPoolBackend::None => None,
    };
    let ctx = DriverRoundCtx {
        host,
        transport,
        public_key,
        private_share,
        args,
        broadcast_pool_config,
    };

    for round_id in 0..args.rounds {
        let round_outcome = run_driver_round(
            &ctx,
            round_id,
            &mut carryovers,
            &mut batch_archive,
            &mut queue_peaks,
            &mut rust_broadcast_mempool,
        )?;
        round_build_latencies.push(round_outcome.build_seconds);
        acs_latencies.push(round_outcome.acs_seconds);
        tpke_stage_latencies.push(round_outcome.tpke_seconds);
        round_latencies.push(round_outcome.protocol_seconds);
        round_wall_latencies.push(round_outcome.wall_seconds);
        acs_pull_latencies.push(round_outcome.acs_pull_seconds);
        tpke_partial_open_latencies.push(round_outcome.tpke_partial_open_seconds);
        tpke_combine_latencies.push(round_outcome.tpke_combine_seconds);
        round_proposed_counts.push(args.batch_size);
        round_delivered_counts.push(round_outcome.delivered_count);
        acs_pull_calls.push(round_outcome.acs_pull_calls);
        acs_empty_pull_calls.push(round_outcome.acs_empty_pull_calls);
        acs_inbound_wire_batches.push(round_outcome.acs_inbound_wire_batches);
        acs_inbound_wire_items.push(round_outcome.acs_inbound_wire_items);
        acs_outbound_events.push(round_outcome.acs_outbound_events);
        tpke_combine_calls.push(round_outcome.tpke_combine_calls);
        stale_acs_frames_dropped.push(round_outcome.stale_acs_frames_dropped);
        per_round_selected_pids.push(round_outcome.selected_pids.clone());
        let block_digest = crate::sha256_hex(&round_outcome.block_payload);
        let block_size = round_outcome.block_payload.len();
        per_round_block_digests.push(block_digest.clone());
        per_round_block_sizes.push(block_size);
        chain_digest =
            crate::compute_chain_digest(&chain_digest, round_id, &round_outcome.block_payload);
        let chain_digest_hex = crate::hex_encode(&chain_digest);
        per_round_chain_digests.push(chain_digest_hex.clone());
        origin_tx_latencies_by_round.push(if round_outcome.selected_pids.contains(&args.pid) {
            vec![round_outcome.wall_seconds; args.batch_size]
        } else {
            Vec::new()
        });
        round_details.push(DriverNodeRoundTelemetry {
            selected_proposal_ids: round_outcome.selected_proposal_ids.clone(),
            selected_pids: round_outcome.selected_pids,
            block_digest,
            block_size,
            chain_digest: chain_digest_hex,
            build_seconds: round_outcome.build_seconds,
            acs_seconds: round_outcome.acs_seconds,
            tpke_seconds: round_outcome.tpke_seconds,
            protocol_seconds: round_outcome.protocol_seconds,
            wall_seconds: round_outcome.wall_seconds,
            delivered_count: round_outcome.delivered_count,
            reused_reference_count: round_outcome.reused_reference_count,
            tpke_partial_open_seconds: round_outcome.tpke_partial_open_seconds,
            tpke_combine_seconds: round_outcome.tpke_combine_seconds,
            acs_outbound_events: round_outcome.acs_outbound_events,
            tpke_combine_calls: round_outcome.tpke_combine_calls,
            driver_phase_stats: round_outcome.driver_stats,
        });
        if let Some(pool) = rust_broadcast_mempool.as_mut() {
            pool.cleanup(round_id as u32);
        }
        let expire_before = (round_id as u32).saturating_sub(broadcast_pool_config.expire_rounds);
        batch_archive.retain(|(origin_round, _), _| *origin_round >= expire_before);
    }

    Ok((
        DriverNodeResult {
            round_build_latencies,
            acs_latencies,
            tpke_stage_latencies,
            round_latencies,
            round_wall_latencies,
            acs_pull_latencies,
            tpke_partial_open_latencies,
            tpke_combine_latencies,
            round_proposed_counts,
            round_delivered_counts,
            origin_tx_latencies_by_round,
            acs_pull_calls,
            acs_empty_pull_calls,
            acs_inbound_wire_batches,
            acs_inbound_wire_items,
            acs_outbound_events,
            tpke_combine_calls,
            stale_acs_frames_dropped,
            chain_digest: crate::hex_encode(&chain_digest),
            per_round_selected_pids,
            per_round_block_digests,
            per_round_block_sizes,
            per_round_chain_digests,
            round_details,
            rust_broadcast_mempool_size: rust_broadcast_mempool
                .as_ref()
                .map(BroadcastMempool::len)
                .unwrap_or(0),
            broadcast_pool_backend: broadcast_pool_config.backend,
        },
        queue_peaks,
    ))
}
