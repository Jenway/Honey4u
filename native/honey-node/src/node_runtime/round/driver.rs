use super::super::args::NodeRuntimeArgs;
use super::super::config::{BroadcastPoolConfig, ByzantineNodeConfig};
use super::super::digest::{GENESIS_CHAIN_DIGEST, compute_chain_digest, sha256_hex};
use super::super::io::current_time_millis;
use super::super::phase_stats::{DriverHostPhaseStats, DriverPhaseStats, record_pull, record_push};
use super::super::pool_reuse::{BroadcastMempool, encode_bundle_acs_payload};
use super::super::types::{
    BatchArchive, DriverCarryovers, DriverNodeResult, DriverNodeRoundTelemetry, DriverRoundCtx,
    DriverRoundOutcome, QueuePeaksSnapshot,
};
use super::super::wire::{
    DriverWireFrame, broadcast_frame, encode_driver_frame, fanout_encoded_payload, send_frame,
};
use super::super::{DRIVER_IDLE_BACKOFF, DRIVER_NETWORK_BATCH_LIMIT};
use super::batch::{
    batch_refs_from_selected_proposals, build_acs_proposal_input, build_driver_round_batch,
    collect_selected_proposals, remember_archived_batch, selected_pids_from_proposals,
};
use super::pool::{
    FetchRequestAction, PoolFetchTracker, ProposalResolutionError, resolve_selected_proposals,
};
use super::transport::{RoundTransportInbox, drain_transport_into_round, update_queue_peaks};
use crate::acs::proposal::ProposalStore;
use crate::acs::protocol::AcsProtocol;
use crate::acs::{AcsBackend, AcsEvent};
use crate::codec::hex_encode;
use honey_node::hb::{
    BatchDecryptor as HbBatchDecryptor, HbPkePrivateKeyShare, HbPkePublicParams,
    decode_tx_batch as decode_hb_tx_batch, merge_tx_batches_bytes as merge_hb_tx_batches_bytes,
    seal_encrypted_batch as seal_hb_encrypted_batch,
};
use honey_node::transport::LocalTcpTransport;
use std::collections::{BTreeMap, BTreeSet};
use std::thread;
use std::time::{Duration, Instant};

pub(in crate::node_runtime) fn wait_until_start(start_at_ms: Option<u64>) -> Result<(), String> {
    let Some(start_at_ms) = start_at_ms else {
        return Ok(());
    };
    let now_ms = current_time_millis()?;
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
    let byzantine_is_silent = ctx.byzantine_node_config.is_silent();
    let mut byzantine_invalid_fetch_responses_sent = 0usize;
    let mut byzantine_fetch_requests_ignored = 0usize;
    let mut byzantine_batch_broadcast_suppressed = 0usize;
    let mut byzantine_share_broadcast_suppressed = 0usize;
    let mut byzantine_empty_proposal_used = false;

    if byzantine_is_silent {
        byzantine_batch_broadcast_suppressed = 1;
    } else {
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
    }

    let reuse_enabled = matches!(ctx.args.acs_protocol, AcsProtocol::Dumbo)
        && ctx.broadcast_pool_config.enable_reuse;
    let proposal_input = if byzantine_is_silent {
        byzantine_empty_proposal_used = true;
        encode_bundle_acs_payload(b"", &[])
    } else {
        build_acs_proposal_input(
            round_id,
            ctx.args.pid,
            rust_broadcast_mempool.as_ref(),
            ctx.broadcast_pool_config,
        )
    };
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
    if !byzantine_is_silent {
        received_batches.entry(ctx.args.pid).or_insert(sealed_batch);
    }
    let mut pending_pool_fetch_requests = Vec::new();
    let mut pending_pool_fetch_responses = carryovers
        .pool_fetch_responses
        .remove(&round_id)
        .unwrap_or_default();
    let mut pending_share_bundles = carryovers
        .share_bundles
        .remove(&round_id)
        .unwrap_or_default();
    let mut pool_fetch_tracker = PoolFetchTracker::default();
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
    let mut fetch_requests_sent = 0usize;
    let mut fetch_responses_served = 0usize;
    let mut fetch_responses_received = 0usize;
    let mut fetched_reference_count = 0usize;
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
        let frame_count = {
            let mut inbox = RoundTransportInbox {
                inbound_acs_wire: &mut inbound_acs_wire,
                pending_pool_fetch_requests: &mut pending_pool_fetch_requests,
                pending_pool_fetch_responses: &mut pending_pool_fetch_responses,
                received_batches: &mut received_batches,
                pending_share_bundles: &mut pending_share_bundles,
            };
            drain_transport_into_round(
                ctx.transport,
                round_id,
                carryovers,
                batch_archive,
                &mut inbox,
            )?
        };
        if frame_count > 0 {
            progressed = true;
        }
        update_queue_peaks(ctx.transport, queue_peaks);

        if !pending_pool_fetch_requests.is_empty() || !pending_pool_fetch_responses.is_empty() {
            if let Some(pool) = rust_broadcast_mempool.as_mut() {
                for request in pending_pool_fetch_requests.drain(..) {
                    match pool_fetch_tracker.handle_request(
                        ctx.transport,
                        ctx.args.pid,
                        pool,
                        request.round_id,
                        request.message,
                        ctx.byzantine_node_config,
                    )? {
                        FetchRequestAction::None => {}
                        FetchRequestAction::Served => {
                            fetch_responses_served += 1;
                            progressed = true;
                        }
                        FetchRequestAction::IgnoredByzantine => {
                            byzantine_fetch_requests_ignored += 1;
                        }
                        FetchRequestAction::InvalidResponseSent => {
                            byzantine_invalid_fetch_responses_sent += 1;
                            progressed = true;
                        }
                    }
                }
                for response in pending_pool_fetch_responses.drain(..) {
                    fetch_responses_received += 1;
                    let inserted = pool_fetch_tracker.handle_response(
                        pool,
                        ctx.args.nodes,
                        ctx.args.faulty,
                        response,
                    )?;
                    fetched_reference_count += usize::from(inserted);
                    progressed |= inserted;
                }
            } else {
                pending_pool_fetch_requests.clear();
                pending_pool_fetch_responses.clear();
            }
            update_queue_peaks(ctx.transport, queue_peaks);
        }

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
                    AcsEvent::Send {
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
                    AcsEvent::Broadcast {
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
                    AcsEvent::ProposalAvailable {
                        round_id: event_round_id,
                        proposal,
                    } => {
                        if event_round_id != round_id {
                            return Err(format!(
                                "driver round {round_id}: proposal_ready carried mismatched round_id {event_round_id}"
                            ));
                        }
                        driver_stats.proposal_available_events += 1;
                        driver_stats.proposal_available_payload_bytes += proposal.payload.len();
                        driver_stats.proposal_available_proof_bytes +=
                            proposal.availability_proof.len();
                        proposal_store.insert(proposal.proposal_id.clone(), proposal);
                    }
                    AcsEvent::Decided {
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
                    AcsEvent::Failure {
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

            let mut waiting_for_fetch = false;
            if selected_batch_refs.is_none() {
                if reuse_enabled {
                    let pool = rust_broadcast_mempool.as_mut().ok_or_else(|| {
                        String::from("missing Rust mempool for proposal resolution")
                    })?;
                    match resolve_selected_proposals(
                        &selected_proposals,
                        pool,
                        ctx.broadcast_pool_config.enable_fetch_fallback,
                    ) {
                        Ok(resolved) => {
                            reused_reference_count = resolved.consumed_reference_ids.len();
                            consumed_reference_ids = resolved.consumed_reference_ids;
                            selected_batch_refs = Some(resolved.batch_refs);
                        }
                        Err(ProposalResolutionError::MissingReusableEntry(reference)) => {
                            if !ctx.broadcast_pool_config.enable_fetch_fallback {
                                return Err(format!(
                                    "missing reusable entry {} during payload resolution",
                                    reference.item_id
                                ));
                            }
                            let requested = pool_fetch_tracker.request_reference(
                                ctx.transport,
                                round_id,
                                ctx.args.pid,
                                ctx.args.nodes,
                                &reference,
                            )?;
                            fetch_requests_sent += usize::from(requested);
                            progressed |= requested;
                            waiting_for_fetch = true;
                        }
                        Err(ProposalResolutionError::Invalid(err)) => return Err(err),
                    }
                } else {
                    selected_batch_refs =
                        Some(batch_refs_from_selected_proposals(&selected_proposals)?);
                }
            }

            if waiting_for_fetch {
                if !progressed {
                    driver_stats.idle_sweeps += 1;
                    driver_stats.idle_backoff_count += 1;
                    thread::sleep(DRIVER_IDLE_BACKOFF);
                } else {
                    driver_stats.active_sweeps += 1;
                }
                continue;
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
                if byzantine_is_silent {
                    byzantine_share_broadcast_suppressed = 1;
                } else {
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
                }
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
                                    proposal.availability_proof.clone(),
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
                        fetch_requests_sent,
                        fetch_responses_served,
                        fetch_responses_received,
                        fetched_reference_count,
                        byzantine_invalid_fetch_responses_sent,
                        byzantine_fetch_requests_ignored,
                        byzantine_batch_broadcast_suppressed,
                        byzantine_share_broadcast_suppressed,
                        byzantine_empty_proposal_used,
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

pub(in crate::node_runtime) fn run_driver_rounds(
    host: &dyn AcsBackend,
    transport: &LocalTcpTransport,
    public_key: &HbPkePublicParams,
    private_share: &HbPkePrivateKeyShare,
    args: &NodeRuntimeArgs,
    broadcast_pool_config: &BroadcastPoolConfig,
    byzantine_node_config: ByzantineNodeConfig,
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
    let mut fetch_requests_sent = Vec::with_capacity(args.rounds);
    let mut fetch_responses_served = Vec::with_capacity(args.rounds);
    let mut fetch_responses_received = Vec::with_capacity(args.rounds);
    let mut fetched_reference_count = Vec::with_capacity(args.rounds);
    let mut byzantine_invalid_fetch_responses_sent = Vec::with_capacity(args.rounds);
    let mut byzantine_fetch_requests_ignored = Vec::with_capacity(args.rounds);
    let mut byzantine_batch_broadcast_suppressed = Vec::with_capacity(args.rounds);
    let mut byzantine_share_broadcast_suppressed = Vec::with_capacity(args.rounds);
    let mut byzantine_empty_proposal_used = Vec::with_capacity(args.rounds);
    let mut chain_digest = GENESIS_CHAIN_DIGEST;
    let mut per_round_selected_pids = Vec::with_capacity(args.rounds);
    let mut per_round_block_digests = Vec::with_capacity(args.rounds);
    let mut per_round_block_sizes = Vec::with_capacity(args.rounds);
    let mut per_round_chain_digests = Vec::with_capacity(args.rounds);
    let mut round_details = Vec::with_capacity(args.rounds);
    let mut rust_broadcast_mempool = Some(BroadcastMempool::new(
        broadcast_pool_config.max_size,
        broadcast_pool_config.expire_rounds,
    ));
    let ctx = DriverRoundCtx {
        host,
        transport,
        public_key,
        private_share,
        args,
        broadcast_pool_config,
        byzantine_node_config,
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
        fetch_requests_sent.push(round_outcome.fetch_requests_sent);
        fetch_responses_served.push(round_outcome.fetch_responses_served);
        fetch_responses_received.push(round_outcome.fetch_responses_received);
        fetched_reference_count.push(round_outcome.fetched_reference_count);
        byzantine_invalid_fetch_responses_sent
            .push(round_outcome.byzantine_invalid_fetch_responses_sent);
        byzantine_fetch_requests_ignored.push(round_outcome.byzantine_fetch_requests_ignored);
        byzantine_batch_broadcast_suppressed
            .push(round_outcome.byzantine_batch_broadcast_suppressed);
        byzantine_share_broadcast_suppressed
            .push(round_outcome.byzantine_share_broadcast_suppressed);
        byzantine_empty_proposal_used.push(round_outcome.byzantine_empty_proposal_used);
        per_round_selected_pids.push(round_outcome.selected_pids.clone());
        let block_digest = sha256_hex(&round_outcome.block_payload);
        let block_size = round_outcome.block_payload.len();
        per_round_block_digests.push(block_digest.clone());
        per_round_block_sizes.push(block_size);
        chain_digest = compute_chain_digest(&chain_digest, round_id, &round_outcome.block_payload);
        let chain_digest_hex = hex_encode(&chain_digest);
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
            fetch_requests_sent: round_outcome.fetch_requests_sent,
            fetch_responses_served: round_outcome.fetch_responses_served,
            fetch_responses_received: round_outcome.fetch_responses_received,
            fetched_reference_count: round_outcome.fetched_reference_count,
            byzantine_invalid_fetch_responses_sent: round_outcome
                .byzantine_invalid_fetch_responses_sent,
            byzantine_fetch_requests_ignored: round_outcome.byzantine_fetch_requests_ignored,
            byzantine_batch_broadcast_suppressed: round_outcome
                .byzantine_batch_broadcast_suppressed,
            byzantine_share_broadcast_suppressed: round_outcome
                .byzantine_share_broadcast_suppressed,
            byzantine_empty_proposal_used: round_outcome.byzantine_empty_proposal_used,
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
            fetch_requests_sent,
            fetch_responses_served,
            fetch_responses_received,
            fetched_reference_count,
            byzantine_invalid_fetch_responses_sent,
            byzantine_fetch_requests_ignored,
            byzantine_batch_broadcast_suppressed,
            byzantine_share_broadcast_suppressed,
            byzantine_empty_proposal_used,
            byzantine_behavior: byzantine_node_config.behavior_label(),
            chain_digest: hex_encode(&chain_digest),
            per_round_selected_pids,
            per_round_block_digests,
            per_round_block_sizes,
            per_round_chain_digests,
            round_details,
            rust_broadcast_mempool_size: rust_broadcast_mempool
                .as_ref()
                .map(BroadcastMempool::len)
                .unwrap_or(0),
        },
        queue_peaks,
    ))
}
