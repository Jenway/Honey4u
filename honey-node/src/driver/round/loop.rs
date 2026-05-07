use super::acs_io::{AcsPumpState, pump_acs_host};
use super::inbox::{RoundTransportInbox, drain_transport_into_round, update_queue_peaks};
use super::metrics::RoundMetricsRecorder;
use super::proposal::{
    build_acs_proposal_input, build_driver_round_batch, collect_selected_proposals,
    selected_pids_from_proposals,
};
use super::state::{
    DriverCarryovers, DriverNodeResult, DriverRoundCtx, DriverRoundOutcome, DriverRunAccumulator,
    QueuePeaksSnapshot,
};
use super::tpke::{TpkeRoundState, TpkeStepContext, decoded_tx_count, run_tpke_step};
use crate::driver::DRIVER_IDLE_BACKOFF;
use crate::driver::args::NodeRuntimeArgs;
use crate::driver::config::{BroadcastPoolConfig, ByzantineNodeConfig};
use crate::driver::encryption::{
    HbPkePrivateKeyShare, HbPkePublicParams, seal_encrypted_batch as seal_hb_encrypted_batch,
};
use crate::driver::error::{DriverError, DriverResult};
use crate::driver::mempool::fetch::{
    FetchRequestAction, IncrementalProposalResolver, PoolFetchTracker,
};
use crate::driver::mempool::pool::{BroadcastMempool, encode_bundle_acs_payload};
use honey_acs::AcsBackend;
use honey_acs::proposal::ProposalStore;
use honey_transport::TransportHandle;
use std::collections::{BTreeMap, BTreeSet};
use std::thread;
use std::time::{Duration, Instant};

struct TimeoutStageSnapshot<'a> {
    selected_proposal_ids: Option<&'a [String]>,
    proposal_store: &'a ProposalStore,
    payload_resolution_complete: bool,
    pending_fetch_count: usize,
    inbound_acs_wire_count: usize,
    pending_fetch_request_count: usize,
    pending_fetch_response_count: usize,
    pending_tpke_share_count: usize,
    known_tpke_item_count: usize,
    ready_local_share_count: usize,
    verified_share_count: usize,
}

fn run_driver_round(
    ctx: &DriverRoundCtx<'_>,
    round_id: usize,
    carryovers: &mut DriverCarryovers,
    queue_peaks: &mut QueuePeaksSnapshot,
    rust_broadcast_mempool: &mut Option<BroadcastMempool>,
) -> DriverResult<DriverRoundOutcome> {
    let result = run_driver_round_inner(
        ctx,
        round_id,
        carryovers,
        queue_peaks,
        rust_broadcast_mempool,
    );
    ctx.transport.unregister_wakeup_waiter();
    match ctx.host.finish_round(round_id) {
        Ok(()) => result,
        Err(message) if result.is_ok() => Err(DriverError::acs("finish_round", message)),
        Err(_) => result,
    }
}

fn run_driver_round_inner(
    ctx: &DriverRoundCtx<'_>,
    round_id: usize,
    carryovers: &mut DriverCarryovers,
    queue_peaks: &mut QueuePeaksSnapshot,
    rust_broadcast_mempool: &mut Option<BroadcastMempool>,
) -> DriverResult<DriverRoundOutcome> {
    let round_wall_start = Instant::now();
    let round_sid = format!("{}:{round_id}:", ctx.args.sid);
    let round_build_start = Instant::now();
    let batch = build_driver_round_batch(round_id, ctx.args.pid, ctx.args.batch_size)?;
    let sealed_batch = seal_hb_encrypted_batch(ctx.public_key, &batch)?;
    let build_seconds = round_build_start.elapsed().as_secs_f64();
    let byzantine_is_silent = ctx.byzantine_node_config.is_silent();
    let mut metrics = RoundMetricsRecorder::new(ctx.args.nodes);

    let reuse_enabled = ctx.args.acs_backend.is_dumbo() && ctx.broadcast_pool_config.enable_reuse;
    let proposal_input = if byzantine_is_silent {
        metrics.byzantine().empty_proposal();
        encode_bundle_acs_payload(b"", &[])
    } else {
        build_acs_proposal_input(
            round_id,
            &sealed_batch,
            rust_broadcast_mempool.as_ref(),
            ctx.broadcast_pool_config,
        )
    };
    ctx.host
        .start_round(round_id, &round_sid, &proposal_input)
        .map_err(|message| DriverError::acs("start_round", message))?;

    let deadline = Instant::now() + Duration::from_secs_f64(ctx.args.global_timeout);
    let mut proposal_store: ProposalStore = BTreeMap::new();
    let mut selected_proposal_ids: Option<Vec<String>> = None;
    let mut selected_pids: Option<Vec<usize>> = None;
    let mut proposal_resolver: Option<IncrementalProposalResolver> = None;
    let mut payload_resolution_complete = false;
    let mut tpke_state = TpkeRoundState::default();
    let mut inbound_acs_wire = carryovers
        .acs_wire_payloads
        .remove(&round_id)
        .unwrap_or_default();
    let mut pending_pool_fetch_requests = Vec::new();
    let mut pending_pool_fetch_responses = carryovers
        .pool_fetch_responses
        .remove(&round_id)
        .unwrap_or_default();
    let mut pending_tpke_shares = carryovers.tpke_shares.remove(&round_id).unwrap_or_default();
    let mut pool_fetch_tracker = PoolFetchTracker::default();
    let mut acs_decision_at: Option<Instant> = None;

    ctx.transport.register_wakeup_waiter(thread::current());
    while Instant::now() < deadline {
        let pending_deliveries =
            ctx.transport.pending_inbound() + inbound_acs_wire.len() + pending_tpke_shares.len();
        metrics.round().sweep(pending_deliveries);
        let mut progressed = false;
        let frame_count = {
            let mut inbox = RoundTransportInbox {
                inbound_acs_wire: &mut inbound_acs_wire,
                pending_pool_fetch_requests: &mut pending_pool_fetch_requests,
                pending_pool_fetch_responses: &mut pending_pool_fetch_responses,
                pending_tpke_shares: &mut pending_tpke_shares,
            };
            drain_transport_into_round(ctx.transport, round_id, carryovers, &mut inbox)?
        };
        metrics.round().transport_drain(frame_count);
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
                            metrics.fetch().response_served();
                            progressed = true;
                        }
                        FetchRequestAction::IgnoredByzantine => {
                            metrics.byzantine().fetch_ignored();
                        }
                        FetchRequestAction::InvalidResponseSent => {
                            metrics.byzantine().invalid_fetch_response();
                            progressed = true;
                        }
                    }
                }
                for response in pending_pool_fetch_responses.drain(..) {
                    metrics.fetch().response_received();
                    let inserted = pool_fetch_tracker.handle_response(
                        pool,
                        ctx.args.nodes,
                        ctx.args.faulty,
                        response,
                    )?;
                    metrics.fetch().reference_inserted(inserted);
                    progressed |= inserted;
                }
            } else {
                pending_pool_fetch_requests.clear();
                pending_pool_fetch_responses.clear();
            }
            update_queue_peaks(ctx.transport, queue_peaks);
        }

        let grace_active = post_decision_grace_active(
            selected_proposal_ids.is_some(),
            acs_decision_at,
            reuse_enabled,
            ctx.broadcast_pool_config.grace_ms,
        );
        let accept_inbound_acs = selected_proposal_ids.is_none() || grace_active;

        progressed |= pump_acs_host(
            ctx,
            round_id,
            AcsPumpState {
                inbound_acs_wire: &mut inbound_acs_wire,
                proposal_store: &mut proposal_store,
                selected_proposal_ids: &mut selected_proposal_ids,
                acs_decision_at: &mut acs_decision_at,
                metrics: &mut metrics,
            },
            accept_inbound_acs,
        )?
        .progressed;

        if selected_proposal_ids.is_some() && !inbound_acs_wire.is_empty() {
            metrics.acs().stale_frames(inbound_acs_wire.len());
            inbound_acs_wire.clear();
            progressed = true;
        }
        update_queue_peaks(ctx.transport, queue_peaks);

        if let Some(selected_proposal_ids) = selected_proposal_ids.as_ref() {
            if proposal_resolver.is_none() {
                proposal_resolver = Some(IncrementalProposalResolver::new(
                    reuse_enabled && ctx.broadcast_pool_config.enable_fetch_fallback,
                ));
            }
            let pool = rust_broadcast_mempool.as_mut().ok_or_else(|| {
                DriverError::invariant("missing Rust mempool for proposal resolution")
            })?;
            let resolution_progress = proposal_resolver
                .as_mut()
                .expect("resolver must exist")
                .step(selected_proposal_ids, &proposal_store, pool)
                .map_err(DriverError::from)?;
            for reference in resolution_progress.missing_references {
                let requested = pool_fetch_tracker.request_reference(
                    ctx.transport,
                    round_id,
                    ctx.args.pid,
                    ctx.args.nodes,
                    &reference,
                )?;
                metrics.fetch().request_sent(requested);
                progressed |= requested;
            }
            payload_resolution_complete = resolution_progress.complete;
            if payload_resolution_complete && selected_pids.is_none() {
                let selected_proposals =
                    collect_selected_proposals(selected_proposal_ids, &proposal_store).ok_or_else(
                        || {
                            DriverError::invariant(format!(
                                "driver round {round_id}: missing selected proposals at resolution completion"
                            ))
                        },
                    )?;
                selected_pids = Some(selected_pids_from_proposals(&selected_proposals));
            }

            let tpke_outcome = run_tpke_step(
                TpkeStepContext {
                    ctx,
                    round_id,
                    newly_resolved_items: &resolution_progress.newly_resolved_items,
                    resolution_complete: payload_resolution_complete,
                    pending_tpke_shares: &mut pending_tpke_shares,
                    metrics: &mut metrics,
                    queue_peaks,
                },
                &mut tpke_state,
            )?;
            progressed |= tpke_outcome.progressed;

            if let Some(block_payload) = tpke_outcome.block_payload {
                let delivered_count = decoded_tx_count(&block_payload)?;
                let wall_seconds = round_wall_start.elapsed().as_secs_f64();
                let acs_seconds = acs_decision_at
                    .map(|instant| {
                        (instant.duration_since(round_wall_start).as_secs_f64() - build_seconds)
                            .max(0.0)
                    })
                    .unwrap_or(0.0);
                let protocol_seconds = (wall_seconds - build_seconds).max(0.0);
                let tpke_seconds = (protocol_seconds - acs_seconds).max(0.0);
                let consumed_reference_ids = proposal_resolver
                    .as_ref()
                    .map(|resolver| resolver.consumed_reference_ids().to_vec())
                    .unwrap_or_default();
                let reused_reference_count = consumed_reference_ids.len();
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
                metrics.round().active_sweep();
                let metrics = metrics.finish();
                return Ok(DriverRoundOutcome {
                    build_seconds,
                    acs_seconds,
                    tpke_seconds,
                    protocol_seconds,
                    wall_seconds,
                    metrics,
                    selected_proposal_ids: selected_proposal_ids.clone(),
                    selected_pids: selected_pids.clone().unwrap_or_default(),
                    reused_reference_count,
                    delivered_count,
                    block_payload,
                });
            }
        }

        if !progressed {
            metrics.round().idle_backoff();
            thread::park_timeout(DRIVER_IDLE_BACKOFF);
            continue;
        }
        metrics.round().active_sweep();
    }

    Err(DriverError::Timeout {
        round_id,
        timeout_seconds: ctx.args.global_timeout,
        stage: timeout_stage_label(TimeoutStageSnapshot {
            selected_proposal_ids: selected_proposal_ids.as_deref(),
            proposal_store: &proposal_store,
            payload_resolution_complete,
            pending_fetch_count: pool_fetch_tracker.pending_references.len(),
            inbound_acs_wire_count: inbound_acs_wire.len(),
            pending_fetch_request_count: pending_pool_fetch_requests.len(),
            pending_fetch_response_count: pending_pool_fetch_responses.len(),
            pending_tpke_share_count: pending_tpke_shares.len(),
            known_tpke_item_count: tpke_state.known_item_count(),
            ready_local_share_count: tpke_state.local_share_broadcasted_count(),
            verified_share_count: tpke_state.verified_share_count(),
        }),
    })
}

fn post_decision_grace_active(
    has_decision: bool,
    decision_at: Option<Instant>,
    reuse_enabled: bool,
    grace_ms: u64,
) -> bool {
    has_decision
        && reuse_enabled
        && grace_ms > 0
        && decision_at.is_some_and(|instant| instant.elapsed() < Duration::from_millis(grace_ms))
}

fn timeout_stage_label(snapshot: TimeoutStageSnapshot<'_>) -> String {
    let TimeoutStageSnapshot {
        selected_proposal_ids,
        proposal_store,
        payload_resolution_complete,
        pending_fetch_count,
        inbound_acs_wire_count,
        pending_fetch_request_count,
        pending_fetch_response_count,
        pending_tpke_share_count,
        known_tpke_item_count,
        ready_local_share_count,
        verified_share_count,
    } = snapshot;
    let Some(selected_proposal_ids) = selected_proposal_ids else {
        return format!(
            "waiting for ACS decision (proposal_store={}, inbound_acs_wire={}, pending_fetch_requests={}, pending_fetch_responses={}, pending_tpke_shares={})",
            proposal_store.len(),
            inbound_acs_wire_count,
            pending_fetch_request_count,
            pending_fetch_response_count,
            pending_tpke_share_count,
        );
    };

    let missing_selected = selected_proposal_ids
        .iter()
        .filter(|proposal_id| !proposal_store.contains_key(*proposal_id))
        .count();
    if missing_selected > 0 {
        return format!(
            "waiting for selected proposal payloads (missing={}, selected={}, proposal_store={}, inbound_acs_wire={})",
            missing_selected,
            selected_proposal_ids.len(),
            proposal_store.len(),
            inbound_acs_wire_count,
        );
    }

    if !payload_resolution_complete {
        if pending_fetch_count > 0 {
            return format!(
                "waiting for pool fetch responses (pending_references={}, pending_fetch_requests={}, pending_fetch_responses={})",
                pending_fetch_count, pending_fetch_request_count, pending_fetch_response_count,
            );
        }
        return format!(
            "resolving selected proposal payloads (selected={}, proposal_store={}, pending_tpke_shares={})",
            selected_proposal_ids.len(),
            proposal_store.len(),
            pending_tpke_share_count,
        );
    }

    format!(
        "waiting for TPKE shares (local_share_items={}/{}, verified_shares={}, pending_tpke_shares={})",
        ready_local_share_count,
        known_tpke_item_count,
        verified_share_count,
        pending_tpke_share_count,
    )
}

pub(in crate::driver) fn run_driver_rounds(
    host: &dyn AcsBackend,
    transport: &dyn TransportHandle,
    public_key: &HbPkePublicParams,
    private_share: &HbPkePrivateKeyShare,
    args: &NodeRuntimeArgs,
    broadcast_pool_config: &BroadcastPoolConfig,
    byzantine_node_config: ByzantineNodeConfig,
) -> DriverResult<(DriverNodeResult, QueuePeaksSnapshot)> {
    let mut queue_peaks = QueuePeaksSnapshot::default();
    let mut carryovers = DriverCarryovers::default();
    let mut run_result = DriverRunAccumulator::new(args.rounds, byzantine_node_config);
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
            &mut queue_peaks,
            &mut rust_broadcast_mempool,
        )?;
        run_result.push_round(round_id, args.pid, args.batch_size, round_outcome);
        if let Some(pool) = rust_broadcast_mempool.as_mut() {
            pool.cleanup(round_id as u32);
        }
    }

    let mempool_size = rust_broadcast_mempool
        .as_ref()
        .map(BroadcastMempool::len)
        .unwrap_or(0);
    Ok((run_result.finish(mempool_size), queue_peaks))
}
