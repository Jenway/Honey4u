use super::*;
use crate::drive_acs::{driver_phase_stats_json, record_pull, record_push};
use bincode::{deserialize, serialize};
use honey_native::transport::LocalTcpTransport;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const DRIVER_NETWORK_BATCH_LIMIT: usize = 512;
const DRIVER_IDLE_BACKOFF: Duration = Duration::from_micros(50);

#[derive(Serialize, Deserialize)]
enum DriverWireFrame {
    AcsEnvelope {
        round_id: usize,
        payload: Vec<u8>,
    },
    HbBatch {
        sender: usize,
        round_id: usize,
        sealed_batch: Vec<u8>,
    },
    HbShareBundle {
        sender: usize,
        round_id: usize,
        selected_pids: Vec<usize>,
        shares: Vec<Option<Vec<u8>>>,
    },
}

#[derive(Default)]
struct DriverCarryovers {
    acs_wire_payloads: BTreeMap<usize, Vec<Vec<u8>>>,
    sealed_batches: BTreeMap<usize, BTreeMap<usize, Vec<u8>>>,
    share_bundles: BTreeMap<usize, Vec<InboundShareBundle>>,
}

struct InboundShareBundle {
    sender: usize,
    selected_pids: Vec<usize>,
    shares: Vec<Option<Vec<u8>>>,
}

#[derive(Default)]
struct QueuePeaksSnapshot {
    raw_inbound_messages: usize,
    raw_outbound_messages: usize,
    transport_inbound: usize,
    transport_outbound: usize,
}

struct DriverRoundOutcome {
    build_seconds: f64,
    acs_seconds: f64,
    tpke_seconds: f64,
    protocol_seconds: f64,
    wall_seconds: f64,
    acs_pull_seconds: f64,
    tpke_partial_open_seconds: f64,
    tpke_combine_seconds: f64,
    acs_pull_calls: usize,
    acs_empty_pull_calls: usize,
    acs_inbound_wire_batches: usize,
    acs_inbound_wire_items: usize,
    acs_outbound_events: usize,
    tpke_combine_calls: usize,
    stale_acs_frames_dropped: usize,
    selected_pids: Vec<usize>,
    delivered_count: usize,
    block_payload: Vec<u8>,
    driver_stats: DriverPhaseStats,
}

struct DriverNodeRoundTelemetry {
    selected_pids: Vec<usize>,
    block_digest: String,
    block_size: usize,
    chain_digest: String,
    build_seconds: f64,
    acs_seconds: f64,
    tpke_seconds: f64,
    protocol_seconds: f64,
    wall_seconds: f64,
    delivered_count: usize,
    tpke_partial_open_seconds: f64,
    tpke_combine_seconds: f64,
    acs_outbound_events: usize,
    tpke_combine_calls: usize,
    driver_phase_stats: DriverPhaseStats,
}

struct DriverRoundCtx<'a> {
    host: &'a PyAcsHost,
    transport: &'a LocalTcpTransport,
    public_key: &'a HbPkePublicParams,
    private_share: &'a HbPkePrivateKeyShare,
    args: &'a RunDriverNodeArgs,
}

struct DriverNodeResult {
    round_build_latencies: Vec<f64>,
    acs_latencies: Vec<f64>,
    tpke_stage_latencies: Vec<f64>,
    round_latencies: Vec<f64>,
    round_wall_latencies: Vec<f64>,
    acs_pull_latencies: Vec<f64>,
    tpke_partial_open_latencies: Vec<f64>,
    tpke_combine_latencies: Vec<f64>,
    round_proposed_counts: Vec<usize>,
    round_delivered_counts: Vec<usize>,
    origin_tx_latencies_by_round: Vec<Vec<f64>>,
    acs_pull_calls: Vec<usize>,
    acs_empty_pull_calls: Vec<usize>,
    acs_inbound_wire_batches: Vec<usize>,
    acs_inbound_wire_items: Vec<usize>,
    acs_outbound_events: Vec<usize>,
    tpke_combine_calls: Vec<usize>,
    stale_acs_frames_dropped: Vec<usize>,
    chain_digest: String,
    /// Per-round selected PIDs (BFT consensus output); index = round_id.
    per_round_selected_pids: Vec<Vec<usize>>,
    /// Per-round SHA-256 hex of the decrypted block payload; index = round_id.
    per_round_block_digests: Vec<String>,
    /// Per-round block payload sizes in bytes; index = round_id.
    per_round_block_sizes: Vec<usize>,
    /// Per-round cumulative chain_digest (hex); index = round_id.
    per_round_chain_digests: Vec<String>,
    /// Rich per-round telemetry used by the multi-process drive-hb coordinator.
    round_details: Vec<DriverNodeRoundTelemetry>,
}

fn encode_driver_frame(frame: &DriverWireFrame) -> Result<Vec<u8>, String> {
    serialize(frame).map_err(|err| err.to_string())
}

fn decode_driver_frame(payload: &[u8]) -> Result<DriverWireFrame, String> {
    deserialize(payload).map_err(|err| err.to_string())
}

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

fn encode_proposal_ref(pid: usize) -> Vec<u8> {
    (pid as u64).to_be_bytes().to_vec()
}

fn update_queue_peaks(transport: &LocalTcpTransport, peaks: &mut QueuePeaksSnapshot) {
    let pending_inbound = transport.pending_inbound();
    let pending_outbound = transport.pending_outbound();
    peaks.raw_inbound_messages = peaks.raw_inbound_messages.max(pending_inbound);
    peaks.raw_outbound_messages = peaks.raw_outbound_messages.max(pending_outbound);
    peaks.transport_inbound = peaks.transport_inbound.max(pending_inbound);
    peaks.transport_outbound = peaks.transport_outbound.max(pending_outbound);
}

fn timing_summary_json(samples: &[f64]) -> Value {
    if samples.is_empty() {
        return json!({
            "sample_count": 0usize,
            "total_seconds": 0.0f64,
            "max_seconds": 0.0f64,
        });
    }
    let total_seconds = samples.iter().sum::<f64>();
    let max_seconds = samples.iter().copied().fold(0.0f64, f64::max);
    json!({
        "sample_count": samples.len(),
        "total_seconds": total_seconds,
        "max_seconds": max_seconds,
    })
}

fn send_frame(
    transport: &LocalTcpTransport,
    recipient: usize,
    frame: &DriverWireFrame,
) -> Result<(), String> {
    let payload = encode_driver_frame(frame)?;
    transport
        .send(recipient, &payload)
        .map_err(|err| err.to_string())
}

fn broadcast_frame(
    transport: &LocalTcpTransport,
    nodes: usize,
    frame: &DriverWireFrame,
) -> Result<(), String> {
    for recipient in 0..nodes {
        send_frame(transport, recipient, frame)?;
    }
    Ok(())
}

fn build_node_result_json(
    pid: usize,
    batch_size: usize,
    run_result: DriverNodeResult,
    host_stats: PyAcsHostStats,
    transport: &LocalTcpTransport,
    queue_peaks: &QueuePeaksSnapshot,
) -> Result<String, String> {
    let round_proposed_counts = run_result.round_proposed_counts;
    let round_build_latencies = run_result.round_build_latencies;
    let acs_latencies = run_result.acs_latencies;
    let tpke_stage_latencies = run_result.tpke_stage_latencies;
    let round_latencies = run_result.round_latencies;
    let round_wall_latencies = run_result.round_wall_latencies;
    let acs_pull_latencies = run_result.acs_pull_latencies;
    let tpke_partial_open_latencies = run_result.tpke_partial_open_latencies;
    let tpke_combine_latencies = run_result.tpke_combine_latencies;
    let round_delivered_counts = run_result.round_delivered_counts;
    let origin_tx_latencies_by_round = run_result.origin_tx_latencies_by_round;
    let acs_pull_calls = run_result.acs_pull_calls;
    let acs_empty_pull_calls = run_result.acs_empty_pull_calls;
    let acs_inbound_wire_batches = run_result.acs_inbound_wire_batches;
    let acs_inbound_wire_items = run_result.acs_inbound_wire_items;
    let acs_outbound_events = run_result.acs_outbound_events;
    let tpke_combine_calls = run_result.tpke_combine_calls;
    let stale_acs_frames_dropped = run_result.stale_acs_frames_dropped;
    let origin_tx_latencies = origin_tx_latencies_by_round
        .iter()
        .flat_map(|samples| samples.iter().copied())
        .collect::<Vec<_>>();
    let delivered_total = round_delivered_counts.iter().sum::<usize>();
    let node_run_total = round_wall_latencies.iter().sum::<f64>();
    let transport_stats = transport.stats();

    serde_json::to_string(&json!({
        "pid": pid,
        "rounds": round_delivered_counts.len(),
        "delivered": delivered_total,
        "round_build_latencies": round_build_latencies,
        "round_latencies": round_latencies,
        "round_wall_latencies": round_wall_latencies,
        "round_proposed_counts": round_proposed_counts,
        "round_delivered_counts": round_delivered_counts,
        "origin_tx_latencies": origin_tx_latencies,
        "origin_tx_latencies_by_round": origin_tx_latencies_by_round,
        "chain_digest": run_result.chain_digest,
        "ledger_path": Value::Null,
        "subprotocol_timings": {
            "hb.round.seconds": timing_summary_json(&round_latencies),
            "acs.driver.seconds": timing_summary_json(&acs_latencies),
            "tpke.stage.seconds": timing_summary_json(&tpke_stage_latencies),
            "acs.pull.seconds": timing_summary_json(&acs_pull_latencies),
            "tpke.encrypt.seconds": timing_summary_json(&round_build_latencies),
            "tpke.partial_open.seconds": timing_summary_json(&tpke_partial_open_latencies),
            "tpke.combine.seconds": timing_summary_json(&tpke_combine_latencies),
            "node.run.seconds": json!({
                "sample_count": 1usize,
                "total_seconds": node_run_total,
                "max_seconds": node_run_total,
            }),
        },
        "queue_peaks": {
            "raw_inbound_messages": queue_peaks.raw_inbound_messages,
            "raw_outbound_messages": queue_peaks.raw_outbound_messages,
            "transport_inbound": queue_peaks.transport_inbound,
            "transport_outbound": queue_peaks.transport_outbound,
            "mailbox_round_inbox": 0usize,
        },
        "transport_stats": {
            "sent_frames": transport_stats.sent_frames,
            "recv_frames": transport_stats.recv_frames,
            "connect_retries": transport_stats.connect_retries,
            "send_retries": transport_stats.send_retries,
        },
        "driver_stats": {
            "acs_pull_calls": acs_pull_calls.iter().sum::<usize>(),
            "acs_empty_pull_calls": acs_empty_pull_calls.iter().sum::<usize>(),
            "acs_inbound_wire_batches": acs_inbound_wire_batches.iter().sum::<usize>(),
            "acs_inbound_wire_items": acs_inbound_wire_items.iter().sum::<usize>(),
            "acs_outbound_events": acs_outbound_events.iter().sum::<usize>(),
            "tpke_combine_calls": tpke_combine_calls.iter().sum::<usize>(),
            "stale_acs_frames_dropped": stale_acs_frames_dropped.iter().sum::<usize>(),
        },
        "host_stats": {
            "worker_ident": host_stats.worker_ident,
            "rounds_started": host_stats.rounds_started,
            "rounds_finished": host_stats.rounds_finished,
            "processed_commands": host_stats.processed_commands,
            "bridge_queue_size": host_stats.bridge_queue_size,
            "worker_running": host_stats.worker_running,
            "worker_error": host_stats.worker_error,
            "start_round_calls": host_stats.start_round_calls,
            "push_inbound_batch_calls": host_stats.push_inbound_batch_calls,
            "push_inbound_batch_items": host_stats.push_inbound_batch_items,
            "push_inbound_wire_batch_calls": host_stats.push_inbound_wire_batch_calls,
            "push_inbound_wire_batch_items": host_stats.push_inbound_wire_batch_items,
            "exchange_batches_calls": host_stats.exchange_batches_calls,
            "exchange_inbound_items": host_stats.exchange_inbound_items,
            "exchange_outbound_items": host_stats.exchange_outbound_items,
            "pull_outbound_batch_calls": host_stats.pull_outbound_batch_calls,
            "pull_outbound_batch_items": host_stats.pull_outbound_batch_items,
            "pull_outbound_wire_batch_calls": host_stats.pull_outbound_wire_batch_calls,
            "pull_outbound_wire_batch_items": host_stats.pull_outbound_wire_batch_items,
            "stats_calls": host_stats.stats_calls,
            "exchange_deliver_seconds": host_stats.exchange_deliver_seconds,
            "exchange_pump_seconds": host_stats.exchange_pump_seconds,
            "exchange_drain_seconds": host_stats.exchange_drain_seconds,
            "exchange_total_seconds": host_stats.exchange_total_seconds,
        },
        "batch_size": batch_size,
        "per_round_selected_pids": run_result.per_round_selected_pids,
        "per_round_block_digests": run_result.per_round_block_digests,
        "per_round_block_sizes": run_result.per_round_block_sizes,
        "per_round_chain_digests": run_result.per_round_chain_digests,
        "round_details": run_result.round_details.iter().map(|round| {
            json!({
                "selected_pids": round.selected_pids,
                "block_digest": round.block_digest,
                "block_size": round.block_size,
                "chain_digest": round.chain_digest,
                "build_seconds": round.build_seconds,
                "acs_seconds": round.acs_seconds,
                "tpke_seconds": round.tpke_seconds,
                "protocol_seconds": round.protocol_seconds,
                "wall_seconds": round.wall_seconds,
                "delivered_count": round.delivered_count,
                "tpke_partial_open_seconds": round.tpke_partial_open_seconds,
                "tpke_combine_seconds": round.tpke_combine_seconds,
                "acs_outbound_events": round.acs_outbound_events,
                "tpke_combine_calls": round.tpke_combine_calls,
                "driver_phase_stats": driver_phase_stats_json(&round.driver_phase_stats),
            })
        }).collect::<Vec<_>>(),
    }))
    .map_err(|err| err.to_string())
}

fn wait_until_start(start_at_ms: Option<u64>) -> Result<(), String> {
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

fn parse_addresses_json(payload: &str) -> Result<Vec<(String, u16)>, String> {
    serde_json::from_str(payload).map_err(|err| err.to_string())
}

fn drain_transport_into_round(
    transport: &LocalTcpTransport,
    round_id: usize,
    carryovers: &mut DriverCarryovers,
    inbound_acs_wire: &mut Vec<Vec<u8>>,
    received_batches: &mut BTreeMap<usize, Vec<u8>>,
    pending_share_bundles: &mut Vec<InboundShareBundle>,
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
                selected_pids,
                shares,
            } => {
                let bundle = InboundShareBundle {
                    sender,
                    selected_pids,
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

fn run_driver_round(
    ctx: &DriverRoundCtx<'_>,
    round_id: usize,
    carryovers: &mut DriverCarryovers,
    queue_peaks: &mut QueuePeaksSnapshot,
) -> Result<DriverRoundOutcome, String> {
    let round_wall_start = Instant::now();
    let round_sid = format!("{}:{round_id}:", ctx.args.sid);
    let round_build_start = Instant::now();
    let batch = build_driver_round_batch(round_id, ctx.args.pid, ctx.args.batch_size)?;
    let sealed_batch = seal_hb_encrypted_batch(ctx.public_key, &batch)?;
    let build_seconds = round_build_start.elapsed().as_secs_f64();

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

    ctx.host
        .start_round(round_id, &round_sid, &encode_proposal_ref(ctx.args.pid))?;

    let deadline = Instant::now() + Duration::from_secs_f64(ctx.args.global_timeout);
    let mut decision: Option<Vec<usize>> = None;
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
            &mut inbound_acs_wire,
            &mut received_batches,
            &mut pending_share_bundles,
        )?;
        if frame_count > 0 {
            progressed = true;
        }
        update_queue_peaks(ctx.transport, queue_peaks);

        if decision.is_none() {
            let mut pushed_inbound = false;
            if !inbound_acs_wire.is_empty() {
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

            if pushed_inbound || ctx.host.outbound_ready()? {
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
                        PyAcsWireEvent::Send {
                            round_id: event_round_id,
                            recipient,
                            payload,
                        } => {
                            if event_round_id != round_id {
                                return Err(format!(
                                    "driver round {round_id}: outbound ACS event carried mismatched round_id {event_round_id}"
                                ));
                            }
                            send_frame(
                                ctx.transport,
                                recipient,
                                &DriverWireFrame::AcsEnvelope { round_id, payload },
                            )?;
                        }
                        PyAcsWireEvent::Decision {
                            round_id: event_round_id,
                            selected_pids,
                            selected_payloads: _,
                        } => {
                            if event_round_id != round_id {
                                return Err(format!(
                                    "driver round {round_id}: decision carried mismatched round_id {event_round_id}"
                                ));
                            }
                            if acs_decision_at.is_none() {
                                acs_decision_at = Some(Instant::now());
                            }
                            decision = Some(selected_pids);
                        }
                        PyAcsWireEvent::Failure {
                            round_id: event_round_id,
                            error,
                            exception_type,
                        } => {
                            return Err(format!(
                                "driver round {round_id}: ACS host failed in event round {event_round_id} with {exception_type}: {error}"
                            ));
                        }
                        PyAcsWireEvent::Carryovers {
                            round_id: event_round_id,
                            items: _,
                        } => {
                            if event_round_id != round_id {
                                return Err(format!(
                                    "driver round {round_id}: carryovers event carried mismatched round_id {event_round_id}"
                                ));
                            }
                        }
                    }
                }
            }
        } else if !inbound_acs_wire.is_empty() {
            // Once ACS has emitted a decision, the service has already torn down the round state.
            // Current-round ACS envelopes arriving later are stale and would be ignored by Python.
            stale_acs_frames_dropped += inbound_acs_wire.len();
            inbound_acs_wire.clear();
            progressed = true;
        }
        update_queue_peaks(ctx.transport, queue_peaks);

        if let Some(selected_pids) = decision.as_ref() {
            if !local_share_broadcasted
                && selected_pids
                    .iter()
                    .all(|pid| received_batches.contains_key(pid))
            {
                let selected_batches = selected_pids
                    .iter()
                    .map(|pid| {
                        received_batches.get(pid).cloned().ok_or_else(|| {
                            format!("driver round {round_id}: missing selected batch for pid={pid}")
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
                        selected_pids: selected_pids.clone(),
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
                    if bundle.selected_pids != *selected_pids {
                        return Err(format!(
                            "driver round {round_id}: share bundle from pid={} carried divergent selected_pids",
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
                        selected_pids: selected_pids.clone(),
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

fn run_driver_rounds(
    host: &PyAcsHost,
    transport: &LocalTcpTransport,
    public_key: &HbPkePublicParams,
    private_share: &HbPkePrivateKeyShare,
    args: &RunDriverNodeArgs,
) -> Result<(DriverNodeResult, QueuePeaksSnapshot), String> {
    let mut queue_peaks = QueuePeaksSnapshot::default();
    let mut carryovers = DriverCarryovers::default();
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
    let ctx = DriverRoundCtx {
        host,
        transport,
        public_key,
        private_share,
        args,
    };

    for round_id in 0..args.rounds {
        let round_outcome = run_driver_round(&ctx, round_id, &mut carryovers, &mut queue_peaks)?;
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
            tpke_partial_open_seconds: round_outcome.tpke_partial_open_seconds,
            tpke_combine_seconds: round_outcome.tpke_combine_seconds,
            acs_outbound_events: round_outcome.acs_outbound_events,
            tpke_combine_calls: round_outcome.tpke_combine_calls,
            driver_phase_stats: round_outcome.driver_stats,
        });
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
            chain_digest: hex_encode(&chain_digest),
            per_round_selected_pids,
            per_round_block_digests,
            per_round_block_sizes,
            per_round_chain_digests,
            round_details,
        },
        queue_peaks,
    ))
}

pub(crate) fn run_rust_driver_node(args: RunDriverNodeArgs) -> Result<(), String> {
    let addresses = parse_addresses_json(&args.addresses_json)?;
    let mut transport =
        LocalTcpTransport::new(args.pid, addresses).map_err(|err| err.to_string())?;
    let host = PyAcsHost::new(
        args.acs_protocol,
        args.pid,
        args.nodes,
        args.faulty,
        &args.acs_crypto_json,
        &args.config_json,
    )?;
    let (public_key, private_share) = parse_honeybadger_crypto_payload(&args.hb_crypto_json)?;
    wait_until_start(args.start_at_ms)?;

    let result = run_driver_rounds(&host, &transport, &public_key, &private_share, &args);
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
