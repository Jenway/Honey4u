use super::*;
use crate::drive_acs::{driver_phase_stats_json, record_pull, record_push};
use crate::pool_reuse::{
    AcsPayload, BroadcastMempool, PoolReference, decode_acs_payload, encode_bundle_acs_payload,
};
use bincode::{deserialize, serialize};
use honey_native::transport::LocalTcpTransport;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const DRIVER_NETWORK_BATCH_LIMIT: usize = 512;
const DRIVER_IDLE_BACKOFF: Duration = Duration::from_micros(50);
const BATCH_REF_TAG: u8 = 1;

#[derive(Clone, Copy, PartialEq, Eq)]
enum BroadcastPoolBackend {
    None,
    Rust,
}

impl BroadcastPoolBackend {
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Rust => "rust",
        }
    }
}

struct BroadcastPoolConfig {
    backend: BroadcastPoolBackend,
    max_size: usize,
    expire_rounds: u32,
    enable_reuse: bool,
    enable_reference_proposals: bool,
    enable_fetch_fallback: bool,
    reuse_limit_per_round: usize,
}

fn parse_broadcast_pool_config(config_json: &str) -> Result<BroadcastPoolConfig, String> {
    let value: Value = serde_json::from_str(config_json).map_err(|err| err.to_string())?;
    let backend = match value
        .get("broadcast_mempool_backend")
        .and_then(Value::as_str)
        .unwrap_or("rust")
    {
        "none" => BroadcastPoolBackend::None,
        "rust" => BroadcastPoolBackend::Rust,
        other => {
            return Err(format!(
                "unsupported broadcast_mempool_backend in config_json: {other}"
            ));
        }
    };
    let max_size = value
        .get("pool_mempool_max")
        .and_then(Value::as_u64)
        .unwrap_or(1000) as usize;
    let expire_rounds = value
        .get("pool_expire_rounds")
        .and_then(Value::as_u64)
        .unwrap_or(5) as u32;
    let enable_reuse = value
        .get("enable_broadcast_pool_reuse")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let enable_reference_proposals = value
        .get("enable_pool_reference_proposals")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let enable_fetch_fallback = value
        .get("enable_pool_fetch_fallback")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let reuse_limit_per_round = value
        .get("pool_reuse_limit_per_round")
        .and_then(Value::as_u64)
        .unwrap_or(1) as usize;
    if enable_reuse && backend == BroadcastPoolBackend::None {
        return Err(String::from(
            "broadcast_mempool_backend=none is incompatible with enable_broadcast_pool_reuse=true",
        ));
    }
    Ok(BroadcastPoolConfig {
        backend,
        max_size,
        expire_rounds,
        enable_reuse,
        enable_reference_proposals,
        enable_fetch_fallback,
        reuse_limit_per_round,
    })
}

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
        selected_batch_refs: Vec<(u32, u32)>,
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
    selected_batch_refs: Vec<(u32, u32)>,
    shares: Vec<Option<Vec<u8>>>,
}

type BatchArchive = BTreeMap<(u32, u32), Vec<u8>>;

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
    reused_reference_count: usize,
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
    reused_reference_count: usize,
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
    broadcast_pool_config: &'a BroadcastPoolConfig,
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
    rust_broadcast_mempool_size: usize,
    broadcast_pool_backend: BroadcastPoolBackend,
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

fn proposal_batch_refs_for_selected_pids(
    round_id: usize,
    selected_pids: &[usize],
) -> Vec<(u32, u32)> {
    selected_pids
        .iter()
        .map(|pid| (round_id as u32, *pid as u32))
        .collect()
}

fn build_dumbo_proposal_input(
    round_id: usize,
    pid: usize,
    pool: Option<&BroadcastMempool>,
    config: &BroadcastPoolConfig,
) -> Vec<u8> {
    let inline_payload = encode_batch_ref(round_id, pid);
    let references = if config.enable_reference_proposals {
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

struct ResolvedSelectedPayloads {
    batch_refs: Vec<(u32, u32)>,
    consumed_reference_ids: Vec<String>,
}

fn resolve_selected_payloads(
    selected_payloads: &[Option<Vec<u8>>],
    pool: &mut BroadcastMempool,
    allow_fetch_fallback: bool,
) -> Result<ResolvedSelectedPayloads, String> {
    let mut batch_refs = Vec::new();
    let mut seen_batch_refs = BTreeSet::new();
    let mut consumed_reference_ids = Vec::new();
    let mut visited_reference_ids = BTreeSet::new();
    for payload in selected_payloads.iter().flatten() {
        resolve_payload_bytes(
            payload,
            pool,
            allow_fetch_fallback,
            &mut batch_refs,
            &mut seen_batch_refs,
            &mut consumed_reference_ids,
            &mut visited_reference_ids,
        )?;
    }
    Ok(ResolvedSelectedPayloads {
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
    let rust_broadcast_mempool_size = run_result.rust_broadcast_mempool_size;
    let broadcast_pool_backend = run_result.broadcast_pool_backend.as_str();
    let origin_tx_latencies = origin_tx_latencies_by_round
        .iter()
        .flat_map(|samples| samples.iter().copied())
        .collect::<Vec<_>>();
    let delivered_total = round_delivered_counts.iter().sum::<usize>();
    let node_run_total = round_wall_latencies.iter().sum::<f64>();
    let transport_stats = transport.stats();
    let round_details_json = run_result
        .round_details
        .iter()
        .map(|round| {
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
                "reused_reference_count": round.reused_reference_count,
                "tpke_partial_open_seconds": round.tpke_partial_open_seconds,
                "tpke_combine_seconds": round.tpke_combine_seconds,
                "acs_outbound_events": round.acs_outbound_events,
                "tpke_combine_calls": round.tpke_combine_calls,
                "driver_phase_stats": driver_phase_stats_json(&round.driver_phase_stats),
            })
        })
        .collect::<Vec<_>>();

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
        "broadcast_pool_backend": broadcast_pool_backend,
        "mempool_size": rust_broadcast_mempool_size,
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
            "push_inbound_wire_batch_calls": host_stats.push_inbound_wire_batch_calls,
            "push_inbound_wire_batch_items": host_stats.push_inbound_wire_batch_items,
            "pull_outbound_wire_batch_calls": host_stats.pull_outbound_wire_batch_calls,
            "pull_outbound_wire_batch_items": host_stats.pull_outbound_wire_batch_items,
            "stats_calls": host_stats.stats_calls,
        },
        "batch_size": batch_size,
        "per_round_selected_pids": run_result.per_round_selected_pids,
        "per_round_block_digests": run_result.per_round_block_digests,
        "per_round_block_sizes": run_result.per_round_block_sizes,
        "per_round_chain_digests": run_result.per_round_chain_digests,
        "round_details": round_details_json,
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
    batch_archive: &mut BatchArchive,
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
                let bundle = InboundShareBundle {
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
    let proposal_input = if reuse_enabled {
        build_dumbo_proposal_input(
            round_id,
            ctx.args.pid,
            rust_broadcast_mempool.as_ref(),
            ctx.broadcast_pool_config,
        )
    } else {
        encode_proposal_ref(ctx.args.pid)
    };
    ctx.host
        .start_round(round_id, &round_sid, &proposal_input)?;

    let deadline = Instant::now() + Duration::from_secs_f64(ctx.args.global_timeout);
    let mut decision: Option<Vec<usize>> = None;
    let mut decision_payloads: Option<Vec<Option<Vec<u8>>>> = None;
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
    let mut broadcast_outputs_taken = false;
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
                            driver_stats.send_events += 1;
                            driver_stats.send_payload_bytes += payload.len();
                            send_frame(
                                ctx.transport,
                                recipient,
                                &DriverWireFrame::AcsEnvelope { round_id, payload },
                            )?;
                        }
                        PyAcsWireEvent::Decision {
                            round_id: event_round_id,
                            selected_pids,
                            selected_payloads,
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
                            let resolved_selected_pids = if selected_pids.is_empty() {
                                selected_payloads
                                    .as_ref()
                                    .map(|payloads| {
                                        payloads
                                            .iter()
                                            .enumerate()
                                            .filter_map(|(pid, payload)| {
                                                payload.as_ref().map(|_| pid)
                                            })
                                            .collect::<Vec<_>>()
                                    })
                                    .unwrap_or_default()
                            } else {
                                selected_pids
                            };
                            decision = Some(resolved_selected_pids);
                            decision_payloads = selected_payloads;
                        }
                        PyAcsWireEvent::Failure {
                            round_id: event_round_id,
                            error,
                            exception_type,
                        } => {
                            driver_stats.failure_events += 1;
                            return Err(format!(
                                "driver round {round_id}: ACS host failed in event round {event_round_id} with {exception_type}: {error}"
                            ));
                        }
                        PyAcsWireEvent::Carryovers {
                            round_id: event_round_id,
                            items,
                        } => {
                            if event_round_id != round_id {
                                return Err(format!(
                                    "driver round {round_id}: carryovers event carried mismatched round_id {event_round_id}"
                                ));
                            }
                            driver_stats.carryover_events += 1;
                            if reuse_enabled {
                                let pool = rust_broadcast_mempool.as_mut().ok_or_else(|| {
                                    String::from("Dumbo pool reuse requires a Rust mempool backend")
                                })?;
                                for item in items {
                                    pool.add_reusable(
                                        item.value,
                                        item.roothash,
                                        item.proof_payload,
                                        round_id as u32,
                                        item.leader,
                                        0.0,
                                    );
                                }
                            }
                        }
                        PyAcsWireEvent::BroadcastOutput {
                            round_id: event_round_id,
                            sender,
                            payload_id: _,
                            payload,
                            roothash,
                        } => {
                            if event_round_id != round_id {
                                return Err(format!(
                                    "driver round {round_id}: broadcast_output carried mismatched round_id {event_round_id}"
                                ));
                            }
                            driver_stats.broadcast_output_events += 1;
                            driver_stats.broadcast_output_payload_bytes += payload.len();
                            driver_stats.broadcast_output_roothash_bytes += roothash.len();
                            if let Some(pool) = rust_broadcast_mempool.as_mut() {
                                pool.add_rbc(
                                    payload,
                                    roothash,
                                    round_id as u32,
                                    sender as u32,
                                    0.0,
                                );
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
            if reuse_enabled && selected_batch_refs.is_none() {
                let pool = rust_broadcast_mempool.as_mut().ok_or_else(|| {
                    String::from("missing Rust mempool for Dumbo payload resolution")
                })?;
                let payloads = decision_payloads.as_ref().ok_or_else(|| {
                    format!(
                        "driver round {round_id}: Dumbo reuse decision missing selected_payloads"
                    )
                })?;
                let resolved = resolve_selected_payloads(
                    payloads,
                    pool,
                    ctx.broadcast_pool_config.enable_fetch_fallback,
                )?;
                reused_reference_count = resolved.consumed_reference_ids.len();
                consumed_reference_ids = resolved.consumed_reference_ids;
                selected_batch_refs = Some(resolved.batch_refs);
            }

            if rust_broadcast_mempool.is_some() && !broadcast_outputs_taken {
                let outputs = ctx.host.take_round_broadcast_outputs(round_id)?;
                for event in outputs {
                    match event {
                        PyAcsWireEvent::BroadcastOutput {
                            round_id: event_round_id,
                            sender,
                            payload_id: _,
                            payload,
                            roothash,
                        } => {
                            if event_round_id != round_id {
                                return Err(format!(
                                    "driver round {round_id}: side-channel broadcast_output carried mismatched round_id {event_round_id}"
                                ));
                            }
                            driver_stats.broadcast_output_events += 1;
                            driver_stats.broadcast_output_payload_bytes += payload.len();
                            driver_stats.broadcast_output_roothash_bytes += roothash.len();
                            if let Some(pool) = rust_broadcast_mempool.as_mut() {
                                pool.add_rbc(
                                    payload,
                                    roothash,
                                    round_id as u32,
                                    sender as u32,
                                    0.0,
                                );
                            }
                        }
                        other => {
                            return Err(format!(
                                "driver round {round_id}: unexpected side-channel ACS event kind {}",
                                match other {
                                    PyAcsWireEvent::Send { .. } => "send",
                                    PyAcsWireEvent::Decision { .. } => "decision",
                                    PyAcsWireEvent::Failure { .. } => "failure",
                                    PyAcsWireEvent::Carryovers { .. } => "carryovers",
                                    PyAcsWireEvent::BroadcastOutput { .. } => "broadcast_output",
                                }
                            ));
                        }
                    }
                }
                broadcast_outputs_taken = true;
            }

            let round_batch_refs = selected_batch_refs
                .clone()
                .unwrap_or_else(|| proposal_batch_refs_for_selected_pids(round_id, selected_pids));

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
                    if !consumed_reference_ids.is_empty() {
                        if let Some(pool) = rust_broadcast_mempool.as_mut() {
                            for item_id in &consumed_reference_ids {
                                pool.mark_selected(item_id, round_id as u32);
                                pool.mark_consumed(item_id, round_id as u32);
                            }
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

fn run_driver_rounds(
    host: &PyAcsHost,
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
            broadcast_pool_backend: broadcast_pool_config.backend,
        },
        queue_peaks,
    ))
}

fn build_host_config_json(
    args: &RunDriverNodeArgs,
    broadcast_pool_config: &BroadcastPoolConfig,
) -> Result<String, String> {
    if !matches!(args.acs_protocol, Protocol::Dumbo) || !broadcast_pool_config.enable_reuse {
        return Ok(args.config_json.clone());
    }
    let mut value: Value =
        serde_json::from_str(&args.config_json).map_err(|err| err.to_string())?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| String::from("run-driver-node config_json must be a JSON object"))?;
    object.insert(
        String::from("output_mode"),
        Value::String(String::from("payloads")),
    );
    serde_json::to_string(&value).map_err(|err| err.to_string())
}

pub(crate) fn run_rust_driver_node(args: RunDriverNodeArgs) -> Result<(), String> {
    let broadcast_pool_config = parse_broadcast_pool_config(&args.config_json)?;
    let addresses = parse_addresses_json(&args.addresses_json)?;
    let mut transport =
        LocalTcpTransport::new(args.pid, addresses).map_err(|err| err.to_string())?;
    let host_config_json = build_host_config_json(&args, &broadcast_pool_config)?;
    let host = PyAcsHost::new(
        args.acs_protocol,
        args.pid,
        args.nodes,
        args.faulty,
        &args.acs_crypto_json,
        &host_config_json,
    )?;
    let (public_key, private_share) = parse_honeybadger_crypto_payload(&args.hb_crypto_json)?;
    wait_until_start(args.start_at_ms)?;

    let result = run_driver_rounds(
        &host,
        &transport,
        &public_key,
        &private_share,
        &args,
        &broadcast_pool_config,
    );
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
