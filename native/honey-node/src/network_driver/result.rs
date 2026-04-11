use super::types::{DriverNodeResult, QueuePeaksSnapshot};
use crate::AcsHostStats;
use crate::drive_acs::driver_phase_stats_json;
use honey_node::transport::LocalTcpTransport;
use serde_json::{Value, json};

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

pub(super) fn build_node_result_json(
    pid: usize,
    batch_size: usize,
    run_result: DriverNodeResult,
    host_stats: AcsHostStats,
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
                "selected_proposal_ids": round.selected_proposal_ids,
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
