use serde_json::{Value, json};

#[derive(Clone, Default)]
pub(crate) struct DriverHostPhaseStats {
    pub(crate) pid: usize,
    pub(crate) push_calls: usize,
    pub(crate) push_items: usize,
    pub(crate) max_push_batch: usize,
    pub(crate) push_seconds: f64,
    pub(crate) pull_calls: usize,
    pub(crate) empty_pull_calls: usize,
    pub(crate) pulled_events: usize,
    pub(crate) max_pull_batch: usize,
    pub(crate) pull_limit_hits: usize,
    pub(crate) pull_seconds: f64,
}

#[derive(Clone, Default)]
pub(crate) struct DriverPhaseStats {
    pub(crate) sweep_count: usize,
    pub(crate) active_sweeps: usize,
    pub(crate) idle_sweeps: usize,
    pub(crate) idle_backoff_count: usize,
    pub(crate) total_pending_deliveries: usize,
    pub(crate) max_pending_deliveries: usize,
    pub(crate) total_pushed_items: usize,
    pub(crate) total_pulled_events: usize,
    pub(crate) max_pull_batch: usize,
    pub(crate) pull_limit_hits: usize,
    pub(crate) total_push_seconds: f64,
    pub(crate) total_pull_seconds: f64,
    pub(crate) send_events: usize,
    pub(crate) send_payload_bytes: usize,
    pub(crate) proposal_available_events: usize,
    pub(crate) proposal_available_payload_bytes: usize,
    pub(crate) proposal_available_proof_bytes: usize,
    pub(crate) decision_events: usize,
    pub(crate) failure_events: usize,
    pub(crate) host_stats: Vec<DriverHostPhaseStats>,
}

pub(crate) fn record_push(
    stats: &mut DriverPhaseStats,
    pid: usize,
    batch_len: usize,
    seconds: f64,
) {
    if batch_len == 0 {
        return;
    }
    let host = &mut stats.host_stats[pid];
    host.push_calls += 1;
    host.push_items += batch_len;
    host.max_push_batch = host.max_push_batch.max(batch_len);
    host.push_seconds += seconds;
    stats.total_pushed_items += batch_len;
    stats.total_push_seconds += seconds;
}

pub(crate) fn record_pull(
    stats: &mut DriverPhaseStats,
    pid: usize,
    event_count: usize,
    seconds: f64,
    limit: usize,
) {
    let host = &mut stats.host_stats[pid];
    host.pull_calls += 1;
    host.pull_seconds += seconds;
    host.pulled_events += event_count;
    host.max_pull_batch = host.max_pull_batch.max(event_count);
    if event_count == 0 {
        host.empty_pull_calls += 1;
    }
    if event_count >= limit {
        host.pull_limit_hits += 1;
        stats.pull_limit_hits += 1;
    }
    stats.total_pulled_events += event_count;
    stats.max_pull_batch = stats.max_pull_batch.max(event_count);
    stats.total_pull_seconds += seconds;
}

pub(crate) fn driver_phase_stats_json(stats: &DriverPhaseStats) -> Value {
    json!({
        "sweep_count": stats.sweep_count,
        "active_sweeps": stats.active_sweeps,
        "idle_sweeps": stats.idle_sweeps,
        "idle_backoff_count": stats.idle_backoff_count,
        "total_pending_deliveries": stats.total_pending_deliveries,
        "max_pending_deliveries": stats.max_pending_deliveries,
        "total_pushed_items": stats.total_pushed_items,
        "total_pulled_events": stats.total_pulled_events,
        "max_pull_batch": stats.max_pull_batch,
        "pull_limit_hits": stats.pull_limit_hits,
        "total_push_seconds": stats.total_push_seconds,
        "total_pull_seconds": stats.total_pull_seconds,
        "send_events": stats.send_events,
        "send_payload_bytes": stats.send_payload_bytes,
        "proposal_available_events": stats.proposal_available_events,
        "proposal_available_payload_bytes": stats.proposal_available_payload_bytes,
        "proposal_available_proof_bytes": stats.proposal_available_proof_bytes,
        "proposal_ready_events": stats.proposal_available_events,
        "proposal_ready_payload_bytes": stats.proposal_available_payload_bytes,
        "proposal_ready_certificate_bytes": stats.proposal_available_proof_bytes,
        "decision_events": stats.decision_events,
        "failure_events": stats.failure_events,
        "host_stats": stats.host_stats.iter().map(|host| {
            json!({
                "pid": host.pid,
                "push_calls": host.push_calls,
                "push_items": host.push_items,
                "max_push_batch": host.max_push_batch,
                "push_seconds": host.push_seconds,
                "pull_calls": host.pull_calls,
                "empty_pull_calls": host.empty_pull_calls,
                "pulled_events": host.pulled_events,
                "max_pull_batch": host.max_pull_batch,
                "pull_limit_hits": host.pull_limit_hits,
                "pull_seconds": host.pull_seconds,
            })
        }).collect::<Vec<_>>(),
    })
}
