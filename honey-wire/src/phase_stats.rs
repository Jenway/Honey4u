use serde_json::{Value, json};

#[derive(Clone, Default)]
pub struct DriverHostPhaseStats {
    pub pid: usize,
    pub push_calls: usize,
    pub push_items: usize,
    pub max_push_batch: usize,
    pub push_seconds: f64,
    pub pull_calls: usize,
    pub empty_pull_calls: usize,
    pub pulled_events: usize,
    pub max_pull_batch: usize,
    pub pull_limit_hits: usize,
    pub pull_seconds: f64,
}

#[derive(Clone, Default)]
pub struct DriverPhaseStats {
    pub sweep_count: usize,
    pub active_sweeps: usize,
    pub idle_sweeps: usize,
    pub idle_backoff_count: usize,
    pub total_pending_deliveries: usize,
    pub max_pending_deliveries: usize,
    pub total_pushed_items: usize,
    pub total_pulled_events: usize,
    pub max_pull_batch: usize,
    pub pull_limit_hits: usize,
    pub total_push_seconds: f64,
    pub total_pull_seconds: f64,
    pub send_events: usize,
    pub send_payload_bytes: usize,
    pub proposal_available_events: usize,
    pub proposal_available_payload_bytes: usize,
    pub proposal_available_proof_bytes: usize,
    pub decision_events: usize,
    pub failure_events: usize,
    pub host_stats: Vec<DriverHostPhaseStats>,
}

fn json_array_field<'a>(value: &'a Value, key: &str) -> Result<&'a [Value], String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| format!("missing array field: {key}"))
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

pub fn driver_host_phase_stats_from_value(value: &Value) -> Result<DriverHostPhaseStats, String> {
    Ok(DriverHostPhaseStats {
        pid: json_usize_field(value, "pid")?,
        push_calls: json_usize_field(value, "push_calls")?,
        push_items: json_usize_field(value, "push_items")?,
        max_push_batch: json_usize_field(value, "max_push_batch")?,
        push_seconds: json_f64_field(value, "push_seconds")?,
        pull_calls: json_usize_field(value, "pull_calls")?,
        empty_pull_calls: json_usize_field(value, "empty_pull_calls")?,
        pulled_events: json_usize_field(value, "pulled_events")?,
        max_pull_batch: json_usize_field(value, "max_pull_batch")?,
        pull_limit_hits: json_usize_field(value, "pull_limit_hits")?,
        pull_seconds: json_f64_field(value, "pull_seconds")?,
    })
}

pub fn driver_phase_stats_from_value(value: &Value) -> Result<DriverPhaseStats, String> {
    let host_stats = json_array_field(value, "host_stats")?
        .iter()
        .map(driver_host_phase_stats_from_value)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(DriverPhaseStats {
        sweep_count: json_usize_field(value, "sweep_count")?,
        active_sweeps: json_usize_field(value, "active_sweeps")?,
        idle_sweeps: json_usize_field(value, "idle_sweeps")?,
        idle_backoff_count: json_usize_field(value, "idle_backoff_count")?,
        total_pending_deliveries: json_usize_field(value, "total_pending_deliveries")?,
        max_pending_deliveries: json_usize_field(value, "max_pending_deliveries")?,
        total_pushed_items: json_usize_field(value, "total_pushed_items")?,
        total_pulled_events: json_usize_field(value, "total_pulled_events")?,
        max_pull_batch: json_usize_field(value, "max_pull_batch")?,
        pull_limit_hits: json_usize_field(value, "pull_limit_hits")?,
        total_push_seconds: json_f64_field(value, "total_push_seconds")?,
        total_pull_seconds: json_f64_field(value, "total_pull_seconds")?,
        send_events: value
            .get("send_events")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize,
        send_payload_bytes: value
            .get("send_payload_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize,
        proposal_available_events: value
            .get("proposal_available_events")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize,
        proposal_available_payload_bytes: value
            .get("proposal_available_payload_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize,
        proposal_available_proof_bytes: value
            .get("proposal_available_proof_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize,
        decision_events: value
            .get("decision_events")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize,
        failure_events: value
            .get("failure_events")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize,
        host_stats,
    })
}

pub fn aggregate_driver_phase_stats(
    stats_by_node: &[DriverPhaseStats],
    host_count: usize,
) -> DriverPhaseStats {
    let mut aggregated = DriverPhaseStats {
        host_stats: (0..host_count)
            .map(|pid| DriverHostPhaseStats {
                pid,
                ..DriverHostPhaseStats::default()
            })
            .collect(),
        ..DriverPhaseStats::default()
    };

    for stats in stats_by_node {
        aggregated.sweep_count += stats.sweep_count;
        aggregated.active_sweeps += stats.active_sweeps;
        aggregated.idle_sweeps += stats.idle_sweeps;
        aggregated.idle_backoff_count += stats.idle_backoff_count;
        aggregated.total_pending_deliveries += stats.total_pending_deliveries;
        aggregated.max_pending_deliveries = aggregated
            .max_pending_deliveries
            .max(stats.max_pending_deliveries);
        aggregated.total_pushed_items += stats.total_pushed_items;
        aggregated.total_pulled_events += stats.total_pulled_events;
        aggregated.max_pull_batch = aggregated.max_pull_batch.max(stats.max_pull_batch);
        aggregated.pull_limit_hits += stats.pull_limit_hits;
        aggregated.total_push_seconds += stats.total_push_seconds;
        aggregated.total_pull_seconds += stats.total_pull_seconds;
        aggregated.send_events += stats.send_events;
        aggregated.send_payload_bytes += stats.send_payload_bytes;
        aggregated.proposal_available_events += stats.proposal_available_events;
        aggregated.proposal_available_payload_bytes += stats.proposal_available_payload_bytes;
        aggregated.proposal_available_proof_bytes += stats.proposal_available_proof_bytes;
        aggregated.decision_events += stats.decision_events;
        aggregated.failure_events += stats.failure_events;

        for (index, host_stats) in stats.host_stats.iter().enumerate() {
            let aggregated_host = &mut aggregated.host_stats[index];
            aggregated_host.push_calls += host_stats.push_calls;
            aggregated_host.push_items += host_stats.push_items;
            aggregated_host.max_push_batch = aggregated_host
                .max_push_batch
                .max(host_stats.max_push_batch);
            aggregated_host.push_seconds += host_stats.push_seconds;
            aggregated_host.pull_calls += host_stats.pull_calls;
            aggregated_host.empty_pull_calls += host_stats.empty_pull_calls;
            aggregated_host.pulled_events += host_stats.pulled_events;
            aggregated_host.max_pull_batch = aggregated_host
                .max_pull_batch
                .max(host_stats.max_pull_batch);
            aggregated_host.pull_limit_hits += host_stats.pull_limit_hits;
            aggregated_host.pull_seconds += host_stats.pull_seconds;
        }
    }

    aggregated
}

pub fn driver_phase_stats_json(stats: &DriverPhaseStats) -> Value {
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
