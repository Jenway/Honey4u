use super::*;
use crate::py_host::RustDrivenAcsHost;
use std::collections::BTreeMap;

type PendingDelivery = (usize, usize, String, Option<usize>, Py<PyAny>);
type PendingDeliveries = BTreeMap<usize, Vec<PendingDelivery>>;

fn encode_honeybadger_proposal_ref(pid: usize) -> Vec<u8> {
    (pid as u64).to_be_bytes().to_vec()
}

fn encode_dumbo_proposal_ref(pid: usize) -> Vec<u8> {
    (pid as u64).to_be_bytes().to_vec()
}

fn new_driver_phase_stats<T: RustDrivenAcsHost>(hosts: &[T]) -> DriverPhaseStats {
    DriverPhaseStats {
        host_stats: hosts
            .iter()
            .enumerate()
            .map(|(pid, host)| {
                debug_assert_eq!(pid, host.pid());
                DriverHostPhaseStats {
                    pid: host.pid(),
                    ..DriverHostPhaseStats::default()
                }
            })
            .collect(),
        ..DriverPhaseStats::default()
    }
}

fn update_pending_snapshot(stats: &mut DriverPhaseStats, pending_deliveries: &PendingDeliveries) {
    stats.sweep_count += 1;
    let pending = pending_deliveries.values().map(Vec::len).sum::<usize>();
    stats.total_pending_deliveries += pending;
    stats.max_pending_deliveries = stats.max_pending_deliveries.max(pending);
}

fn record_push(stats: &mut DriverPhaseStats, pid: usize, batch_len: usize, seconds: f64) {
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

fn record_pull(
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

fn collect_exchange_events(
    pid: usize,
    round_id: usize,
    host_count: usize,
    events: Vec<PyAcsEvent>,
    pending_deliveries: &mut PendingDeliveries,
    decisions: &mut [Option<Vec<usize>>],
) -> Result<(), String> {
    for event in events {
        match event {
            PyAcsEvent::Send {
                round_id: event_round_id,
                recipient,
                channel,
                instance_id,
                message,
            } => {
                if event_round_id != round_id {
                    return Err(format!(
                        "drive-acs round {round_id}: send event carried mismatched round_id {event_round_id}"
                    ));
                }
                if recipient >= host_count {
                    return Err(format!(
                        "drive-acs round {round_id}: invalid recipient {recipient}"
                    ));
                }
                pending_deliveries.entry(recipient).or_default().push((
                    pid,
                    round_id,
                    channel,
                    instance_id,
                    message,
                ));
            }
            PyAcsEvent::Decision {
                round_id: event_round_id,
                selected_pids,
            } => {
                if event_round_id != round_id {
                    return Err(format!(
                        "drive-acs round {round_id}: decision event carried mismatched round_id {event_round_id}"
                    ));
                }
                debug_drive_acs(&format!("round:decision round={round_id} pid={pid}"));
                decisions[pid] = Some(selected_pids);
            }
            PyAcsEvent::Failure {
                round_id: event_round_id,
                error,
                exception_type,
            } => {
                return Err(format!(
                    "drive-acs round {round_id}: node {pid} failed in event round {event_round_id} with {exception_type}: {error}"
                ));
            }
            PyAcsEvent::Carryovers { round_id: _ } => {}
        }
    }
    Ok(())
}

pub(crate) fn run_acs_round<T: RustDrivenAcsHost>(
    hosts: &[T],
    round_id: usize,
    round_sid: &str,
    proposal_inputs: &[Vec<u8>],
    global_timeout: f64,
) -> Result<AcsRoundOutcome, String> {
    if proposal_inputs.len() != hosts.len() {
        return Err(format!(
            "round {round_id}: expected {} local ACS inputs, got {}",
            hosts.len(),
            proposal_inputs.len()
        ));
    }

    debug_drive_acs(&format!("round:start round={round_id}"));
    for (host, proposal_input) in hosts.iter().zip(proposal_inputs) {
        debug_drive_acs(&format!(
            "round:start_round:call round={round_id} pid={}",
            host.pid()
        ));
        host.start_round(round_id, round_sid, proposal_input)?;
        debug_drive_acs(&format!(
            "round:start_round:done round={round_id} pid={}",
            host.pid()
        ));
    }
    for host in hosts {
        let stats = host.stats()?;
        debug_drive_acs(&format!(
            "round:stats round={round_id} pid={} running={} commands={} queue={} started={} finished={} worker_error={:?}",
            host.pid(),
            stats.worker_running,
            stats.processed_commands,
            stats.bridge_queue_size,
            stats.rounds_started,
            stats.rounds_finished,
            stats.worker_error
        ));
    }

    let deadline = Instant::now() + Duration::from_secs_f64(global_timeout);
    let mut send_events = 0usize;
    let mut decisions: Vec<Option<Vec<usize>>> = vec![None; hosts.len()];
    let mut pending_deliveries: PendingDeliveries = BTreeMap::new();
    let mut drive_stats = new_driver_phase_stats(hosts);

    while Instant::now() < deadline {
        update_pending_snapshot(&mut drive_stats, &pending_deliveries);
        let mut progressed = false;

        for (pid, host) in hosts.iter().enumerate() {
            let inbound = pending_deliveries.remove(&pid).unwrap_or_default();
            send_events += inbound.len();
            progressed |= !inbound.is_empty();
            if !inbound.is_empty() {
                let push_start = Instant::now();
                let _ = host.push_inbound_batch(&inbound)?;
                record_push(
                    &mut drive_stats,
                    pid,
                    inbound.len(),
                    push_start.elapsed().as_secs_f64(),
                );
            }
        }

        let mut pull_starts = Vec::with_capacity(hosts.len());
        for host in hosts {
            pull_starts.push(Instant::now());
            host.begin_pull_outbound_batch(ACS_PULL_BATCH_LIMIT)?;
        }

        for (pid, host) in hosts.iter().enumerate() {
            let events = host.finish_pull_outbound_batch()?;
            let pull_seconds = pull_starts[pid].elapsed().as_secs_f64();
            let event_count = events.len();
            progressed |= event_count > 0;
            record_pull(
                &mut drive_stats,
                pid,
                event_count,
                pull_seconds,
                ACS_PULL_BATCH_LIMIT,
            );
            collect_exchange_events(
                pid,
                round_id,
                hosts.len(),
                events,
                &mut pending_deliveries,
                &mut decisions,
            )?;
        }

        if !progressed {
            drive_stats.idle_sweeps += 1;
            drive_stats.idle_backoff_count += 1;
            thread::sleep(ACS_IDLE_BACKOFF);
            continue;
        }
        drive_stats.active_sweeps += 1;
        if decisions.iter().all(Option::is_some) {
            break;
        }
    }

    if decisions.iter().any(Option::is_none) {
        return Err(format!(
            "drive-acs timed out after {:.3}s in round {round_id}",
            global_timeout
        ));
    }

    let canonical = decisions[0]
        .clone()
        .ok_or_else(|| format!("drive-acs round {round_id}: missing canonical decision"))?;
    for (pid, decision) in decisions.iter().enumerate().skip(1) {
        if decision.as_ref() != Some(&canonical) {
            return Err(format!(
                "drive-acs round {round_id}: node {pid} decision diverged"
            ));
        }
    }

    let settle_stats = settle_acs_round(hosts, round_id, &mut send_events)?;
    Ok(AcsRoundOutcome {
        selected_pids: canonical,
        send_events,
        drive_stats,
        settle_stats,
    })
}

pub(crate) fn run_drive_acs(args: DriveAcsArgs) -> Result<(), String> {
    debug_drive_acs("serialize_crypto_payloads:start");
    let crypto_payloads = serialize_crypto_payloads(args.protocol, args.nodes, args.faulty)?;
    debug_drive_acs("serialize_crypto_payloads:done");
    let mut hosts = Vec::with_capacity(crypto_payloads.len());
    for (pid, payload) in crypto_payloads.iter().enumerate() {
        debug_drive_acs(&format!("host:new:start pid={pid}"));
        match PyAcsHost::new(
            args.protocol,
            pid,
            args.nodes,
            args.faulty,
            payload,
            &args.config_json,
        ) {
            Ok(host) => {
                debug_drive_acs(&format!("host:new:done pid={pid}"));
                hosts.push(host)
            }
            Err(err) => {
                for host in &hosts {
                    let _ = host.shutdown();
                }
                return Err(err);
            }
        }
    }

    let result = drive_acs_rounds(&hosts, &args);

    let mut shutdown_errors = Vec::new();
    for host in &hosts {
        if let Err(err) = host.shutdown() {
            shutdown_errors.push(format!("pid={}: {err}", host.pid));
        }
    }

    let rendered = result?;
    if !shutdown_errors.is_empty() {
        return Err(format!(
            "drive-acs shutdown failed: {}",
            shutdown_errors.join("; ")
        ));
    }

    write_output(args.result_path.as_deref(), &rendered)
}

fn drive_acs_rounds(hosts: &[PyAcsHost], args: &DriveAcsArgs) -> Result<String, String> {
    let mut rounds = Vec::with_capacity(args.rounds);

    for round_id in 0..args.rounds {
        let round_sid = format!("{}:{round_id}:", args.sid);
        let proposal_inputs = hosts
            .iter()
            .map(|host| {
                Ok(match args.protocol {
                    Protocol::HoneyBadger => encode_honeybadger_proposal_ref(host.pid),
                    Protocol::Dumbo => encode_dumbo_proposal_ref(host.pid),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let outcome = run_acs_round(
            hosts,
            round_id,
            &round_sid,
            &proposal_inputs,
            args.global_timeout,
        )?;

        rounds.push(json!({
            "round_id": round_id,
            "selected_count": outcome.selected_pids.len(),
            "selected_pids": outcome.selected_pids,
            "send_events": outcome.send_events,
            "drive_stats": driver_phase_stats_json(&outcome.drive_stats),
            "settle_stats": driver_phase_stats_json(&outcome.settle_stats),
        }));
    }

    let nodes = hosts
        .iter()
        .map(|host| {
            let stats = host.stats()?;
            Ok(json!({
                "pid": host.pid,
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
        "protocol": args.protocol.as_str(),
        "sid": args.sid,
        "nodes": nodes,
        "rounds": rounds,
    }))
    .map_err(|err| err.to_string())
}

fn settle_acs_round<T: RustDrivenAcsHost>(
    hosts: &[T],
    round_id: usize,
    send_events: &mut usize,
) -> Result<DriverPhaseStats, String> {
    let deadline = Instant::now() + Duration::from_millis(100);
    let mut pending_deliveries: PendingDeliveries = BTreeMap::new();
    let mut settle_stats = new_driver_phase_stats(hosts);
    while Instant::now() < deadline {
        update_pending_snapshot(&mut settle_stats, &pending_deliveries);
        let mut progressed = false;

        for (pid, host) in hosts.iter().enumerate() {
            let inbound = pending_deliveries.remove(&pid).unwrap_or_default();
            *send_events += inbound.len();
            progressed |= !inbound.is_empty();
            if !inbound.is_empty() {
                let push_start = Instant::now();
                let _ = host.push_inbound_batch(&inbound)?;
                record_push(
                    &mut settle_stats,
                    pid,
                    inbound.len(),
                    push_start.elapsed().as_secs_f64(),
                );
            }
        }

        let mut pull_starts = Vec::with_capacity(hosts.len());
        for host in hosts {
            pull_starts.push(Instant::now());
            host.begin_pull_outbound_batch(ACS_PULL_BATCH_LIMIT)?;
        }

        for (pid, host) in hosts.iter().enumerate() {
            let events = host.finish_pull_outbound_batch()?;
            let pull_seconds = pull_starts[pid].elapsed().as_secs_f64();
            let event_count = events.len();
            progressed |= event_count > 0;
            record_pull(
                &mut settle_stats,
                pid,
                event_count,
                pull_seconds,
                ACS_PULL_BATCH_LIMIT,
            );
            for event in events {
                match event {
                    PyAcsEvent::Send {
                        round_id: event_round_id,
                        recipient,
                        channel,
                        instance_id,
                        message,
                    } => {
                        if event_round_id != round_id {
                            return Err(format!(
                                "drive-acs round {round_id}: send event carried mismatched round_id {event_round_id} during settle"
                            ));
                        }
                        if recipient >= hosts.len() {
                            return Err(format!(
                                "drive-acs round {round_id}: invalid recipient {recipient} during settle"
                            ));
                        }
                        pending_deliveries.entry(recipient).or_default().push((
                            pid,
                            round_id,
                            channel,
                            instance_id,
                            message,
                        ));
                    }
                    PyAcsEvent::Failure {
                        round_id: event_round_id,
                        error,
                        exception_type,
                    } => {
                        return Err(format!(
                            "drive-acs round {round_id}: node {pid} failed during settle in event round {event_round_id} with {exception_type}: {error}"
                        ));
                    }
                    PyAcsEvent::Decision { .. } => {}
                    PyAcsEvent::Carryovers {
                        round_id: event_round_id,
                    } => {
                        if event_round_id != round_id {
                            return Err(format!(
                                "drive-acs round {round_id}: carryovers event carried mismatched round_id {event_round_id} during settle"
                            ));
                        }
                    }
                }
            }
        }

        if !progressed {
            let queues_empty = hosts
                .iter()
                .map(RustDrivenAcsHost::stats)
                .collect::<Result<Vec<_>, String>>()?
                .into_iter()
                .all(|stats| stats.bridge_queue_size == 0);
            if queues_empty {
                break;
            }
            settle_stats.idle_sweeps += 1;
            settle_stats.idle_backoff_count += 1;
            thread::sleep(ACS_IDLE_BACKOFF);
            continue;
        }
        settle_stats.active_sweeps += 1;
        thread::sleep(ACS_IDLE_BACKOFF);
    }
    Ok(settle_stats)
}
