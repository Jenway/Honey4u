use super::*;
use crate::py_host::RustDrivenAcsHost;

fn drive_acs_debug_enabled() -> bool {
    std::env::var_os("HONEY_DEBUG_ACS").is_some()
}

fn start_worker_rounds_parallel(
    workers: &mut [HbWorkerProcess],
    round_id: usize,
    round_sid: &str,
    local_inputs: &[Vec<u8>],
) -> Result<(), String> {
    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers.len());
        for (worker, local_input) in workers.iter_mut().zip(local_inputs) {
            handles.push(scope.spawn(move || worker.start_round(round_id, round_sid, local_input)));
        }
        for handle in handles {
            handle
                .join()
                .map_err(|_| String::from("worker start_round thread panicked"))??;
        }
        Ok::<(), String>(())
    })
}

fn collect_worker_stats_parallel(
    workers: &mut [HbWorkerProcess],
) -> Result<Vec<(usize, PyAcsHostStats)>, String> {
    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers.len());
        for worker in workers.iter_mut() {
            handles.push(scope.spawn(move || worker.stats().map(|stats| (worker.pid, stats))));
        }

        let mut stats = Vec::with_capacity(handles.len());
        for handle in handles {
            stats.push(
                handle
                    .join()
                    .map_err(|_| String::from("worker stats thread panicked"))??,
            );
        }
        Ok::<Vec<(usize, PyAcsHostStats)>, String>(stats)
    })
}

fn drain_worker_events_parallel(
    workers: &mut [HbWorkerProcess],
    limit: usize,
) -> Result<Vec<(usize, Vec<HbWorkerEvent>)>, String> {
    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers.len());
        for worker in workers.iter_mut() {
            handles.push(scope.spawn(move || {
                worker
                    .drain_events(limit)
                    .map(|events| (worker.pid, events))
            }));
        }

        let mut drained = Vec::with_capacity(handles.len());
        for handle in handles {
            drained.push(
                handle
                    .join()
                    .map_err(|_| String::from("worker drain_events thread panicked"))??,
            );
        }
        Ok::<Vec<(usize, Vec<HbWorkerEvent>)>, String>(drained)
    })
}

fn flush_worker_deliveries_parallel(
    workers: &mut [HbWorkerProcess],
    deliveries_by_recipient: &mut [Vec<Vec<u8>>],
) -> Result<usize, String> {
    thread::scope(|scope| {
        let mut handles = Vec::new();
        for (recipient, worker) in workers.iter_mut().enumerate() {
            if deliveries_by_recipient[recipient].is_empty() {
                continue;
            }
            let payloads = std::mem::take(&mut deliveries_by_recipient[recipient]);
            handles.push(scope.spawn(move || worker.deliver_batch(&payloads)));
        }

        let non_empty_recipients = handles.len();
        for handle in handles {
            handle
                .join()
                .map_err(|_| String::from("worker deliver_batch thread panicked"))??;
        }
        Ok::<usize, String>(non_empty_recipients)
    })
}

fn run_acs_round<T: RustDrivenAcsHost>(
    hosts: &[T],
    round_id: usize,
    round_sid: &str,
    local_inputs: &[Vec<u8>],
    global_timeout: f64,
) -> Result<AcsRoundOutcome, String> {
    if local_inputs.len() != hosts.len() {
        return Err(format!(
            "round {round_id}: expected {} local ACS inputs, got {}",
            hosts.len(),
            local_inputs.len()
        ));
    }

    debug_drive_acs(&format!("round:start round={round_id}"));
    for (host, local_input) in hosts.iter().zip(local_inputs) {
        debug_drive_acs(&format!(
            "round:start_round:call round={round_id} pid={}",
            host.pid()
        ));
        host.start_round(round_id, round_sid, local_input)?;
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
    let mut decisions: Vec<Option<Vec<Option<Vec<u8>>>>> = vec![None; hosts.len()];

    while Instant::now() < deadline {
        let mut progressed = false;

        for (pid, host) in hosts.iter().enumerate() {
            for event in host.drain_events(512)? {
                progressed = true;
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
                        if recipient >= hosts.len() {
                            return Err(format!(
                                "drive-acs round {round_id}: invalid recipient {recipient}"
                            ));
                        }
                        hosts[recipient].deliver_decoded(
                            pid,
                            round_id,
                            &channel,
                            instance_id,
                            &message,
                        )?;
                        send_events += 1;
                    }
                    PyAcsEvent::Decision {
                        round_id: event_round_id,
                        values,
                    } => {
                        if event_round_id != round_id {
                            return Err(format!(
                                "drive-acs round {round_id}: decision event carried mismatched round_id {event_round_id}"
                            ));
                        }
                        debug_drive_acs(&format!("round:decision round={round_id} pid={pid}"));
                        decisions[pid] = Some(values);
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
        }

        if decisions.iter().all(Option::is_some) {
            break;
        }
        if !progressed {
            thread::sleep(ACS_IDLE_BACKOFF);
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

    settle_acs_round(hosts, round_id, &mut send_events)?;
    Ok(AcsRoundOutcome {
        canonical,
        send_events,
    })
}

pub(crate) fn run_acs_round_workers(
    workers: &mut [HbWorkerProcess],
    round_id: usize,
    round_sid: &str,
    local_inputs: &[Vec<u8>],
    global_timeout: f64,
) -> Result<AcsRoundOutcome, String> {
    if local_inputs.len() != workers.len() {
        return Err(format!(
            "round {round_id}: expected {} local ACS inputs, got {}",
            workers.len(),
            local_inputs.len()
        ));
    }

    debug_drive_acs(&format!("round:start round={round_id}"));
    for worker in workers.iter() {
        debug_drive_acs(&format!(
            "round:start_round:call round={round_id} pid={}",
            worker.pid
        ));
    }
    start_worker_rounds_parallel(workers, round_id, round_sid, local_inputs)?;
    for worker in workers.iter() {
        debug_drive_acs(&format!(
            "round:start_round:done round={round_id} pid={}",
            worker.pid
        ));
    }
    if drive_acs_debug_enabled() {
        for (pid, stats) in collect_worker_stats_parallel(workers)? {
            debug_drive_acs(&format!(
                "round:stats round={round_id} pid={} running={} commands={} queue={} started={} finished={} worker_error={:?}",
                pid,
                stats.worker_running,
                stats.processed_commands,
                stats.bridge_queue_size,
                stats.rounds_started,
                stats.rounds_finished,
                stats.worker_error
            ));
        }
    }

    let deadline = Instant::now() + Duration::from_secs_f64(global_timeout);
    let mut send_events = 0usize;
    let mut decisions: Vec<Option<Vec<Option<Vec<u8>>>>> = vec![None; workers.len()];

    while Instant::now() < deadline {
        let mut progressed = false;
        let mut deliveries_by_recipient = vec![Vec::new(); workers.len()];

        for (pid, events) in drain_worker_events_parallel(workers, ACS_EVENT_DRAIN_LIMIT)? {
            for event in events {
                progressed = true;
                match event {
                    HbWorkerEvent::Send {
                        round_id: event_round_id,
                        recipient,
                        payload,
                    } => {
                        if event_round_id != round_id {
                            return Err(format!(
                                "drive-acs round {round_id}: send event carried mismatched round_id {event_round_id}"
                            ));
                        }
                        if recipient >= workers.len() {
                            return Err(format!(
                                "drive-acs round {round_id}: invalid recipient {recipient}"
                            ));
                        }
                        deliveries_by_recipient[recipient].push(payload);
                        send_events += 1;
                    }
                    HbWorkerEvent::Decision {
                        round_id: event_round_id,
                        values,
                    } => {
                        if event_round_id != round_id {
                            return Err(format!(
                                "drive-acs round {round_id}: decision event carried mismatched round_id {event_round_id}"
                            ));
                        }
                        debug_drive_acs(&format!("round:decision round={round_id} pid={pid}"));
                        decisions[pid] = Some(values);
                    }
                    HbWorkerEvent::Failure {
                        round_id: event_round_id,
                        error,
                        exception_type,
                    } => {
                        return Err(format!(
                            "drive-acs round {round_id}: node {pid} failed in event round {event_round_id} with {exception_type}: {error}"
                        ));
                    }
                    HbWorkerEvent::Carryovers {
                        round_id: event_round_id,
                    } => {
                        if event_round_id != round_id {
                            return Err(format!(
                                "drive-acs round {round_id}: carryovers event carried mismatched round_id {event_round_id}"
                            ));
                        }
                    }
                }
            }
        }

        let delivered_batches =
            flush_worker_deliveries_parallel(workers, &mut deliveries_by_recipient)?;
        if delivered_batches > 0 {
            progressed = true;
        }

        if decisions.iter().all(Option::is_some) {
            break;
        }
        if !progressed {
            thread::sleep(ACS_IDLE_BACKOFF);
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

    settle_acs_round_workers(workers, round_id, &mut send_events)?;
    Ok(AcsRoundOutcome {
        canonical,
        send_events,
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
        let local_inputs = hosts
            .iter()
            .map(|host| {
                Ok(format!(
                    "{}-round-{round_id}-node-{}",
                    args.protocol.as_str(),
                    host.pid
                )
                .into_bytes())
            })
            .collect::<Result<Vec<_>, String>>()?;
        let outcome = run_acs_round(
            hosts,
            round_id,
            &round_sid,
            &local_inputs,
            args.global_timeout,
        )?;

        rounds.push(json!({
            "round_id": round_id,
            "selected_count": outcome.canonical.iter().filter(|value| value.is_some()).count(),
            "send_events": outcome.send_events,
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
                "bridge_queue_size": stats.bridge_queue_size,
                "worker_running": stats.worker_running,
                "worker_error": stats.worker_error,
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

fn settle_acs_round_workers(
    workers: &mut [HbWorkerProcess],
    round_id: usize,
    send_events: &mut usize,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_millis(100);
    while Instant::now() < deadline {
        let mut progressed = false;
        let mut deliveries_by_recipient = vec![Vec::new(); workers.len()];

        for (pid, events) in drain_worker_events_parallel(workers, ACS_EVENT_DRAIN_LIMIT)? {
            for event in events {
                progressed = true;
                match event {
                    HbWorkerEvent::Send {
                        round_id: event_round_id,
                        recipient,
                        payload,
                    } => {
                        if event_round_id != round_id {
                            return Err(format!(
                                "drive-acs round {round_id}: send event carried mismatched round_id {event_round_id} during settle"
                            ));
                        }
                        if recipient >= workers.len() {
                            return Err(format!(
                                "drive-acs round {round_id}: invalid recipient {recipient} during settle"
                            ));
                        }
                        deliveries_by_recipient[recipient].push(payload);
                        *send_events += 1;
                    }
                    HbWorkerEvent::Failure {
                        round_id: event_round_id,
                        error,
                        exception_type,
                    } => {
                        return Err(format!(
                            "drive-acs round {round_id}: node {pid} failed during settle in event round {event_round_id} with {exception_type}: {error}"
                        ));
                    }
                    HbWorkerEvent::Decision { .. } => {}
                    HbWorkerEvent::Carryovers {
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

        let delivered_batches =
            flush_worker_deliveries_parallel(workers, &mut deliveries_by_recipient)?;
        if delivered_batches > 0 {
            progressed = true;
        }

        if !progressed {
            let queues_empty = collect_worker_stats_parallel(workers)?
                .into_iter()
                .all(|(_pid, stats)| stats.bridge_queue_size == 0);
            if queues_empty {
                break;
            }
        }
        thread::sleep(ACS_IDLE_BACKOFF);
    }
    Ok(())
}

fn settle_acs_round<T: RustDrivenAcsHost>(
    hosts: &[T],
    round_id: usize,
    send_events: &mut usize,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_millis(100);
    while Instant::now() < deadline {
        let mut progressed = false;
        for (pid, host) in hosts.iter().enumerate() {
            for event in host.drain_events(512)? {
                progressed = true;
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
                        hosts[recipient].deliver_decoded(
                            pid,
                            round_id,
                            &channel,
                            instance_id,
                            &message,
                        )?;
                        *send_events += 1;
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
                    PyAcsEvent::Decision { .. } | PyAcsEvent::Carryovers { .. } => {}
                }
            }
        }

        let queues_empty = hosts
            .iter()
            .map(|host| host.stats())
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .all(|stats| stats.bridge_queue_size == 0);
        if !progressed && queues_empty {
            break;
        }
        thread::sleep(ACS_IDLE_BACKOFF);
    }
    Ok(())
}
