use crate::node_runtime::phase_stats::{
    new_driver_phase_stats, record_pull, record_push, update_pending_snapshot,
};
use crate::*;
use honey_node::host_crypto::{
    generate_dumbo_crypto_payloads_json, generate_hb_crypto_payloads_json,
};
use std::collections::BTreeMap;
use std::thread;
use std::time::{Duration, Instant};

const ACS_PULL_BATCH_LIMIT: usize = 512;
const ACS_IDLE_BACKOFF: Duration = Duration::from_micros(50);

fn debug_acs_driver(message: &str) {
    if std::env::var_os("HONEY_DEBUG_ACS").is_some() {
        eprintln!("[bench-driver:acs] {message}");
    }
}

pub(crate) fn serialize_crypto_payloads(
    protocol: AcsProtocol,
    nodes: usize,
    faulty: usize,
) -> Result<Vec<String>, String> {
    match protocol {
        AcsProtocol::HoneyBadger => generate_hb_crypto_payloads_json(nodes, faulty),
        AcsProtocol::Dumbo => generate_dumbo_crypto_payloads_json(nodes, faulty),
    }
}

type PendingDelivery = Vec<u8>;
type PendingDeliveries = BTreeMap<usize, Vec<PendingDelivery>>;

fn selected_pids_from_proposal_ids(
    selected_proposal_ids: &[String],
    proposal_store: &ProposalStore,
) -> Result<Vec<usize>, String> {
    selected_proposal_ids
        .iter()
        .map(|proposal_id| {
            proposal_store
                .get(proposal_id)
                .map(|proposal| proposal.proposer)
                .ok_or_else(|| format!("missing proposal artifact for selected id {proposal_id}"))
        })
        .collect()
}

fn collect_exchange_events(
    pid: usize,
    round_id: usize,
    host_count: usize,
    events: Vec<AcsEvent>,
    pending_deliveries: &mut PendingDeliveries,
    proposal_store: &mut ProposalStore,
    decisions: &mut [Option<Vec<String>>],
) -> Result<(), String> {
    for event in events {
        match event {
            AcsEvent::Send {
                round_id: event_round_id,
                recipient,
                payload,
            } => {
                if event_round_id != round_id {
                    return Err(format!(
                        "bench-driver:acs round {round_id}: send event carried mismatched round_id {event_round_id}"
                    ));
                }
                if recipient >= host_count {
                    return Err(format!(
                        "bench-driver:acs round {round_id}: invalid recipient {recipient}"
                    ));
                }
                pending_deliveries
                    .entry(recipient)
                    .or_default()
                    .push(payload);
            }
            AcsEvent::Broadcast {
                round_id: event_round_id,
                payload,
                include_self,
            } => {
                if event_round_id != round_id {
                    return Err(format!(
                        "bench-driver:acs round {round_id}: broadcast event carried mismatched round_id {event_round_id}"
                    ));
                }
                for recipient in 0..host_count {
                    if !include_self && recipient == pid {
                        continue;
                    }
                    pending_deliveries
                        .entry(recipient)
                        .or_default()
                        .push(payload.clone());
                }
            }
            AcsEvent::ProposalAvailable {
                round_id: event_round_id,
                proposal,
            } => {
                if event_round_id != round_id {
                    return Err(format!(
                        "bench-driver:acs round {round_id}: proposal_ready event carried mismatched round_id {event_round_id}"
                    ));
                }
                proposal_store.insert(proposal.proposal_id.clone(), proposal);
            }
            AcsEvent::Decided {
                round_id: event_round_id,
                selected_proposal_ids,
            } => {
                if event_round_id != round_id {
                    return Err(format!(
                        "bench-driver:acs round {round_id}: decision event carried mismatched round_id {event_round_id}"
                    ));
                }
                debug_acs_driver(&format!("round:decision round={round_id} pid={pid}"));
                decisions[pid] = Some(selected_proposal_ids);
            }
            AcsEvent::Failure {
                round_id: event_round_id,
                error,
                exception_type,
            } => {
                return Err(format!(
                    "bench-driver:acs round {round_id}: node {pid} failed in event round {event_round_id} with {exception_type}: {error}"
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn run_acs_round<T: AcsBackend>(
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

    debug_acs_driver(&format!("round:start round={round_id}"));
    for (host, proposal_input) in hosts.iter().zip(proposal_inputs) {
        debug_acs_driver(&format!(
            "round:start_round:call round={round_id} pid={}",
            host.pid()
        ));
        host.start_round(round_id, round_sid, proposal_input)?;
        debug_acs_driver(&format!(
            "round:start_round:done round={round_id} pid={}",
            host.pid()
        ));
    }
    for host in hosts {
        let stats = host.stats()?;
        debug_acs_driver(&format!(
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
    let mut proposal_stores: Vec<ProposalStore> = vec![BTreeMap::new(); hosts.len()];
    let mut decisions: Vec<Option<Vec<String>>> = vec![None; hosts.len()];
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
                let _ = host.push_inbound_wire_batch(&inbound)?;
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
            host.begin_pull_outbound_wire_batch(ACS_PULL_BATCH_LIMIT)?;
        }

        for (pid, host) in hosts.iter().enumerate() {
            let events = host.finish_pull_outbound_wire_batch()?;
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
                &mut proposal_stores[pid],
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
            "bench-driver:acs timed out after {:.3}s in round {round_id}",
            global_timeout
        ));
    }

    let canonical = decisions[0]
        .clone()
        .ok_or_else(|| format!("bench-driver:acs round {round_id}: missing canonical decision"))?;
    for (pid, decision) in decisions.iter().enumerate().skip(1) {
        if decision.as_ref() != Some(&canonical) {
            return Err(format!(
                "bench-driver:acs round {round_id}: node {pid} decision diverged"
            ));
        }
    }
    let selected_pids = selected_pids_from_proposal_ids(&canonical, &proposal_stores[0])?;

    let _settle_stats = settle_acs_round(hosts, round_id, &mut send_events)?;
    Ok(AcsRoundOutcome {
        selected_proposal_ids: canonical,
        selected_pids,
    })
}

fn settle_acs_round<T: AcsBackend>(
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
                let _ = host.push_inbound_wire_batch(&inbound)?;
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
            host.begin_pull_outbound_wire_batch(ACS_PULL_BATCH_LIMIT)?;
        }

        for (pid, host) in hosts.iter().enumerate() {
            let events = host.finish_pull_outbound_wire_batch()?;
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
                    AcsEvent::Send {
                        round_id: event_round_id,
                        recipient,
                        payload,
                    } => {
                        if event_round_id != round_id {
                            return Err(format!(
                                "bench-driver:acs round {round_id}: send event carried mismatched round_id {event_round_id} during settle"
                            ));
                        }
                        if recipient >= hosts.len() {
                            return Err(format!(
                                "bench-driver:acs round {round_id}: invalid recipient {recipient} during settle"
                            ));
                        }
                        pending_deliveries
                            .entry(recipient)
                            .or_default()
                            .push(payload);
                    }
                    AcsEvent::Broadcast {
                        round_id: event_round_id,
                        payload,
                        include_self,
                    } => {
                        if event_round_id != round_id {
                            return Err(format!(
                                "bench-driver:acs round {round_id}: broadcast event carried mismatched round_id {event_round_id} during settle"
                            ));
                        }
                        for recipient in 0..hosts.len() {
                            if !include_self && recipient == pid {
                                continue;
                            }
                            pending_deliveries
                                .entry(recipient)
                                .or_default()
                                .push(payload.clone());
                        }
                    }
                    AcsEvent::Failure {
                        round_id: event_round_id,
                        error,
                        exception_type,
                    } => {
                        return Err(format!(
                            "bench-driver:acs round {round_id}: node {pid} failed during settle in event round {event_round_id} with {exception_type}: {error}"
                        ));
                    }
                    AcsEvent::ProposalAvailable { .. } => {}
                    AcsEvent::Decided { .. } => {}
                }
            }
        }

        if !progressed {
            let queues_empty = hosts
                .iter()
                .map(AcsBackend::stats)
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
