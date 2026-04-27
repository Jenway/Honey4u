use super::super::DRIVER_NETWORK_BATCH_LIMIT;
use super::super::error::{DriverError, DriverResult};
use super::super::wire::frame::{
    DriverWireFrame, encode_driver_frame, fanout_encoded_payload, send_frame,
};
use super::metrics::RoundMetricsRecorder;
use super::state::DriverRoundCtx;
use honey_acs::AcsEvent;
use honey_acs::proposal::ProposalStore;
use std::time::Instant;

pub(super) struct AcsPumpOutcome {
    pub(super) progressed: bool,
}

pub(super) fn pump_acs_host(
    ctx: &DriverRoundCtx<'_>,
    round_id: usize,
    inbound_acs_wire: &mut Vec<Vec<u8>>,
    proposal_store: &mut ProposalStore,
    selected_proposal_ids: &mut Option<Vec<String>>,
    acs_decision_at: &mut Option<Instant>,
    metrics: &mut RoundMetricsRecorder,
) -> DriverResult<AcsPumpOutcome> {
    let mut progressed = false;
    let mut pushed_inbound = false;

    if selected_proposal_ids.is_none() && !inbound_acs_wire.is_empty() {
        let batch = std::mem::take(inbound_acs_wire);
        let push_start = Instant::now();
        ctx.host
            .push_inbound_wire_batch(&batch)
            .map_err(|message| DriverError::acs("push_inbound_wire_batch", message))?;
        metrics.acs().push(
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
        ctx.host
            .outbound_ready()
            .map_err(|message| DriverError::acs("outbound_ready", message))?
    };
    if !should_pull_host {
        return Ok(AcsPumpOutcome { progressed });
    }

    let pull_start = Instant::now();
    ctx.host
        .begin_pull_outbound_wire_batch(DRIVER_NETWORK_BATCH_LIMIT)
        .map_err(|message| DriverError::acs("begin_pull_outbound_wire_batch", message))?;
    let events = ctx
        .host
        .finish_pull_outbound_wire_batch()
        .map_err(|message| DriverError::acs("finish_pull_outbound_wire_batch", message))?;
    let pull_seconds = pull_start.elapsed().as_secs_f64();
    let event_count = events.len();
    metrics.acs().pull(
        ctx.args.pid,
        event_count,
        pull_seconds,
        DRIVER_NETWORK_BATCH_LIMIT,
    );
    if !events.is_empty() {
        progressed = true;
    }

    for event in events {
        handle_acs_event(
            ctx,
            round_id,
            event,
            proposal_store,
            selected_proposal_ids,
            acs_decision_at,
            metrics,
        )?;
    }
    Ok(AcsPumpOutcome { progressed })
}

fn handle_acs_event(
    ctx: &DriverRoundCtx<'_>,
    round_id: usize,
    event: AcsEvent,
    proposal_store: &mut ProposalStore,
    selected_proposal_ids: &mut Option<Vec<String>>,
    acs_decision_at: &mut Option<Instant>,
    metrics: &mut RoundMetricsRecorder,
) -> DriverResult<()> {
    match event {
        AcsEvent::Send {
            round_id: event_round_id,
            recipient,
            payload,
        } => {
            require_event_round(round_id, event_round_id, "outbound ACS event")?;
            metrics.acs().send(payload.len());
            send_frame(
                ctx.transport,
                recipient,
                &DriverWireFrame::AcsEnvelope { round_id, payload },
            )
        }
        AcsEvent::Broadcast {
            round_id: event_round_id,
            payload,
            include_self,
        } => {
            require_event_round(round_id, event_round_id, "outbound ACS broadcast event")?;
            let payload_len = payload.len();
            let frame_payload =
                encode_driver_frame(&DriverWireFrame::AcsEnvelope { round_id, payload })?;
            let sent = fanout_encoded_payload(
                ctx.transport,
                ctx.args.nodes,
                &frame_payload,
                (!include_self).then_some(ctx.args.pid),
            )?;
            metrics.acs().broadcast(sent, payload_len);
            Ok(())
        }
        AcsEvent::ProposalAvailable {
            round_id: event_round_id,
            proposal,
        } => {
            require_event_round(round_id, event_round_id, "proposal_available")?;
            metrics
                .acs()
                .proposal_available(proposal.payload.len(), proposal.availability_proof.len());
            proposal_store.insert(proposal.proposal_id.clone(), proposal);
            Ok(())
        }
        AcsEvent::Decided {
            round_id: event_round_id,
            selected_proposal_ids: event_selected_proposal_ids,
        } => {
            require_event_round(round_id, event_round_id, "decision")?;
            if acs_decision_at.is_none() {
                *acs_decision_at = Some(Instant::now());
            }
            metrics.acs().decision();
            *selected_proposal_ids = Some(event_selected_proposal_ids);
            Ok(())
        }
        AcsEvent::Failure {
            round_id: event_round_id,
            error,
            exception_type,
        } => {
            metrics.acs().failure();
            Err(DriverError::acs(
                "event",
                format!(
                    "driver round {round_id}: ACS host failed in event round {event_round_id} with {exception_type}: {error}"
                ),
            ))
        }
    }
}

fn require_event_round(round_id: usize, event_round_id: usize, label: &str) -> DriverResult<()> {
    if event_round_id == round_id {
        return Ok(());
    }
    Err(DriverError::invariant(format!(
        "driver round {round_id}: {label} carried mismatched round_id {event_round_id}"
    )))
}
