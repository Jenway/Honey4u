use super::inbox::update_queue_peaks;
use super::metrics::RoundMetricsRecorder;
use super::state::{DriverRoundCtx, InboundShareBundle, QueuePeaksSnapshot};
use crate::driver::encryption::{
    BatchDecryptor as HbBatchDecryptor, decode_tx_batch as decode_hb_tx_batch,
    merge_tx_batches_bytes as merge_hb_tx_batches_bytes,
};
use crate::driver::error::{DriverError, DriverResult};
use crate::driver::frame::{DriverWireFrame, encode_driver_frame, fanout_encoded_payload};
use std::collections::BTreeSet;
use std::time::Instant;

#[derive(Default)]
pub(super) struct TpkeRoundState {
    decryptor: Option<HbBatchDecryptor>,
    seen_share_senders: BTreeSet<usize>,
    local_share_broadcasted: bool,
}

impl TpkeRoundState {
    pub(super) fn local_share_broadcasted(&self) -> bool {
        self.local_share_broadcasted
    }

    pub(super) fn seen_share_sender_count(&self) -> usize {
        self.seen_share_senders.len()
    }
}

pub(super) struct TpkeStepOutcome {
    pub(super) progressed: bool,
    pub(super) block_payload: Option<Vec<u8>>,
}

pub(super) struct TpkeStepContext<'a> {
    pub(super) ctx: &'a DriverRoundCtx<'a>,
    pub(super) round_id: usize,
    pub(super) selected_proposal_ids: &'a [String],
    pub(super) selected_batches: &'a [Vec<u8>],
    pub(super) selected_digests: &'a [Vec<u8>],
    pub(super) pending_share_bundles: &'a mut Vec<InboundShareBundle>,
    pub(super) metrics: &'a mut RoundMetricsRecorder,
    pub(super) queue_peaks: &'a mut QueuePeaksSnapshot,
}

pub(super) fn run_tpke_step(
    mut input: TpkeStepContext<'_>,
    state: &mut TpkeRoundState,
) -> DriverResult<TpkeStepOutcome> {
    let mut progressed = false;

    if !state.local_share_broadcasted {
        let mut batch_decryptor = HbBatchDecryptor::new(
            input.ctx.public_key.clone(),
            input.selected_batches.to_vec(),
        )?;
        if input.ctx.byzantine_node_config.is_silent() {
            input.metrics.byzantine().share_broadcast_suppressed();
        } else {
            broadcast_local_shares(
                &mut input,
                &mut batch_decryptor,
                &mut state.seen_share_senders,
            )?;
        }
        state.decryptor = Some(batch_decryptor);
        state.local_share_broadcasted = true;
        progressed = true;
    }

    let Some(batch_decryptor) = state.decryptor.as_mut() else {
        return Ok(TpkeStepOutcome {
            progressed,
            block_payload: None,
        });
    };

    for bundle in input.pending_share_bundles.drain(..) {
        ingest_share_bundle(
            input.round_id,
            input.selected_proposal_ids,
            input.selected_digests,
            bundle,
            batch_decryptor,
            &mut state.seen_share_senders,
            input.metrics,
        )?;
        progressed = true;
    }

    let block_payload = if batch_decryptor.is_complete() {
        Some(merge_hb_tx_batches_bytes(
            batch_decryptor
                .plaintexts()
                .into_iter()
                .flatten()
                .collect::<Vec<_>>(),
        )?)
    } else {
        None
    };

    Ok(TpkeStepOutcome {
        progressed,
        block_payload,
    })
}

fn broadcast_local_shares(
    input: &mut TpkeStepContext<'_>,
    batch_decryptor: &mut HbBatchDecryptor,
    seen_share_senders: &mut BTreeSet<usize>,
) -> DriverResult<()> {
    let partial_open_start = Instant::now();
    let local_shares = batch_decryptor.local_shares(input.ctx.private_share)?;
    input
        .metrics
        .tpke()
        .partial_open(partial_open_start.elapsed().as_secs_f64());
    let local_bundle = local_shares.into_iter().map(Some).collect::<Vec<_>>();

    let combine_start = Instant::now();
    let _ = batch_decryptor.ingest_bundle(input.ctx.args.pid, local_bundle.clone())?;
    input
        .metrics
        .tpke()
        .combine(combine_start.elapsed().as_secs_f64());
    seen_share_senders.insert(input.ctx.args.pid);

    let frame_payload = encode_driver_frame(&DriverWireFrame::HbShareBundle {
        sender: input.ctx.args.pid,
        round_id: input.round_id,
        selected_proposal_ids: input.selected_proposal_ids.to_vec(),
        selected_digests: input.selected_digests.to_vec(),
        shares: local_bundle,
    })?;
    let _ = fanout_encoded_payload(
        input.ctx.transport,
        input.ctx.args.nodes,
        &frame_payload,
        None,
    )?;
    update_queue_peaks(input.ctx.transport, input.queue_peaks);
    Ok(())
}

fn ingest_share_bundle(
    round_id: usize,
    selected_proposal_ids: &[String],
    selected_digests: &[Vec<u8>],
    bundle: InboundShareBundle,
    batch_decryptor: &mut HbBatchDecryptor,
    seen_share_senders: &mut BTreeSet<usize>,
    metrics: &mut RoundMetricsRecorder,
) -> DriverResult<()> {
    if bundle.selected_proposal_ids != selected_proposal_ids
        || bundle.selected_digests != selected_digests
    {
        return Err(DriverError::invariant(format!(
            "driver round {round_id}: share bundle from pid={} carried divergent selected proposal set",
            bundle.sender
        )));
    }
    if !seen_share_senders.insert(bundle.sender) {
        return Ok(());
    }
    let combine_start = Instant::now();
    let _ = batch_decryptor.ingest_bundle(bundle.sender, bundle.shares)?;
    metrics
        .tpke()
        .combine(combine_start.elapsed().as_secs_f64());
    Ok(())
}

pub(super) fn decoded_tx_count(block_payload: &[u8]) -> DriverResult<usize> {
    Ok(decode_hb_tx_batch(block_payload)?.len())
}
