use super::inbox::update_queue_peaks;
use super::metrics::RoundMetricsRecorder;
use super::state::{DriverRoundCtx, InboundTpkeShare, QueuePeaksSnapshot};
use crate::driver::encryption::{
    DecryptItem as HbDecryptItem, ShareIngestResult, decode_tx_batch as decode_hb_tx_batch,
    encode_tpke_share, merge_tx_batches_bytes as merge_hb_tx_batches_bytes,
};
use crate::driver::error::DriverResult;
use crate::driver::frame::{DriverWireFrame, encode_driver_frame, fanout_encoded_payload};
use crate::driver::mempool::fetch::ResolvedPayloadItem;
use std::collections::BTreeMap;
use std::time::Instant;

struct ItemTpkeState {
    decryptor: HbDecryptItem,
    local_share_started: bool,
    local_share_broadcasted: bool,
}

#[derive(Default)]
pub(super) struct TpkeRoundState {
    items: BTreeMap<Vec<u8>, ItemTpkeState>,
    item_order: Vec<Vec<u8>>,
}

impl TpkeRoundState {
    pub(super) fn local_share_broadcasted_count(&self) -> usize {
        self.items
            .values()
            .filter(|item| item.local_share_broadcasted)
            .count()
    }

    pub(super) fn known_item_count(&self) -> usize {
        self.items.len()
    }

    pub(super) fn verified_share_count(&self) -> usize {
        self.items
            .values()
            .map(|item| item.decryptor.verified_share_count())
            .sum()
    }

    fn all_items_complete(&self) -> bool {
        self.items.values().all(|item| item.decryptor.is_complete())
    }

    fn ordered_plaintexts(&self) -> Vec<Vec<u8>> {
        self.item_order
            .iter()
            .filter_map(|digest| {
                self.items
                    .get(digest)
                    .and_then(|item| item.decryptor.plaintext())
            })
            .collect()
    }
}

pub(super) struct TpkeStepOutcome {
    pub(super) progressed: bool,
    pub(super) block_payload: Option<Vec<u8>>,
}

pub(super) struct TpkeStepContext<'a> {
    pub(super) ctx: &'a DriverRoundCtx<'a>,
    pub(super) round_id: usize,
    pub(super) newly_resolved_items: &'a [ResolvedPayloadItem],
    pub(super) resolution_complete: bool,
    pub(super) pending_tpke_shares: &'a mut Vec<InboundTpkeShare>,
    pub(super) metrics: &'a mut RoundMetricsRecorder,
    pub(super) queue_peaks: &'a mut QueuePeaksSnapshot,
}

pub(super) fn run_tpke_step(
    mut input: TpkeStepContext<'_>,
    state: &mut TpkeRoundState,
) -> DriverResult<TpkeStepOutcome> {
    let mut progressed = false;

    for item in input.newly_resolved_items {
        if state.items.contains_key(&item.payload_digest) {
            continue;
        }
        let mut item_state = ItemTpkeState {
            decryptor: HbDecryptItem::new(input.ctx.public_key.clone(), item.sealed_batch.clone())?,
            local_share_started: false,
            local_share_broadcasted: false,
        };
        let item_progress =
            ensure_local_share_started(&mut input, &item.payload_digest, &mut item_state)?;
        state.item_order.push(item.payload_digest.clone());
        state.items.insert(item.payload_digest.clone(), item_state);
        progressed |= item_progress;
    }

    let mut unresolved_shares = Vec::new();
    for share in input.pending_tpke_shares.drain(..) {
        let Some(item_state) = state.items.get_mut(&share.payload_digest) else {
            if !input.resolution_complete {
                unresolved_shares.push(share);
            }
            continue;
        };
        progressed |= ingest_share(item_state, share, input.metrics)?;
    }
    *input.pending_tpke_shares = unresolved_shares;

    let block_payload = if input.resolution_complete && state.all_items_complete() {
        Some(merge_hb_tx_batches_bytes(state.ordered_plaintexts())?)
    } else {
        None
    };

    Ok(TpkeStepOutcome {
        progressed,
        block_payload,
    })
}

fn ensure_local_share_started(
    input: &mut TpkeStepContext<'_>,
    payload_digest: &[u8],
    item_state: &mut ItemTpkeState,
) -> DriverResult<bool> {
    if item_state.local_share_started {
        return Ok(false);
    }
    item_state.local_share_started = true;
    if input.ctx.byzantine_node_config.is_silent() {
        input.metrics.byzantine().share_broadcast_suppressed();
        return Ok(false);
    }

    let partial_open_start = Instant::now();
    let local_share = item_state.decryptor.local_share(input.ctx.private_share)?;
    input
        .metrics
        .tpke()
        .partial_open(partial_open_start.elapsed().as_secs_f64());

    let combine_start = Instant::now();
    let local_result = item_state
        .decryptor
        .ingest_verified_share(input.ctx.args.pid, local_share.clone())?;
    input
        .metrics
        .tpke()
        .combine(combine_start.elapsed().as_secs_f64());

    let frame_payload = encode_driver_frame(&DriverWireFrame::HbShare {
        sender: input.ctx.args.pid,
        round_id: input.round_id,
        payload_digest: payload_digest.to_vec(),
        share: encode_tpke_share(&local_share)?,
    })?;
    let _ = fanout_encoded_payload(
        input.ctx.transport,
        input.ctx.args.nodes,
        &frame_payload,
        None,
    )?;
    update_queue_peaks(input.ctx.transport, input.queue_peaks);
    item_state.local_share_broadcasted = true;
    Ok(local_result.is_progress())
}

fn ingest_share(
    item_state: &mut ItemTpkeState,
    share: InboundTpkeShare,
    metrics: &mut RoundMetricsRecorder,
) -> DriverResult<bool> {
    let combine_start = Instant::now();
    let result = item_state
        .decryptor
        .ingest_untrusted_share(share.sender, &share.share)?;
    if !result.is_progress() {
        return Ok(false);
    }
    metrics
        .tpke()
        .combine(combine_start.elapsed().as_secs_f64());
    Ok(matches!(
        result,
        ShareIngestResult::Accepted | ShareIngestResult::Decrypted
    ))
}

pub(super) fn decoded_tx_count(block_payload: &[u8]) -> DriverResult<usize> {
    Ok(decode_hb_tx_batch(block_payload)?.len())
}
