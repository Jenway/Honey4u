use crate::driver::config::BroadcastPoolConfig;
use crate::driver::encryption::{encode_json_string, encode_tx_batch};
use crate::driver::error::DriverResult;
use crate::driver::mempool::pool::{BroadcastMempool, PoolReference, encode_bundle_acs_payload};
use honey_acs::proposal::{AvailableProposal, ProposalStore};

pub(in crate::driver) fn build_driver_round_batch(
    round_id: usize,
    pid: usize,
    batch_size: usize,
) -> DriverResult<Vec<u8>> {
    let mut items = Vec::with_capacity(batch_size);
    for tx_index in 0..batch_size {
        items.push(encode_json_string(&format!(
            "hb-rust-driver-round-{round_id}-node-{pid}-tx-{tx_index}"
        ))?);
    }
    encode_tx_batch(items)
}

pub(in crate::driver) fn build_acs_proposal_input(
    round_id: usize,
    sealed_batch: &[u8],
    pool: Option<&BroadcastMempool>,
    config: &BroadcastPoolConfig,
) -> Vec<u8> {
    let references = if config.enable_reuse && config.enable_reference_proposals {
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
    encode_bundle_acs_payload(sealed_batch, &references)
}

pub(in crate::driver) fn collect_selected_proposals<'a>(
    selected_proposal_ids: &[String],
    proposal_store: &'a ProposalStore,
) -> Option<Vec<&'a AvailableProposal>> {
    let mut proposals = Vec::with_capacity(selected_proposal_ids.len());
    for proposal_id in selected_proposal_ids {
        let proposal = proposal_store.get(proposal_id)?;
        proposals.push(proposal);
    }
    Some(proposals)
}

pub(in crate::driver) fn selected_pids_from_proposals(
    selected_proposals: &[&AvailableProposal],
) -> Vec<usize> {
    selected_proposals
        .iter()
        .map(|proposal| proposal.proposer)
        .collect()
}
