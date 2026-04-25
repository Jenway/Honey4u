use super::super::BATCH_REF_TAG;
use super::super::config::BroadcastPoolConfig;
use super::super::pool_reuse::{
    AcsPayload, BroadcastMempool, PoolReference, decode_acs_payload, encode_bundle_acs_payload,
};
use super::super::types::BatchArchive;
use crate::acs::proposal::{AvailableProposal, ProposalStore};
use honey_node::hb::{
    encode_json_string as encode_hb_json_string, encode_tx_batch as encode_hb_tx_batch,
};
use std::collections::BTreeSet;

pub(super) fn build_driver_round_batch(
    round_id: usize,
    pid: usize,
    batch_size: usize,
) -> Result<Vec<u8>, String> {
    let mut items = Vec::with_capacity(batch_size);
    for tx_index in 0..batch_size {
        items.push(encode_hb_json_string(&format!(
            "hb-rust-driver-round-{round_id}-node-{pid}-tx-{tx_index}"
        ))?);
    }
    encode_hb_tx_batch(items)
}

pub(super) fn encode_batch_ref(round_id: usize, sender: usize) -> Vec<u8> {
    let mut payload = Vec::with_capacity(7);
    payload.push(BATCH_REF_TAG);
    payload.extend_from_slice(&(round_id as u32).to_be_bytes());
    payload.extend_from_slice(&(sender as u16).to_be_bytes());
    payload
}

pub(super) fn decode_batch_ref(payload: &[u8]) -> Result<(u32, u32), String> {
    if payload.len() != 7 {
        return Err(format!(
            "invalid batch ref length: expected 7 bytes, got {}",
            payload.len()
        ));
    }
    if payload[0] != BATCH_REF_TAG {
        return Err(format!("invalid batch ref tag: {}", payload[0]));
    }
    let round_id = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
    let sender = u16::from_be_bytes([payload[5], payload[6]]) as u32;
    Ok((round_id, sender))
}

pub(super) fn remember_archived_batch(
    batch_archive: &mut BatchArchive,
    round_id: usize,
    sender: usize,
    sealed_batch: &[u8],
) {
    batch_archive
        .entry((round_id as u32, sender as u32))
        .or_insert_with(|| sealed_batch.to_vec());
}

pub(super) fn build_acs_proposal_input(
    round_id: usize,
    pid: usize,
    pool: Option<&BroadcastMempool>,
    config: &BroadcastPoolConfig,
) -> Vec<u8> {
    let inline_payload = encode_batch_ref(round_id, pid);
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
    encode_bundle_acs_payload(&inline_payload, &references)
}

pub(super) fn collect_selected_proposals<'a>(
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

pub(super) fn selected_pids_from_proposals(
    selected_proposals: &[&AvailableProposal],
) -> Vec<usize> {
    selected_proposals
        .iter()
        .map(|proposal| proposal.proposer)
        .collect()
}

pub(super) fn batch_refs_from_selected_proposals(
    selected_proposals: &[&AvailableProposal],
) -> Result<Vec<(u32, u32)>, String> {
    let mut batch_refs = Vec::new();
    let mut seen_batch_refs = BTreeSet::new();
    for proposal in selected_proposals {
        match decode_acs_payload(&proposal.payload)? {
            AcsPayload::Inline(data) => {
                let batch_ref = decode_batch_ref(&data)?;
                if seen_batch_refs.insert(batch_ref) {
                    batch_refs.push(batch_ref);
                }
            }
            AcsPayload::Bundle {
                inline_payload,
                references,
            } => {
                if !references.is_empty() {
                    return Err(format!(
                        "proposal {} unexpectedly carried reusable references with pool reuse disabled",
                        proposal.proposal_id
                    ));
                }
                if inline_payload.is_empty() {
                    continue;
                }
                let batch_ref = decode_batch_ref(&inline_payload)?;
                if seen_batch_refs.insert(batch_ref) {
                    batch_refs.push(batch_ref);
                }
            }
        }
    }
    Ok(batch_refs)
}
