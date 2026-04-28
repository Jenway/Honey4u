use super::pool::{AcsPayload, BroadcastMempool, PoolReference, decode_acs_payload};
use crate::driver::config::ByzantineNodeConfig;
use crate::driver::error::{DriverError, DriverResult};
use crate::driver::frame::{
    DriverWireFrame, PoolFetchWire, encode_driver_frame, encode_pool_fetch_request_wire,
    encode_pool_fetch_response_wire, fanout_encoded_payload, send_frame,
};
use honey_acs::proposal::AvailableProposal;
use honey_crypto::merkle;
use honey_transport::TransportHandle;
use std::collections::{BTreeMap, BTreeSet};

pub(in crate::driver) struct ResolvedSelectedProposals {
    pub(in crate::driver) sealed_batches: Vec<Vec<u8>>,
    pub(in crate::driver) selected_digests: Vec<Vec<u8>>,
    pub(in crate::driver) consumed_reference_ids: Vec<String>,
}

pub(in crate::driver) struct PendingPoolFetchRequest {
    pub(in crate::driver) round_id: usize,
    pub(in crate::driver) message: PoolFetchWire,
}

pub(in crate::driver) enum FetchRequestAction {
    None,
    Served,
    IgnoredByzantine,
    InvalidResponseSent,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProposalResolutionError {
    #[error("invalid selected proposal payload: {0}")]
    Invalid(String),
    #[error("missing reusable entry {0:?} during payload resolution")]
    MissingReusableEntry(PoolReference),
}

#[derive(Default)]
pub(in crate::driver) struct PoolFetchTracker {
    pub(in crate::driver) pending_references: BTreeMap<String, PoolReference>,
}

impl PoolFetchTracker {
    pub(in crate::driver) fn request_reference(
        &mut self,
        transport: &dyn TransportHandle,
        round_id: usize,
        pid: usize,
        nodes: usize,
        reference: &PoolReference,
    ) -> DriverResult<bool> {
        match self.pending_references.get(&reference.item_id) {
            Some(existing) if !references_match(existing, reference) => {
                return Err(DriverError::pool_fetch(format!(
                    "conflicting pending pool fetch metadata for {}",
                    reference.item_id
                )));
            }
            Some(_) => return Ok(false),
            None => {
                self.pending_references
                    .insert(reference.item_id.clone(), reference.clone());
            }
        }

        let payload = encode_pool_fetch_request_wire(
            pid as u32,
            round_id as u32,
            &reference.item_id,
            reference.origin_round,
            reference.origin_sender,
            &reference.roothash,
        )?;
        let frame_payload =
            encode_driver_frame(&DriverWireFrame::AcsEnvelope { round_id, payload })?;
        let sent = fanout_encoded_payload(transport, nodes, &frame_payload, Some(pid))?;
        Ok(sent > 0)
    }

    pub(in crate::driver) fn handle_request(
        &self,
        transport: &dyn TransportHandle,
        pid: usize,
        pool: &BroadcastMempool,
        request_round_id: usize,
        message: PoolFetchWire,
        byzantine_node_config: ByzantineNodeConfig,
    ) -> DriverResult<FetchRequestAction> {
        let PoolFetchWire::Request {
            sender,
            item_id,
            origin_round,
            origin_sender,
            roothash,
        } = message
        else {
            return Ok(FetchRequestAction::None);
        };
        let sender = sender as usize;
        if sender == pid {
            return Ok(FetchRequestAction::None);
        }
        let Some(entry) = pool.get_reusable(&item_id) else {
            return Ok(FetchRequestAction::None);
        };
        if entry.round_no != origin_round
            || entry.sender_id != origin_sender
            || entry.roothash != roothash
        {
            return Ok(FetchRequestAction::None);
        }
        if byzantine_node_config.is_silent() {
            return Ok(FetchRequestAction::IgnoredByzantine);
        }
        let response_payload = if byzantine_node_config.sends_invalid_fetch_response() {
            corrupt_fetch_response_payload(&entry.payload)
        } else {
            entry.payload.clone()
        };
        let payload = encode_pool_fetch_response_wire(
            pid as u32,
            request_round_id as u32,
            &item_id,
            &response_payload,
        )?;
        send_frame(
            transport,
            sender,
            &DriverWireFrame::AcsEnvelope {
                round_id: request_round_id,
                payload,
            },
        )?;
        Ok(if byzantine_node_config.sends_invalid_fetch_response() {
            FetchRequestAction::InvalidResponseSent
        } else {
            FetchRequestAction::Served
        })
    }

    pub(in crate::driver) fn handle_response(
        &mut self,
        pool: &mut BroadcastMempool,
        nodes: usize,
        faulty: usize,
        message: PoolFetchWire,
    ) -> DriverResult<bool> {
        let PoolFetchWire::Response {
            sender: _sender,
            item_id,
            payload,
        } = message
        else {
            return Ok(false);
        };
        if pool.get_reusable(&item_id).is_some() {
            self.pending_references.remove(&item_id);
            return Ok(false);
        }
        let Some(reference) = self.pending_references.get(&item_id).cloned() else {
            return Ok(false);
        };
        if !validate_fetched_reusable_payload(&payload, &reference, nodes, faulty) {
            return Ok(false);
        }
        pool.add_reusable(
            payload,
            reference.roothash.clone(),
            reference.proof_payload.clone(),
            reference.origin_round,
            reference.origin_sender,
        );
        if pool.get_reusable(&item_id).is_none() {
            return Err(DriverError::pool_fetch(format!(
                "failed to insert fetched reusable entry {} into Rust mempool",
                item_id
            )));
        }
        self.pending_references.remove(&item_id);
        Ok(true)
    }
}

fn corrupt_fetch_response_payload(payload: &[u8]) -> Vec<u8> {
    if payload.is_empty() {
        return vec![0xFF];
    }
    let mut corrupted = payload.to_vec();
    corrupted[0] ^= 0xFF;
    corrupted
}

fn references_match(left: &PoolReference, right: &PoolReference) -> bool {
    left.item_id == right.item_id
        && left.origin_round == right.origin_round
        && left.origin_sender == right.origin_sender
        && left.roothash == right.roothash
        && left.proof_payload == right.proof_payload
}

fn validate_fetched_reusable_payload(
    payload: &[u8],
    reference: &PoolReference,
    nodes: usize,
    faulty: usize,
) -> bool {
    if BroadcastMempool::compute_item_id(
        reference.origin_round,
        reference.origin_sender,
        &reference.roothash,
    ) != reference.item_id
    {
        return false;
    }
    let data_threshold = nodes.saturating_sub(2 * faulty);
    if data_threshold == 0 {
        return false;
    }
    let Ok(encoded) = merkle::encode(payload, data_threshold, nodes) else {
        return false;
    };
    encoded.root.as_slice() == reference.roothash.as_slice()
}

pub(in crate::driver) fn resolve_selected_proposals(
    selected_proposals: &[&AvailableProposal],
    pool: &mut BroadcastMempool,
    allow_fetch_fallback: bool,
) -> Result<ResolvedSelectedProposals, ProposalResolutionError> {
    let mut sealed_batches = Vec::new();
    let mut selected_digests = Vec::new();
    let mut seen_digests = BTreeSet::new();
    let mut consumed_reference_ids = Vec::new();
    let mut visited_reference_ids = BTreeSet::new();
    let mut state = PayloadResolutionState {
        pool,
        allow_fetch_fallback,
        sealed_batches: &mut sealed_batches,
        selected_digests: &mut selected_digests,
        seen_digests: &mut seen_digests,
        consumed_reference_ids: &mut consumed_reference_ids,
        visited_reference_ids: &mut visited_reference_ids,
    };
    for proposal in selected_proposals {
        resolve_payload_bytes(&proposal.payload, &proposal.digest, &mut state)?;
    }
    Ok(ResolvedSelectedProposals {
        sealed_batches,
        selected_digests,
        consumed_reference_ids,
    })
}

struct PayloadResolutionState<'a> {
    pool: &'a mut BroadcastMempool,
    allow_fetch_fallback: bool,
    sealed_batches: &'a mut Vec<Vec<u8>>,
    selected_digests: &'a mut Vec<Vec<u8>>,
    seen_digests: &'a mut BTreeSet<Vec<u8>>,
    consumed_reference_ids: &'a mut Vec<String>,
    visited_reference_ids: &'a mut BTreeSet<String>,
}

fn resolve_payload_bytes(
    payload: &[u8],
    payload_digest: &[u8],
    state: &mut PayloadResolutionState<'_>,
) -> Result<(), ProposalResolutionError> {
    match decode_acs_payload(payload)
        .map_err(|err| ProposalResolutionError::Invalid(err.to_string()))?
    {
        AcsPayload::Inline(data) => {
            if !data.is_empty() && state.seen_digests.insert(payload_digest.to_vec()) {
                state.sealed_batches.push(data);
                state.selected_digests.push(payload_digest.to_vec());
            }
            Ok(())
        }
        AcsPayload::Bundle {
            inline_payload,
            references,
        } => {
            if !inline_payload.is_empty() && state.seen_digests.insert(payload_digest.to_vec()) {
                state.sealed_batches.push(inline_payload);
                state.selected_digests.push(payload_digest.to_vec());
            }
            for reference in references {
                if !state
                    .visited_reference_ids
                    .insert(reference.item_id.clone())
                {
                    continue;
                }
                let nested_payload =
                    if let Some(entry) = state.pool.get_reusable(&reference.item_id) {
                        if entry.round_no != reference.origin_round
                            || entry.sender_id != reference.origin_sender
                            || entry.roothash != reference.roothash
                        {
                            return Err(ProposalResolutionError::Invalid(format!(
                                "reusable entry {} metadata mismatch during payload resolution",
                                reference.item_id
                            )));
                        }
                        if entry.consumed_in_round.is_some() {
                            continue;
                        }
                        entry.payload.clone()
                    } else if state.allow_fetch_fallback {
                        return Err(ProposalResolutionError::MissingReusableEntry(reference));
                    } else {
                        return Err(ProposalResolutionError::Invalid(format!(
                            "missing reusable entry {} during payload resolution",
                            reference.item_id
                        )));
                    };
                state.consumed_reference_ids.push(reference.item_id.clone());
                resolve_payload_bytes(&nested_payload, &reference.roothash, state)?;
            }
            Ok(())
        }
    }
}
