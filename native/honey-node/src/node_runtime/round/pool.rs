use super::super::config::ByzantineNodeConfig;
use super::super::pool_reuse::{AcsPayload, BroadcastMempool, PoolReference, decode_acs_payload};
use super::super::wire::{
    DriverWireFrame, encode_driver_frame, fanout_encoded_payload, send_frame,
};
use super::batch::decode_batch_ref;
use crate::AvailableProposal;
use honey_crypto::merkle;
use honey_node::pool_wire::{
    PoolFetchWire, encode_pool_fetch_request_wire, encode_pool_fetch_response_wire,
};
use honey_node::transport::LocalTcpTransport;
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct ResolvedSelectedProposals {
    pub(super) batch_refs: Vec<(u32, u32)>,
    pub(super) consumed_reference_ids: Vec<String>,
}

pub(super) struct PendingPoolFetchRequest {
    pub(super) round_id: usize,
    pub(super) message: PoolFetchWire,
}

pub(super) enum FetchRequestAction {
    None,
    Served,
    IgnoredByzantine,
    InvalidResponseSent,
}

pub(super) enum ProposalResolutionError {
    Invalid(String),
    MissingReusableEntry(PoolReference),
}

#[derive(Default)]
pub(super) struct PoolFetchTracker {
    pub(super) pending_references: BTreeMap<String, PoolReference>,
}

impl PoolFetchTracker {
    pub(super) fn request_reference(
        &mut self,
        transport: &LocalTcpTransport,
        round_id: usize,
        pid: usize,
        nodes: usize,
        reference: &PoolReference,
    ) -> Result<bool, String> {
        match self.pending_references.get(&reference.item_id) {
            Some(existing) if !references_match(existing, reference) => {
                return Err(format!(
                    "conflicting pending pool fetch metadata for {}",
                    reference.item_id
                ));
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

    pub(super) fn handle_request(
        &self,
        transport: &LocalTcpTransport,
        pid: usize,
        pool: &BroadcastMempool,
        request_round_id: usize,
        message: PoolFetchWire,
        byzantine_node_config: ByzantineNodeConfig,
    ) -> Result<FetchRequestAction, String> {
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

    pub(super) fn handle_response(
        &mut self,
        pool: &mut BroadcastMempool,
        nodes: usize,
        faulty: usize,
        message: PoolFetchWire,
    ) -> Result<bool, String> {
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
            return Err(format!(
                "failed to insert fetched reusable entry {} into Rust mempool",
                item_id
            ));
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

pub(super) fn resolve_selected_proposals(
    selected_proposals: &[&AvailableProposal],
    pool: &mut BroadcastMempool,
    allow_fetch_fallback: bool,
) -> Result<ResolvedSelectedProposals, ProposalResolutionError> {
    let mut batch_refs = Vec::new();
    let mut seen_batch_refs = BTreeSet::new();
    let mut consumed_reference_ids = Vec::new();
    let mut visited_reference_ids = BTreeSet::new();
    for proposal in selected_proposals {
        resolve_payload_bytes(
            &proposal.payload,
            pool,
            allow_fetch_fallback,
            &mut batch_refs,
            &mut seen_batch_refs,
            &mut consumed_reference_ids,
            &mut visited_reference_ids,
        )?;
    }
    Ok(ResolvedSelectedProposals {
        batch_refs,
        consumed_reference_ids,
    })
}

fn resolve_payload_bytes(
    payload: &[u8],
    pool: &mut BroadcastMempool,
    allow_fetch_fallback: bool,
    batch_refs: &mut Vec<(u32, u32)>,
    seen_batch_refs: &mut BTreeSet<(u32, u32)>,
    consumed_reference_ids: &mut Vec<String>,
    visited_reference_ids: &mut BTreeSet<String>,
) -> Result<(), ProposalResolutionError> {
    match decode_acs_payload(payload).map_err(ProposalResolutionError::Invalid)? {
        AcsPayload::Inline(data) => {
            let batch_ref = decode_batch_ref(&data).map_err(ProposalResolutionError::Invalid)?;
            if seen_batch_refs.insert(batch_ref) {
                batch_refs.push(batch_ref);
            }
            Ok(())
        }
        AcsPayload::Bundle {
            inline_payload,
            references,
        } => {
            if !inline_payload.is_empty() {
                let batch_ref =
                    decode_batch_ref(&inline_payload).map_err(ProposalResolutionError::Invalid)?;
                if seen_batch_refs.insert(batch_ref) {
                    batch_refs.push(batch_ref);
                }
            }
            for reference in references {
                if !visited_reference_ids.insert(reference.item_id.clone()) {
                    continue;
                }
                let nested_payload = if let Some(entry) = pool.get_reusable(&reference.item_id) {
                    if entry.round_no != reference.origin_round
                        || entry.sender_id != reference.origin_sender
                        || entry.roothash != reference.roothash
                    {
                        return Err(ProposalResolutionError::Invalid(format!(
                            "reusable entry {} metadata mismatch during payload resolution",
                            reference.item_id
                        )));
                    }
                    entry.payload.clone()
                } else if allow_fetch_fallback {
                    return Err(ProposalResolutionError::MissingReusableEntry(reference));
                } else {
                    return Err(ProposalResolutionError::Invalid(format!(
                        "missing reusable entry {} during payload resolution",
                        reference.item_id
                    )));
                };
                consumed_reference_ids.push(reference.item_id.clone());
                resolve_payload_bytes(
                    &nested_payload,
                    pool,
                    allow_fetch_fallback,
                    batch_refs,
                    seen_batch_refs,
                    consumed_reference_ids,
                    visited_reference_ids,
                )?;
            }
            Ok(())
        }
    }
}
