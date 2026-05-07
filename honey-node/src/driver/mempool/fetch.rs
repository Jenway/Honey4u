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

#[allow(dead_code)]
pub(in crate::driver) struct ResolvedSelectedProposals {
    pub(in crate::driver) sealed_batches: Vec<Vec<u8>>,
    pub(in crate::driver) selected_digests: Vec<Vec<u8>>,
    pub(in crate::driver) consumed_reference_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::driver) struct ResolvedPayloadItem {
    pub(in crate::driver) sealed_batch: Vec<u8>,
    pub(in crate::driver) payload_digest: Vec<u8>,
}

pub(in crate::driver) struct ProposalResolutionProgress {
    pub(in crate::driver) newly_resolved_items: Vec<ResolvedPayloadItem>,
    pub(in crate::driver) missing_references: Vec<PoolReference>,
    pub(in crate::driver) complete: bool,
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
    #[allow(dead_code)]
    MissingReusableEntry(PoolReference),
}

#[derive(Default)]
pub(in crate::driver) struct PoolFetchTracker {
    pub(in crate::driver) pending_references: BTreeMap<String, PoolReference>,
}

pub(in crate::driver) struct IncrementalProposalResolver {
    allow_fetch_fallback: bool,
    seen_digests: BTreeSet<Vec<u8>>,
    completed_selected_proposals: BTreeSet<String>,
    resolved_reference_ids: BTreeSet<String>,
    consumed_reference_ids: Vec<String>,
    consumed_reference_set: BTreeSet<String>,
}

impl IncrementalProposalResolver {
    pub(in crate::driver) fn new(allow_fetch_fallback: bool) -> Self {
        Self {
            allow_fetch_fallback,
            seen_digests: BTreeSet::new(),
            completed_selected_proposals: BTreeSet::new(),
            resolved_reference_ids: BTreeSet::new(),
            consumed_reference_ids: Vec::new(),
            consumed_reference_set: BTreeSet::new(),
        }
    }

    pub(in crate::driver) fn step(
        &mut self,
        selected_proposal_ids: &[String],
        proposal_store: &BTreeMap<String, AvailableProposal>,
        pool: &mut BroadcastMempool,
    ) -> Result<ProposalResolutionProgress, ProposalResolutionError> {
        let mut newly_resolved_items = Vec::new();
        let mut missing_references = Vec::new();
        for proposal_id in selected_proposal_ids {
            if self.completed_selected_proposals.contains(proposal_id) {
                continue;
            }
            let Some(proposal) = proposal_store.get(proposal_id) else {
                continue;
            };
            let mut visiting_references = BTreeSet::new();
            let proposal_missing = self.resolve_payload_bytes(
                &proposal.payload,
                &proposal.digest,
                pool,
                &mut newly_resolved_items,
                &mut visiting_references,
            )?;
            if proposal_missing.is_empty() {
                self.completed_selected_proposals
                    .insert(proposal_id.clone());
            } else {
                missing_references.extend(proposal_missing);
            }
        }
        let complete = selected_proposal_ids
            .iter()
            .all(|proposal_id| self.completed_selected_proposals.contains(proposal_id));
        Ok(ProposalResolutionProgress {
            newly_resolved_items,
            missing_references,
            complete,
        })
    }

    pub(in crate::driver) fn consumed_reference_ids(&self) -> &[String] {
        &self.consumed_reference_ids
    }

    fn resolve_payload_bytes(
        &mut self,
        payload: &[u8],
        payload_digest: &[u8],
        pool: &mut BroadcastMempool,
        newly_resolved_items: &mut Vec<ResolvedPayloadItem>,
        visiting_references: &mut BTreeSet<String>,
    ) -> Result<Vec<PoolReference>, ProposalResolutionError> {
        match decode_acs_payload(payload)
            .map_err(|err| ProposalResolutionError::Invalid(err.to_string()))?
        {
            AcsPayload::Inline(data) => {
                if !data.is_empty() && self.seen_digests.insert(payload_digest.to_vec()) {
                    newly_resolved_items.push(ResolvedPayloadItem {
                        sealed_batch: data,
                        payload_digest: payload_digest.to_vec(),
                    });
                }
                Ok(Vec::new())
            }
            AcsPayload::Bundle {
                inline_payload,
                references,
            } => {
                if !inline_payload.is_empty() && self.seen_digests.insert(payload_digest.to_vec()) {
                    newly_resolved_items.push(ResolvedPayloadItem {
                        sealed_batch: inline_payload,
                        payload_digest: payload_digest.to_vec(),
                    });
                }

                let mut missing_references = Vec::new();
                for reference in references {
                    if self.resolved_reference_ids.contains(&reference.item_id)
                        || !visiting_references.insert(reference.item_id.clone())
                    {
                        continue;
                    }

                    let nested_missing = match pool.get_reusable(&reference.item_id) {
                        Some(entry) => {
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
                                Vec::new()
                            } else {
                                if self
                                    .consumed_reference_set
                                    .insert(reference.item_id.clone())
                                {
                                    self.consumed_reference_ids.push(reference.item_id.clone());
                                }
                                let nested_payload = entry.payload.clone();
                                self.resolve_payload_bytes(
                                    &nested_payload,
                                    &reference.roothash,
                                    pool,
                                    newly_resolved_items,
                                    visiting_references,
                                )?
                            }
                        }
                        None if self.allow_fetch_fallback => vec![reference.clone()],
                        None => {
                            return Err(ProposalResolutionError::Invalid(format!(
                                "missing reusable entry {} during payload resolution",
                                reference.item_id
                            )));
                        }
                    };

                    if nested_missing.is_empty() {
                        self.resolved_reference_ids
                            .insert(reference.item_id.clone());
                    } else {
                        missing_references.extend(nested_missing);
                    }
                    visiting_references.remove(&reference.item_id);
                }
                Ok(missing_references)
            }
        }
    }
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

#[allow(dead_code)]
pub(in crate::driver) fn resolve_selected_proposals(
    selected_proposals: &[&AvailableProposal],
    pool: &mut BroadcastMempool,
    allow_fetch_fallback: bool,
) -> Result<ResolvedSelectedProposals, ProposalResolutionError> {
    let proposal_store = selected_proposals
        .iter()
        .map(|proposal| (proposal.proposal_id.clone(), (*proposal).clone()))
        .collect::<BTreeMap<_, _>>();
    let selected_proposal_ids = selected_proposals
        .iter()
        .map(|proposal| proposal.proposal_id.clone())
        .collect::<Vec<_>>();
    let mut resolver = IncrementalProposalResolver::new(allow_fetch_fallback);
    let progress = resolver.step(&selected_proposal_ids, &proposal_store, pool)?;
    if !progress.complete {
        if let Some(reference) = progress.missing_references.into_iter().next() {
            return Err(ProposalResolutionError::MissingReusableEntry(reference));
        }
        return Err(ProposalResolutionError::Invalid(
            "selected proposal payload resolution incomplete".to_string(),
        ));
    }
    Ok(ResolvedSelectedProposals {
        sealed_batches: progress
            .newly_resolved_items
            .iter()
            .map(|item| item.sealed_batch.clone())
            .collect(),
        selected_digests: progress
            .newly_resolved_items
            .iter()
            .map(|item| item.payload_digest.clone())
            .collect(),
        consumed_reference_ids: resolver.consumed_reference_ids().to_vec(),
    })
}
