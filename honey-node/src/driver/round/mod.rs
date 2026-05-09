mod acs_io;
mod inbox;
mod r#loop;
pub(in crate::driver) mod metrics;
mod proposal;
pub(in crate::driver) mod state;
mod tpke;

pub(super) use r#loop::run_driver_rounds;

#[cfg(test)]
mod tests {
    use super::super::frame::PoolFetchWire;
    use super::super::mempool::fetch::{
        IncrementalProposalResolver, PoolFetchTracker, ProposalResolutionError,
        ResolvedSelectedProposals, resolve_selected_proposals,
    };
    use super::super::mempool::pool::{BroadcastMempool, PoolReference, encode_bundle_acs_payload};
    use honey_acs::proposal::AvailableProposal;
    use honey_crypto::merkle;

    #[test]
    fn test_resolve_selected_proposals_reports_missing_reference() {
        let reference = PoolReference {
            item_id: String::from("deadbeef01234567"),
            origin_round: 1,
            origin_sender: 2,
            roothash: vec![7; 32],
            proof_payload: vec![9; 8],
        };
        let proposal = AvailableProposal {
            proposal_id: String::from("1:2:deadbeef"),
            proposer: 2,
            payload: encode_bundle_acs_payload(b"", std::slice::from_ref(&reference)),
            digest: reference.roothash.clone(),
            availability_proof: reference.proof_payload.clone(),
        };
        let mut pool = BroadcastMempool::new(8, 4);

        match resolve_selected_proposals(&[&proposal], &mut pool, true) {
            Err(ProposalResolutionError::MissingReusableEntry(missing)) => {
                assert_eq!(missing.item_id, reference.item_id);
                assert_eq!(missing.origin_round, reference.origin_round);
                assert_eq!(missing.origin_sender, reference.origin_sender);
            }
            other => panic!(
                "unexpected resolution result: {:?}",
                other_result_tag(&other)
            ),
        }
    }

    #[test]
    fn test_resolve_selected_proposals_skips_consumed_nested_reference() {
        let root_a = vec![1; 32];
        let payload_a = encode_bundle_acs_payload(b"sealed-batch-a", &[]);
        let item_id_a = BroadcastMempool::compute_item_id(0, 0, &root_a);
        let reference_a = PoolReference {
            item_id: item_id_a.clone(),
            origin_round: 0,
            origin_sender: 0,
            roothash: root_a.clone(),
            proof_payload: vec![10; 8],
        };

        let root_b = vec![2; 32];
        let payload_b =
            encode_bundle_acs_payload(b"sealed-batch-b", std::slice::from_ref(&reference_a));
        let item_id_b = BroadcastMempool::compute_item_id(1, 1, &root_b);
        let reference_b = PoolReference {
            item_id: item_id_b,
            origin_round: 1,
            origin_sender: 1,
            roothash: root_b.clone(),
            proof_payload: vec![11; 8],
        };

        let mut pool = BroadcastMempool::new(8, 4);
        pool.add_reusable(payload_a, root_a.clone(), vec![10; 8], 0, 0);
        pool.mark_consumed(&item_id_a, 1);
        pool.add_reusable(payload_b, root_b.clone(), vec![11; 8], 1, 1);

        let proposal = AvailableProposal {
            proposal_id: String::from("2:2:root-b"),
            proposer: 2,
            payload: encode_bundle_acs_payload(b"", std::slice::from_ref(&reference_b)),
            digest: vec![3; 32],
            availability_proof: vec![12; 8],
        };

        let resolved = resolve_selected_proposals(&[&proposal], &mut pool, true)
            .expect("nested consumed reference should be skipped");

        assert_eq!(resolved.sealed_batches, vec![b"sealed-batch-b".to_vec()]);
        assert_eq!(resolved.selected_digests, vec![root_b]);
        assert_eq!(resolved.consumed_reference_ids, vec![reference_b.item_id]);
    }

    #[test]
    fn test_incremental_resolver_emits_ready_payloads_before_missing_reference_returns() {
        let ready_root = vec![1; 32];
        let ready_payload = encode_bundle_acs_payload(b"sealed-batch-ready", &[]);
        let ready_item_id = BroadcastMempool::compute_item_id(0, 0, &ready_root);
        let ready_reference = PoolReference {
            item_id: ready_item_id.clone(),
            origin_round: 0,
            origin_sender: 0,
            roothash: ready_root.clone(),
            proof_payload: vec![10; 8],
        };

        let missing_root = vec![2; 32];
        let missing_reference = PoolReference {
            item_id: BroadcastMempool::compute_item_id(0, 1, &missing_root),
            origin_round: 0,
            origin_sender: 1,
            roothash: missing_root.clone(),
            proof_payload: vec![11; 8],
        };

        let proposal = AvailableProposal {
            proposal_id: String::from("3:2:root"),
            proposer: 2,
            payload: encode_bundle_acs_payload(
                b"sealed-inline-root",
                &[ready_reference.clone(), missing_reference.clone()],
            ),
            digest: vec![9; 32],
            availability_proof: vec![12; 8],
        };
        let proposal_store = [(proposal.proposal_id.clone(), proposal.clone())]
            .into_iter()
            .collect::<_>();

        let mut pool = BroadcastMempool::new(8, 4);
        pool.add_reusable(ready_payload, ready_root.clone(), vec![10; 8], 0, 0);

        let mut resolver = IncrementalProposalResolver::new(true);
        let progress = resolver
            .step(
                std::slice::from_ref(&proposal.proposal_id),
                &proposal_store,
                &mut pool,
            )
            .expect("resolution step should succeed");

        assert!(!progress.complete);
        assert_eq!(progress.missing_references.len(), 1);
        assert_eq!(
            progress.missing_references[0].item_id,
            missing_reference.item_id
        );
        assert_eq!(
            progress.missing_references[0].roothash,
            missing_reference.roothash
        );
        assert_eq!(
            progress
                .newly_resolved_items
                .iter()
                .map(|item| item.payload_digest.clone())
                .collect::<Vec<_>>(),
            vec![proposal.digest.clone(), ready_root],
        );
        assert_eq!(resolver.consumed_reference_ids(), &[ready_item_id]);
    }

    #[test]
    fn test_pool_fetch_tracker_accepts_valid_response() {
        let payload = encode_bundle_acs_payload(b"sealed-batch-3-1", &[]);
        let encoded = merkle::encode(&payload, 2, 4).expect("payload should encode");
        let reference = PoolReference {
            item_id: BroadcastMempool::compute_item_id(2, 1, &encoded.root),
            origin_round: 2,
            origin_sender: 1,
            roothash: encoded.root.to_vec(),
            proof_payload: vec![5; 8],
        };
        let mut tracker = PoolFetchTracker::default();
        tracker
            .pending_references
            .insert(reference.item_id.clone(), reference.clone());
        let mut pool = BroadcastMempool::new(8, 4);

        let accepted = tracker
            .handle_response(
                &mut pool,
                4,
                1,
                PoolFetchWire::Response {
                    sender: 0,
                    item_id: reference.item_id.clone(),
                    payload: payload.clone(),
                },
            )
            .expect("response handling should succeed");

        assert!(accepted);
        let stored = pool
            .get_reusable(&reference.item_id)
            .expect("fetched entry should be inserted");
        assert_eq!(stored.payload, payload);
        assert_eq!(stored.roothash, reference.roothash);
        assert!(!tracker.pending_references.contains_key(&reference.item_id));
    }

    fn other_result_tag(
        result: &Result<ResolvedSelectedProposals, ProposalResolutionError>,
    ) -> &'static str {
        match result {
            Ok(_) => "ok",
            Err(ProposalResolutionError::Invalid(_)) => "invalid",
            Err(ProposalResolutionError::MissingReusableEntry(_)) => "missing",
        }
    }
}
