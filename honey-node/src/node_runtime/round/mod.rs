mod batch;
mod driver;
mod pool;
mod transport;

pub(super) use driver::{run_driver_rounds, wait_until_start};

#[cfg(test)]
mod tests {
    use super::super::config::ByzantineNodeConfig;
    use super::super::driver_wire::{DriverWireFrame, decode_driver_frame};
    use super::super::pool_reuse::{BroadcastMempool, PoolReference, encode_bundle_acs_payload};
    use super::super::pool_wire::{PoolFetchWire, decode_pool_fetch_from_wire};
    use super::batch::encode_batch_ref;
    use super::pool::{
        FetchRequestAction, PoolFetchTracker, ProposalResolutionError, ResolvedSelectedProposals,
        resolve_selected_proposals,
    };
    use honey_acs::proposal::AvailableProposal;
    use honey_crypto::merkle;
    use honey_node::transport::LocalTcpTransport;
    use std::net::TcpListener;
    use std::time::{Duration, Instant};

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
    fn test_pool_fetch_tracker_accepts_valid_response() {
        let payload = encode_bundle_acs_payload(&encode_batch_ref(3, 1), &[]);
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

    #[test]
    fn test_pool_fetch_tracker_round_trip_over_local_transport() {
        let reserved = (0..2)
            .map(|_| TcpListener::bind("127.0.0.1:0").expect("should reserve loopback port"))
            .collect::<Vec<_>>();
        let addresses = reserved
            .iter()
            .map(|listener| {
                let addr = listener
                    .local_addr()
                    .expect("listener should expose local addr");
                (String::from("127.0.0.1"), addr.port())
            })
            .collect::<Vec<_>>();
        drop(reserved);

        let mut responder_transport =
            LocalTcpTransport::new(0, addresses.clone(), Default::default())
                .expect("transport 0 should bind");
        let mut requester_transport = LocalTcpTransport::new(1, addresses, Default::default())
            .expect("transport 1 should bind");

        let payload = encode_bundle_acs_payload(&encode_batch_ref(3, 1), &[]);
        let encoded = merkle::encode(&payload, 2, 4).expect("payload should encode");
        let reference = PoolReference {
            item_id: BroadcastMempool::compute_item_id(2, 0, &encoded.root),
            origin_round: 2,
            origin_sender: 0,
            roothash: encoded.root.to_vec(),
            proof_payload: vec![7; 8],
        };

        let mut responder_pool = BroadcastMempool::new(8, 4);
        responder_pool.add_reusable(
            payload.clone(),
            reference.roothash.clone(),
            reference.proof_payload.clone(),
            reference.origin_round,
            reference.origin_sender,
        );

        let mut requester_tracker = PoolFetchTracker::default();
        let requested = requester_tracker
            .request_reference(&requester_transport, 5, 1, 2, &reference)
            .expect("request should encode and send");
        assert!(requested);

        let request = recv_single_fetch_wire(&responder_transport, Duration::from_secs(2));
        let responded = PoolFetchTracker::default()
            .handle_request(
                &responder_transport,
                0,
                &responder_pool,
                5,
                request,
                ByzantineNodeConfig::default(),
            )
            .expect("request handling should succeed");
        assert!(matches!(responded, FetchRequestAction::Served));

        let response = recv_single_fetch_wire(&requester_transport, Duration::from_secs(2));
        let mut requester_pool = BroadcastMempool::new(8, 4);
        let inserted = requester_tracker
            .handle_response(&mut requester_pool, 4, 1, response)
            .expect("response handling should succeed");
        assert!(inserted);
        let stored = requester_pool
            .get_reusable(&reference.item_id)
            .expect("fetched entry should be inserted into requester pool");
        assert_eq!(stored.payload, payload);
        assert_eq!(stored.roothash, reference.roothash);
        assert!(
            !requester_tracker
                .pending_references
                .contains_key(&reference.item_id)
        );

        responder_transport
            .close()
            .expect("responder transport should close");
        requester_transport
            .close()
            .expect("requester transport should close");
    }

    #[test]
    fn test_pool_fetch_tracker_can_send_invalid_byzantine_response() {
        let reserved = (0..2)
            .map(|_| TcpListener::bind("127.0.0.1:0").expect("should reserve loopback port"))
            .collect::<Vec<_>>();
        let addresses = reserved
            .iter()
            .map(|listener| {
                let addr = listener
                    .local_addr()
                    .expect("listener should expose local addr");
                (String::from("127.0.0.1"), addr.port())
            })
            .collect::<Vec<_>>();
        drop(reserved);

        let mut responder_transport =
            LocalTcpTransport::new(0, addresses.clone(), Default::default())
                .expect("transport 0 should bind");
        let mut requester_transport = LocalTcpTransport::new(1, addresses, Default::default())
            .expect("transport 1 should bind");

        let payload = encode_bundle_acs_payload(&encode_batch_ref(3, 1), &[]);
        let encoded = merkle::encode(&payload, 2, 4).expect("payload should encode");
        let reference = PoolReference {
            item_id: BroadcastMempool::compute_item_id(2, 0, &encoded.root),
            origin_round: 2,
            origin_sender: 0,
            roothash: encoded.root.to_vec(),
            proof_payload: vec![7; 8],
        };

        let mut responder_pool = BroadcastMempool::new(8, 4);
        responder_pool.add_reusable(
            payload.clone(),
            reference.roothash.clone(),
            reference.proof_payload.clone(),
            reference.origin_round,
            reference.origin_sender,
        );

        let mut requester_tracker = PoolFetchTracker::default();
        let requested = requester_tracker
            .request_reference(&requester_transport, 5, 1, 2, &reference)
            .expect("request should encode and send");
        assert!(requested);

        let request = recv_single_fetch_wire(&responder_transport, Duration::from_secs(2));
        let action = PoolFetchTracker::default()
            .handle_request(
                &responder_transport,
                0,
                &responder_pool,
                5,
                request,
                ByzantineNodeConfig {
                    behavior: Some(super::super::config::ByzantineBehavior::InvalidFetchResponse),
                },
            )
            .expect("request handling should succeed");
        assert!(matches!(action, FetchRequestAction::InvalidResponseSent));

        let response = recv_single_fetch_wire(&requester_transport, Duration::from_secs(2));
        let mut requester_pool = BroadcastMempool::new(8, 4);
        let inserted = requester_tracker
            .handle_response(&mut requester_pool, 4, 1, response)
            .expect("response handling should succeed");
        assert!(!inserted);
        assert!(requester_pool.get_reusable(&reference.item_id).is_none());
        assert!(
            requester_tracker
                .pending_references
                .contains_key(&reference.item_id)
        );

        responder_transport
            .close()
            .expect("responder transport should close");
        requester_transport
            .close()
            .expect("requester transport should close");
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

    fn recv_single_fetch_wire(transport: &LocalTcpTransport, timeout: Duration) -> PoolFetchWire {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let batch = transport.recv_batch(16).expect("recv_batch should succeed");
            for payload in batch {
                let frame = decode_driver_frame(&payload).expect("driver frame should decode");
                let DriverWireFrame::AcsEnvelope {
                    round_id: _round_id,
                    payload,
                } = frame
                else {
                    continue;
                };
                if let Some(message) =
                    decode_pool_fetch_from_wire(&payload).expect("fetch wire should decode")
                {
                    return message;
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("timed out waiting for pool fetch wire message");
    }
}
