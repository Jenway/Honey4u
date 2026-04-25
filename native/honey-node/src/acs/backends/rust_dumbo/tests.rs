use super::*;
use crate::acs::harness::{run_acs_round, serialize_crypto_payloads};
use crate::acs::protocol::AcsProtocol;

fn build_hosts(nodes: usize, faulty: usize) -> Vec<RustDumboAcsBackend> {
    serialize_crypto_payloads(AcsProtocol::Dumbo, nodes, faulty)
        .expect("crypto payloads should serialize")
        .into_iter()
        .enumerate()
        .map(|(pid, payload)| {
            RustDumboAcsBackend::new(
                pid,
                nodes,
                faulty,
                crate::acs::parse_acs_crypto_payload(AcsProtocol::Dumbo, &payload)
                    .expect("crypto payload should parse"),
                r#"{"acs_host_backend":"rust_dumbo"}"#,
            )
            .expect("Rust Dumbo ACS host should construct")
        })
        .collect()
}

#[test]
fn prbc_vector_roundtrip() {
    let proof = PrbcProof {
        roothash: [7; 32],
        sigmas: vec![(0, vec![1; 64]), (2, vec![3; 64])],
    };
    let encoded = RustDumboAcsBackend::serialize_prbc_vector(&[
        Some(proof.clone()),
        None,
        Some(proof.clone()),
        None,
    ]);
    let decoded =
        RustDumboAcsBackend::deserialize_prbc_vector(&encoded, 4).expect("vector decodes");
    assert!(decoded[0].is_some());
    assert!(decoded[1].is_none());
    assert_eq!(decoded[2].as_ref().expect("proof").roothash, proof.roothash);
}

#[test]
fn rust_dumbo_acs_round_reaches_consistent_decision() {
    let hosts = build_hosts(4, 1);
    let proposals = (0..4)
        .map(|pid| format!("rust-dumbo-acs-proposal-{pid}").into_bytes())
        .collect::<Vec<_>>();
    let outcome = run_acs_round(&hosts, 0, "test:rust-dumbo-acs:0:", &proposals, 5.0)
        .expect("round succeeds");

    assert!(outcome.selected_proposal_ids.len() >= 3);
    assert_eq!(
        outcome.selected_proposal_ids.len(),
        outcome.selected_pids.len()
    );
    assert!(outcome.selected_pids.iter().all(|pid| *pid < 4));
}
