use super::*;
use crate::drive_acs::run_acs_round;

fn build_hosts(protocol: Protocol, nodes: usize, faulty: usize) -> Vec<RustAcsHost> {
    serialize_crypto_payloads(protocol, nodes, faulty)
        .expect("crypto payloads should serialize")
        .into_iter()
        .enumerate()
        .map(|(pid, payload)| {
            RustAcsHost::new(
                pid,
                nodes,
                faulty,
                crate::acs_host::parse_acs_crypto_payload(protocol, &payload)
                    .expect("crypto payload should parse"),
                r#"{"acs_host_backend":"rust"}"#,
            )
            .expect("Rust ACS host should construct")
        })
        .collect()
}

#[test]
fn completion_vector_roundtrip_rejects_invalid_bits() {
    let encoded = RustAcsHost::encode_completion_vector(&[true, false, true, true]);
    let decoded = RustAcsHost::decode_completion_vector(&encoded, 4).expect("vector should decode");
    assert_eq!(decoded, vec![true, false, true, true]);
    assert!(RustAcsHost::decode_completion_vector(&[0, 4, 2, 0, 0, 1], 4).is_err());
}

#[test]
fn rust_acs_round_reaches_consistent_decision() {
    let hosts = build_hosts(Protocol::HoneyBadger, 4, 1);
    let proposals = (0..4)
        .map(|pid| format!("rust-acs-proposal-{pid}").into_bytes())
        .collect::<Vec<_>>();
    let outcome =
        run_acs_round(&hosts, 0, "test:rust-acs:0:", &proposals, 5.0).expect("round succeeds");

    assert!(outcome.selected_proposal_ids.len() >= 3);
    assert_eq!(
        outcome.selected_proposal_ids.len(),
        outcome.selected_pids.len()
    );
    assert!(outcome.selected_pids.iter().all(|pid| *pid < 4));
}
