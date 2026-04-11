use super::*;
use crate::drive_acs::run_acs_round;

fn build_hosts(nodes: usize, faulty: usize, mode: HbBroadcastMode) -> Vec<RustHbAcsHost> {
    let config_json = match mode {
        HbBroadcastMode::Rbc => r#"{"acs_host_backend":"rust_hb","hb_broadcast_protocol":"rbc"}"#,
        HbBroadcastMode::Prbc => r#"{"acs_host_backend":"rust_hb","hb_broadcast_protocol":"prbc"}"#,
    };
    serialize_crypto_payloads(Protocol::HoneyBadger, nodes, faulty)
        .expect("crypto payloads should serialize")
        .into_iter()
        .enumerate()
        .map(|(pid, payload)| {
            RustHbAcsHost::new(
                pid,
                nodes,
                faulty,
                crate::acs_host::parse_acs_crypto_payload(Protocol::HoneyBadger, &payload)
                    .expect("crypto payload should parse"),
                config_json,
            )
            .expect("Rust HB ACS host should construct")
        })
        .collect()
}

#[test]
fn rust_hb_rbc_round_reaches_consistent_decision() {
    let hosts = build_hosts(4, 1, HbBroadcastMode::Rbc);
    let proposals = (0..4)
        .map(|pid| format!("rust-hb-rbc-proposal-{pid}").into_bytes())
        .collect::<Vec<_>>();
    let outcome =
        run_acs_round(&hosts, 0, "test:rust-hb:rbc:0:", &proposals, 5.0).expect("round succeeds");

    assert!(outcome.selected_proposal_ids.len() >= 3);
    assert_eq!(
        outcome.selected_proposal_ids.len(),
        outcome.selected_pids.len()
    );
    assert!(outcome.selected_pids.iter().all(|pid| *pid < 4));
}

#[test]
fn rust_hb_prbc_round_reaches_consistent_decision() {
    let hosts = build_hosts(4, 1, HbBroadcastMode::Prbc);
    let proposals = (0..4)
        .map(|pid| format!("rust-hb-prbc-proposal-{pid}").into_bytes())
        .collect::<Vec<_>>();
    let outcome =
        run_acs_round(&hosts, 0, "test:rust-hb:prbc:0:", &proposals, 5.0).expect("round succeeds");

    assert!(outcome.selected_proposal_ids.len() >= 3);
    assert_eq!(
        outcome.selected_proposal_ids.len(),
        outcome.selected_pids.len()
    );
    assert!(outcome.selected_pids.iter().all(|pid| *pid < 4));
}
