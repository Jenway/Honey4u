use super::super::error::{DriverError, DriverResult};
use honey_node::transport::LocalTcpTransport;
use honey_wire::api::{decode_result, encode_result};
use rkyv::{Archive, Deserialize, Serialize};

#[derive(Archive, Serialize, Deserialize)]
pub(in crate::driver_node) enum DriverWireFrame {
    AcsEnvelope {
        round_id: usize,
        payload: Vec<u8>,
    },
    HbShareBundle {
        sender: usize,
        round_id: usize,
        selected_proposal_ids: Vec<String>,
        selected_digests: Vec<Vec<u8>>,
        shares: Vec<Option<Vec<u8>>>,
    },
}

pub(in crate::driver_node) fn encode_driver_frame(
    frame: &DriverWireFrame,
) -> DriverResult<Vec<u8>> {
    encode_result(frame).map_err(DriverError::wire)
}

pub(in crate::driver_node) fn decode_driver_frame(payload: &[u8]) -> DriverResult<DriverWireFrame> {
    decode_result(payload).map_err(DriverError::wire)
}

pub(in crate::driver_node) fn send_frame(
    transport: &LocalTcpTransport,
    recipient: usize,
    frame: &DriverWireFrame,
) -> DriverResult<()> {
    let payload = encode_driver_frame(frame)?;
    send_encoded_payload(transport, recipient, &payload)
}

pub(in crate::driver_node) fn send_encoded_payload(
    transport: &LocalTcpTransport,
    recipient: usize,
    payload: &[u8],
) -> DriverResult<()> {
    transport.send(recipient, payload)?;
    Ok(())
}

pub(in crate::driver_node) fn fanout_encoded_payload(
    transport: &LocalTcpTransport,
    nodes: usize,
    payload: &[u8],
    skip_recipient: Option<usize>,
) -> DriverResult<usize> {
    let mut sent = 0usize;
    for recipient in 0..nodes {
        if skip_recipient == Some(recipient) {
            continue;
        }
        send_encoded_payload(transport, recipient, payload)?;
        sent += 1;
    }
    Ok(sent)
}

pub(in crate::driver_node) fn parse_addresses_json(
    payload: &str,
) -> DriverResult<Vec<(String, u16)>> {
    serde_json::from_str(payload).map_err(|err| DriverError::config(err.to_string()))
}
