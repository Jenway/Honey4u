use bincode::{deserialize, serialize};
use honey_node::transport::LocalTcpTransport;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(super) enum DriverWireFrame {
    AcsEnvelope {
        round_id: usize,
        payload: Vec<u8>,
    },
    HbBatch {
        sender: usize,
        round_id: usize,
        sealed_batch: Vec<u8>,
    },
    HbShareBundle {
        sender: usize,
        round_id: usize,
        selected_batch_refs: Vec<(u32, u32)>,
        shares: Vec<Option<Vec<u8>>>,
    },
}

pub(super) fn encode_driver_frame(frame: &DriverWireFrame) -> Result<Vec<u8>, String> {
    serialize(frame).map_err(|err| err.to_string())
}

pub(super) fn decode_driver_frame(payload: &[u8]) -> Result<DriverWireFrame, String> {
    deserialize(payload).map_err(|err| err.to_string())
}

pub(super) fn send_frame(
    transport: &LocalTcpTransport,
    recipient: usize,
    frame: &DriverWireFrame,
) -> Result<(), String> {
    let payload = encode_driver_frame(frame)?;
    send_encoded_payload(transport, recipient, &payload)
}

pub(super) fn send_encoded_payload(
    transport: &LocalTcpTransport,
    recipient: usize,
    payload: &[u8],
) -> Result<(), String> {
    transport
        .send(recipient, payload)
        .map_err(|err| err.to_string())
}

pub(super) fn fanout_encoded_payload(
    transport: &LocalTcpTransport,
    nodes: usize,
    payload: &[u8],
    skip_recipient: Option<usize>,
) -> Result<usize, String> {
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

pub(super) fn broadcast_frame(
    transport: &LocalTcpTransport,
    nodes: usize,
    frame: &DriverWireFrame,
) -> Result<(), String> {
    let payload = encode_driver_frame(frame)?;
    let _ = fanout_encoded_payload(transport, nodes, &payload, None)?;
    Ok(())
}

pub(super) fn parse_addresses_json(payload: &str) -> Result<Vec<(String, u16)>, String> {
    serde_json::from_str(payload).map_err(|err| err.to_string())
}
