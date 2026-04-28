use honey_transport::TransportHandle;

use crate::driver::error::{DriverError, DriverResult};
use honey_wire::api::{decode_result, encode_result};
use rkyv::{Archive, Deserialize, Serialize};

#[derive(Archive, Serialize, Deserialize)]
pub(in crate::driver) enum DriverWireFrame {
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

pub(in crate::driver) fn encode_driver_frame(frame: &DriverWireFrame) -> DriverResult<Vec<u8>> {
    encode_result(frame).map_err(DriverError::wire)
}

pub(in crate::driver) fn decode_driver_frame(payload: &[u8]) -> DriverResult<DriverWireFrame> {
    decode_result(payload).map_err(DriverError::wire)
}

pub(in crate::driver) fn send_frame(
    transport: &dyn TransportHandle,
    recipient: usize,
    frame: &DriverWireFrame,
) -> DriverResult<()> {
    let payload = encode_driver_frame(frame)?;
    send_encoded_payload(transport, recipient, &payload)
}

pub(in crate::driver) fn send_encoded_payload(
    transport: &dyn TransportHandle,
    recipient: usize,
    payload: &[u8],
) -> DriverResult<()> {
    transport.send(recipient, payload)?;
    Ok(())
}

pub(in crate::driver) fn fanout_encoded_payload(
    transport: &dyn TransportHandle,
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

pub(in crate::driver) fn parse_addresses_json(payload: &str) -> DriverResult<Vec<(String, u16)>> {
    serde_json::from_str(payload).map_err(|err| DriverError::config(err.to_string()))
}

// ─── Pool fetch wiring ────────────────────────────────────────────────────

use honey_wire::format::{ChannelWire, MessageWire, ProtocolEnvelopeWire};

/// Decoded pool-fetch message extracted from a raw protocol-envelope wire payload.
#[derive(Debug, Clone)]
pub enum PoolFetchWire {
    Request {
        sender: u32,
        item_id: String,
        origin_round: u32,
        origin_sender: u32,
        roothash: Vec<u8>,
    },
    Response {
        sender: u32,
        item_id: String,
        payload: Vec<u8>,
    },
}

/// Decode a `DUMBO_POOL` message from a raw protocol-envelope wire payload.
pub fn decode_pool_fetch_from_wire(bytes: &[u8]) -> DriverResult<Option<PoolFetchWire>> {
    let Ok(wire) = decode_result::<ProtocolEnvelopeWire>(bytes) else {
        return Ok(None);
    };
    if !matches!(wire.channel, ChannelWire::DumboPool) {
        return Ok(None);
    }
    let sender = wire.sender;
    match wire.message {
        MessageWire::PoolFetchRequest {
            item_id,
            origin_round,
            origin_sender,
            roothash,
        } => Ok(Some(PoolFetchWire::Request {
            sender,
            item_id,
            origin_round,
            origin_sender,
            roothash,
        })),
        MessageWire::PoolFetchResponse { item_id, payload } => Ok(Some(PoolFetchWire::Response {
            sender,
            item_id,
            payload,
        })),
        _ => Err(DriverError::wire(
            "unexpected message type in DUMBO_POOL envelope",
        )),
    }
}

pub fn encode_pool_fetch_request_wire(
    sender: u32,
    round_id: u32,
    item_id: &str,
    origin_round: u32,
    origin_sender: u32,
    roothash: &[u8],
) -> DriverResult<Vec<u8>> {
    honey_wire::api::encode_result(&ProtocolEnvelopeWire {
        sender,
        round_id,
        channel: ChannelWire::DumboPool,
        instance_id: None,
        message: MessageWire::PoolFetchRequest {
            item_id: item_id.to_owned(),
            origin_round,
            origin_sender,
            roothash: roothash.to_vec(),
        },
    })
    .map_err(DriverError::wire)
}

pub fn encode_pool_fetch_response_wire(
    sender: u32,
    round_id: u32,
    item_id: &str,
    payload: &[u8],
) -> DriverResult<Vec<u8>> {
    honey_wire::api::encode_result(&ProtocolEnvelopeWire {
        sender,
        round_id,
        channel: ChannelWire::DumboPool,
        instance_id: None,
        message: MessageWire::PoolFetchResponse {
            item_id: item_id.to_owned(),
            payload: payload.to_vec(),
        },
    })
    .map_err(DriverError::wire)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_fetch_request_round_trip() {
        let encoded = encode_pool_fetch_request_wire(3, 7, "item-1", 4, 2, b"root")
            .expect("request should encode");
        let decoded = decode_pool_fetch_from_wire(&encoded)
            .expect("request should decode")
            .expect("request should be recognized");
        match decoded {
            PoolFetchWire::Request {
                sender,
                item_id,
                origin_round,
                origin_sender,
                roothash,
            } => {
                assert_eq!(sender, 3);
                assert_eq!(item_id, "item-1");
                assert_eq!(origin_round, 4);
                assert_eq!(origin_sender, 2);
                assert_eq!(roothash, b"root");
            }
            other => panic!("unexpected wire variant: {other:?}"),
        }
    }

    #[test]
    fn test_pool_fetch_response_round_trip() {
        let encoded =
            encode_pool_fetch_response_wire(5, 9, "item-2", b"payload").expect("encode response");
        let decoded = decode_pool_fetch_from_wire(&encoded)
            .expect("response should decode")
            .expect("response should be recognized");
        match decoded {
            PoolFetchWire::Response {
                sender,
                item_id,
                payload,
            } => {
                assert_eq!(sender, 5);
                assert_eq!(item_id, "item-2");
                assert_eq!(payload, b"payload");
            }
            other => panic!("unexpected wire variant: {other:?}"),
        }
    }
}
