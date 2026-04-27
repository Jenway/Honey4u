use honey_wire::api::decode_result;
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
pub fn decode_pool_fetch_from_wire(bytes: &[u8]) -> Result<Option<PoolFetchWire>, String> {
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
        _ => Err(String::from(
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
) -> Result<Vec<u8>, String> {
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
}

pub fn encode_pool_fetch_response_wire(
    sender: u32,
    round_id: u32,
    item_id: &str,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
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
