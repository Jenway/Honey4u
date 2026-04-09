use crate::wire::api::decode_result;
use crate::wire::format::{ChannelWire, MessageWire, ProtocolEnvelopeWire};

/// Decoded pool-fetch message extracted from a raw protocol-envelope wire payload.
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
    let wire: ProtocolEnvelopeWire = decode_result(bytes)?;
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
