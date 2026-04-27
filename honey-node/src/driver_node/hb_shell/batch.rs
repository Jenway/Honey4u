use super::super::error::{DriverError, DriverResult};
use std::collections::HashSet;

use honey_wire::api::{decode_result, encode_result};
use honey_wire::format::TxBatchWire;

pub(crate) fn encode_json_string(value: &str) -> DriverResult<Vec<u8>> {
    serde_json::to_vec(value).map_err(|err| DriverError::serialization(err.to_string()))
}

pub(crate) fn encode_tx_batch(items: Vec<Vec<u8>>) -> DriverResult<Vec<u8>> {
    encode_result(&TxBatchWire { items }).map_err(DriverError::serialization)
}

pub(crate) fn decode_tx_batch(payload: &[u8]) -> DriverResult<Vec<Vec<u8>>> {
    let wire: TxBatchWire = decode_result(payload).map_err(DriverError::serialization)?;
    Ok(wire.items)
}

pub(crate) fn merge_tx_batches_bytes(blocks: Vec<Vec<u8>>) -> DriverResult<Vec<u8>> {
    let mut ordered_results = Vec::new();
    let mut seen = HashSet::new();

    for payload in blocks {
        let wire: TxBatchWire = decode_result(&payload).map_err(DriverError::serialization)?;
        for raw_tx in wire.items {
            if seen.insert(raw_tx.clone()) {
                ordered_results.push(raw_tx);
            }
        }
    }

    encode_result(&TxBatchWire {
        items: ordered_results,
    })
    .map_err(DriverError::serialization)
}
