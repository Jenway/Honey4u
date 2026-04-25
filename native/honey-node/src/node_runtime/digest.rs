use crate::codec::hex_encode;
use sha2::{Digest, Sha256};

pub(crate) const GENESIS_CHAIN_DIGEST: [u8; 32] = [0; 32];

pub(crate) fn sha256_hex(payload: &[u8]) -> String {
    hex_encode(&Sha256::digest(payload))
}

pub(crate) fn compute_chain_digest(
    prev_digest: &[u8],
    round_id: usize,
    block_payload: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prev_digest);
    hasher.update((round_id as u64).to_be_bytes());
    hasher.update(block_payload);
    hasher.finalize().into()
}
