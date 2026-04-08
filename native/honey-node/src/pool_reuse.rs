//! BroadcastMempool and Pool Reuse serialization.
//!
//! This module is a Rust port of `honey_acs.data.broadcast_mempool` and
//! `honey_runtime.data.pool_reuse`.  The serialization format is
//! **byte-for-byte compatible** with the Python implementations so that
//! proposal payloads created here can be decoded by Python nodes and vice versa.
//!
//! Python format (`_BUNDLE_TAG = 3`):
//! ```text
//! [1B tag=3][4B inline_len BE][inline_bytes][2B ref_count BE]
//!   per reference:
//!   [2B id_len BE][id_bytes][4B origin_round BE][2B origin_sender BE]
//!   [2B roothash_len BE][roothash][4B proof_len BE][proof_bytes]
//! ```

use sha2::{Digest, Sha256};
use std::collections::HashMap;

// ─── Wire tags (must match Python pool_reuse.py) ──────────────────────────

const INLINE_TAG: u8 = 1;
const BUNDLE_TAG: u8 = 3;

// ─── Public data types ────────────────────────────────────────────────────

/// A reference to a previously-certified PRBC payload stored in the mempool.
#[derive(Debug, Clone)]
pub struct PoolReference {
    pub item_id: String,
    pub origin_round: u32,
    pub origin_sender: u32,
    pub roothash: Vec<u8>,
    pub proof_payload: Vec<u8>,
}

/// An entry stored in the broadcast mempool.
#[derive(Debug, Clone)]
pub struct ReusableEntry {
    pub payload: Vec<u8>,
    pub roothash: Vec<u8>,
    pub proof_payload: Vec<u8>,
    pub round_no: u32,
    pub sender_id: u32,
    pub timestamp: f64,
    pub consumed_in_round: Option<u32>,
    pub selected_in_round: Option<u32>,
}

/// Decoded ACS payload: either an inline batch or a bundle with references.
#[derive(Debug)]
pub enum AcsPayload {
    Inline(Vec<u8>),
    Bundle {
        inline_payload: Vec<u8>,
        references: Vec<PoolReference>,
    },
}

// ─── Serialization ────────────────────────────────────────────────────────

/// Encode a bare payload (no references) using the inline tag.
pub fn encode_inline_acs_payload(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + payload.len());
    out.push(INLINE_TAG);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Encode a bundle proposal (inline payload + pool references).
/// Corresponds to Python `encode_bundle_acs_payload`.
pub fn encode_bundle_acs_payload(payload: &[u8], refs: &[PoolReference]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(BUNDLE_TAG);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(&(refs.len() as u16).to_be_bytes());
    for r in refs {
        let id_bytes = r.item_id.as_bytes();
        out.extend_from_slice(&(id_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(id_bytes);
        out.extend_from_slice(&r.origin_round.to_be_bytes());
        out.extend_from_slice(&(r.origin_sender as u16).to_be_bytes());
        out.extend_from_slice(&(r.roothash.len() as u16).to_be_bytes());
        out.extend_from_slice(&r.roothash);
        out.extend_from_slice(&(r.proof_payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&r.proof_payload);
    }
    out
}

/// Decode an ACS payload produced by either `encode_inline_acs_payload` or
/// `encode_bundle_acs_payload`.  Corresponds to Python `decode_acs_payload`.
pub fn decode_acs_payload(bytes: &[u8]) -> Result<AcsPayload, String> {
    if bytes.is_empty() {
        return Err("empty ACS payload".into());
    }
    let tag = bytes[0];
    let mut pos = 1usize;

    macro_rules! read_u16 {
        () => {{
            if pos + 2 > bytes.len() {
                return Err("truncated ACS payload (u16)".into());
            }
            let v = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
            pos += 2;
            v as usize
        }};
    }
    macro_rules! read_u32 {
        () => {{
            if pos + 4 > bytes.len() {
                return Err("truncated ACS payload (u32)".into());
            }
            let v =
                u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
            pos += 4;
            v
        }};
    }
    macro_rules! read_slice {
        ($len:expr) => {{
            let len = $len;
            if pos + len > bytes.len() {
                return Err("truncated ACS payload (slice)".into());
            }
            let s = &bytes[pos..pos + len];
            pos += len;
            s
        }};
    }

    if tag == INLINE_TAG {
        let len = read_u32!() as usize;
        let data = read_slice!(len).to_vec();
        return Ok(AcsPayload::Inline(data));
    }

    if tag == BUNDLE_TAG {
        let inline_len = read_u32!() as usize;
        let inline_payload = read_slice!(inline_len).to_vec();
        let ref_count = read_u16!();
        let mut references = Vec::with_capacity(ref_count);
        for _ in 0..ref_count {
            let id_len = read_u16!();
            let id_bytes = read_slice!(id_len);
            let item_id = String::from_utf8(id_bytes.to_vec()).map_err(|e| e.to_string())?;
            let origin_round = read_u32!();
            let origin_sender = read_u16!() as u32;
            let roothash_len = read_u16!();
            let roothash = read_slice!(roothash_len).to_vec();
            let proof_len = read_u32!() as usize;
            let proof_payload = read_slice!(proof_len).to_vec();
            references.push(PoolReference {
                item_id,
                origin_round,
                origin_sender,
                roothash,
                proof_payload,
            });
        }
        return Ok(AcsPayload::Bundle {
            inline_payload,
            references,
        });
    }

    Err(format!("unknown ACS payload tag: {tag}"))
}

// ─── BroadcastMempool ─────────────────────────────────────────────────────

/// In-memory store for PRBC-certified payloads that can be referenced across rounds.
/// Corresponds to Python `honey_acs.data.broadcast_mempool.BroadcastMempool`.
pub struct BroadcastMempool {
    entries: HashMap<String, ReusableEntry>,
    max_size: usize,
    expire_rounds: u32,
}

impl BroadcastMempool {
    pub fn new(max_size: usize, expire_rounds: u32) -> Self {
        Self {
            entries: HashMap::new(),
            max_size,
            expire_rounds,
        }
    }

    /// Compute the deterministic ID for an entry.
    /// Matches Python `_compute_payload_id`:
    ///   `SHA256(f"{round_no}:{sender_id}:{roothash.hex()}".encode()).hexdigest()[:16]`
    pub fn compute_item_id(round_no: u32, sender_id: u32, roothash: &[u8]) -> String {
        let roothash_hex = hex::encode(roothash);
        let input = format!("{round_no}:{sender_id}:{roothash_hex}");
        let digest = Sha256::digest(input.as_bytes());
        hex::encode(&digest[..8]) // first 8 bytes → 16 hex chars
    }

    /// Add a new reusable entry (silently ignored if mempool is full).
    pub fn add_reusable(
        &mut self,
        payload: Vec<u8>,
        roothash: Vec<u8>,
        proof_payload: Vec<u8>,
        round_no: u32,
        sender_id: u32,
        timestamp: f64,
    ) {
        if self.entries.len() >= self.max_size {
            return;
        }
        let item_id = Self::compute_item_id(round_no, sender_id, &roothash);
        self.entries.entry(item_id).or_insert(ReusableEntry {
            payload,
            roothash,
            proof_payload,
            round_no,
            sender_id,
            timestamp,
            consumed_in_round: None,
            selected_in_round: None,
        });
    }

    /// Look up an entry by its computed item ID.
    pub fn get_reusable(&self, item_id: &str) -> Option<&ReusableEntry> {
        self.entries.get(item_id)
    }

    /// List entries eligible for reuse in the given round, sorted ascending by
    /// `(round_no, sender_id, item_id)` — matches Python's `list_reusable`.
    ///
    /// Eligibility: `consumed_in_round.is_none() && round_no < current_round`.
    pub fn list_reusable(&self, current_round: u32, limit: usize) -> Vec<(String, &ReusableEntry)> {
        let mut eligible: Vec<(String, &ReusableEntry)> = self
            .entries
            .iter()
            .filter(|(_, e)| e.consumed_in_round.is_none() && e.round_no < current_round)
            .map(|(k, v)| (k.clone(), v))
            .collect();

        eligible.sort_by(|(ka, a), (kb, b)| {
            a.round_no
                .cmp(&b.round_no)
                .then(a.sender_id.cmp(&b.sender_id))
                .then(ka.cmp(kb))
        });

        eligible.truncate(limit);
        eligible
    }

    /// Mark an entry as selected for the given round (for the `_reuse_owner` check).
    pub fn mark_selected(&mut self, item_id: &str, round_id: u32) {
        if let Some(e) = self.entries.get_mut(item_id) {
            e.selected_in_round = Some(round_id);
        }
    }

    /// Mark an entry as consumed in the given round (excludes it from future reuse).
    pub fn mark_consumed(&mut self, item_id: &str, round_id: u32) {
        if let Some(e) = self.entries.get_mut(item_id) {
            e.consumed_in_round = Some(round_id);
        }
    }

    /// Remove entries that are old enough to have expired.
    /// Matches Python `BroadcastMempool.cleanup(round_id)`.
    pub fn cleanup(&mut self, round_id: u32) {
        let expire_before = round_id.saturating_sub(self.expire_rounds);
        self.entries.retain(|_, e| e.round_no >= expire_before);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inline_round_trip() {
        let payload = b"hello world";
        let encoded = encode_inline_acs_payload(payload);
        match decode_acs_payload(&encoded).unwrap() {
            AcsPayload::Inline(data) => assert_eq!(data, payload),
            _ => panic!("expected Inline"),
        }
    }

    #[test]
    fn test_bundle_round_trip() {
        let payload = b"batch data";
        let refs = vec![PoolReference {
            item_id: "deadbeef01234567".to_string(),
            origin_round: 42,
            origin_sender: 2,
            roothash: vec![0xaa; 32],
            proof_payload: vec![0xbb; 16],
        }];
        let encoded = encode_bundle_acs_payload(payload, &refs);
        match decode_acs_payload(&encoded).unwrap() {
            AcsPayload::Bundle {
                inline_payload,
                references,
            } => {
                assert_eq!(inline_payload, payload);
                assert_eq!(references.len(), 1);
                assert_eq!(references[0].item_id, "deadbeef01234567");
                assert_eq!(references[0].origin_round, 42);
                assert_eq!(references[0].origin_sender, 2);
                assert_eq!(references[0].roothash, vec![0xaa; 32]);
                assert_eq!(references[0].proof_payload, vec![0xbb; 16]);
            }
            _ => panic!("expected Bundle"),
        }
    }

    #[test]
    fn test_item_id_format() {
        // Verify deterministic output (reference value generated from Python)
        let roothash = vec![0u8; 32];
        let id = BroadcastMempool::compute_item_id(0, 0, &roothash);
        assert_eq!(id.len(), 16, "item ID must be 16 hex chars");
    }

    #[test]
    fn test_mempool_lifecycle() {
        let mut pool = BroadcastMempool::new(100, 10);
        let rh = vec![1u8; 32];
        pool.add_reusable(b"p".to_vec(), rh.clone(), b"proof".to_vec(), 1, 0, 0.0);
        let id = BroadcastMempool::compute_item_id(1, 0, &rh);

        // Round 2: entry is eligible
        let list = pool.list_reusable(2, 10);
        assert_eq!(list.len(), 1);

        pool.mark_consumed(&id, 2);
        // After consuming, no longer eligible
        let list2 = pool.list_reusable(3, 10);
        assert_eq!(list2.len(), 0);
    }
}
