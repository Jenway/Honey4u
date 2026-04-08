//! PRBC (Provable Reliable Broadcast) proof serialization and validation.
//!
//! The serialization format is **byte-for-byte compatible** with the Python
//! implementation in `honey_acs.subprotocols.provable_reliable_broadcast`:
//!
//! ```text
//! [2B roothash_len BE][roothash]
//! [2B sigma_count BE]
//!   per sigma:
//!   [2B sender_id BE][4B sig_len BE][sig_bytes]
//! ```
//!
//! Proof validation digest: `b"prbc-ready|" + sid + b"|" + roothash`.
//! Threshold = `num_nodes - faulty`.

// ─── Data types ───────────────────────────────────────────────────────────

/// A PRBC delivery proof: root hash of the Merkle-coded payload + quorum of
/// ECDSA signatures from READY senders.
#[derive(Debug, Clone)]
pub struct PrbcProof {
    pub roothash: Vec<u8>,
    /// `(sender_id_0based, raw_64b_ecdsa_signature)` pairs.
    pub sigmas: Vec<(u32, Vec<u8>)>,
}

// ─── Serialization ────────────────────────────────────────────────────────

/// Encode a proof to the custom binary format used by Python.
/// Corresponds to Python `serialize_prbc_proof`.
pub fn serialize_prbc_proof(proof: &PrbcProof) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(proof.roothash.len() as u16).to_be_bytes());
    out.extend_from_slice(&proof.roothash);
    out.extend_from_slice(&(proof.sigmas.len() as u16).to_be_bytes());
    for (sender, sig) in &proof.sigmas {
        out.extend_from_slice(&(*sender as u16).to_be_bytes());
        out.extend_from_slice(&(sig.len() as u32).to_be_bytes());
        out.extend_from_slice(sig);
    }
    out
}

/// Decode a proof from the custom binary format used by Python.
/// Corresponds to Python `deserialize_prbc_proof`.
pub fn deserialize_prbc_proof(raw: &[u8]) -> Result<PrbcProof, String> {
    let mut pos = 0usize;

    macro_rules! read_u16 {
        () => {{
            if pos + 2 > raw.len() {
                return Err("truncated PRBC proof (u16)".into());
            }
            let v = u16::from_be_bytes([raw[pos], raw[pos + 1]]);
            pos += 2;
            v
        }};
    }
    macro_rules! read_u32 {
        () => {{
            if pos + 4 > raw.len() {
                return Err("truncated PRBC proof (u32)".into());
            }
            let v = u32::from_be_bytes([raw[pos], raw[pos + 1], raw[pos + 2], raw[pos + 3]]);
            pos += 4;
            v
        }};
    }
    macro_rules! read_slice {
        ($len:expr) => {{
            let len = $len as usize;
            if pos + len > raw.len() {
                return Err("truncated PRBC proof (slice)".into());
            }
            let s = raw[pos..pos + len].to_vec();
            pos += len;
            s
        }};
    }

    let root_len = read_u16!();
    let roothash = read_slice!(root_len);
    let count = read_u16!();
    let mut sigmas = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let sender = read_u16!() as u32;
        let sig_len = read_u32!();
        let sig = read_slice!(sig_len);
        sigmas.push((sender, sig));
    }

    if pos != raw.len() {
        return Err(format!(
            "PRBC proof has trailing bytes (pos={pos}, len={})",
            raw.len()
        ));
    }
    Ok(PrbcProof { roothash, sigmas })
}

// ─── Validation ───────────────────────────────────────────────────────────

/// Validate a PRBC delivery proof.
///
/// Corresponds to Python `validate_prbc_proof(sid, num_nodes, faulty, ecdsa_pks, proof)`.
///
/// `ecdsa_pks`: compressed 33-byte secp256k1 public keys, one per node (0-based).
pub fn validate_prbc_proof(
    sid: &str,
    num_nodes: usize,
    faulty: usize,
    ecdsa_pks: &[Vec<u8>],
    proof: &PrbcProof,
) -> bool {
    if ecdsa_pks.len() != num_nodes {
        return false;
    }

    // Convert public keys to fixed-size arrays
    let pks: Vec<[u8; 33]> = ecdsa_pks
        .iter()
        .filter_map(|pk| pk.as_slice().try_into().ok())
        .collect();
    if pks.len() != num_nodes {
        return false; // malformed key(s)
    }

    // Convert sigmas to (i32, [u8; 64]) expected by honey-native
    let sigmas_fixed: Vec<(i32, [u8; 64])> = proof
        .sigmas
        .iter()
        .filter_map(|(node_id, sig)| {
            let arr: [u8; 64] = sig.as_slice().try_into().ok()?;
            Some((*node_id as i32, arr))
        })
        .collect();

    // digest = b"prbc-ready|" + sid + b"|" + roothash
    let mut digest = b"prbc-ready|".to_vec();
    digest.extend_from_slice(sid.as_bytes());
    digest.push(b'|');
    digest.extend_from_slice(&proof.roothash);

    let threshold = num_nodes - faulty;
    honey_native::hb::ecdsa_verify_threshold_sigs(&pks, &digest, &sigmas_fixed, threshold)
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proof() -> PrbcProof {
        PrbcProof {
            roothash: vec![0xab; 32],
            sigmas: vec![(0, vec![0u8; 64]), (2, vec![1u8; 64])],
        }
    }

    #[test]
    fn test_serialize_deserialize_round_trip() {
        let proof = make_proof();
        let encoded = serialize_prbc_proof(&proof);
        let decoded = deserialize_prbc_proof(&encoded).expect("decode should succeed");
        assert_eq!(decoded.roothash, proof.roothash);
        assert_eq!(decoded.sigmas.len(), proof.sigmas.len());
        for ((id_a, sig_a), (id_b, sig_b)) in decoded.sigmas.iter().zip(proof.sigmas.iter()) {
            assert_eq!(id_a, id_b);
            assert_eq!(sig_a, sig_b);
        }
    }

    #[test]
    fn test_trailing_bytes_rejected() {
        let proof = make_proof();
        let mut encoded = serialize_prbc_proof(&proof);
        encoded.push(0xff); // append junk
        assert!(deserialize_prbc_proof(&encoded).is_err());
    }
}
