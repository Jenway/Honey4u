use reed_solomon_erasure::galois_8::ReedSolomon;
use sha2::{Digest, Sha256};

use crate::crypto::crypto_error::CryptoError;

/// Sibling hash on the path from leaf to root.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MerkleProof {
    pub leaf_index: usize,
    pub siblings: Vec<[u8; 32]>,
}

/// Result of encoding data with RS + building the Merkle tree.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MerkleResult {
    pub root: [u8; 32],
    /// All shards (data + parity), each shard is a Vec<u8> of equal length.
    pub shards: Vec<Vec<u8>>,
    pub proofs: Vec<MerkleProof>,
}

type ShardBundle = (usize, Vec<u8>, MerkleProof);

// --- Hashing helpers ---

fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(data);
    h.finalize().into()
}

fn hash_internal(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Next power of two >= n (minimum 1).
fn next_pow2(n: usize) -> usize {
    if n <= 1 {
        return 1;
    }
    let mut p = 1usize;
    while p < n {
        p <<= 1;
    }
    p
}

fn reed_solomon(k: usize, n: usize) -> Result<ReedSolomon, CryptoError> {
    if k < 1 || k > n || n < 1 {
        return Err(CryptoError::InvalidArgument("k must be 1..=n".into()));
    }

    ReedSolomon::new(k, n - k).map_err(|e| CryptoError::ReedSolomonError(e.to_string()))
}

/// Build a Merkle tree over `leaf_hashes` (padded to next power of two).
/// Returns a 1-indexed node array of size 2*P.
fn build_tree(leaf_hashes: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let n = leaf_hashes.len();
    let p = next_pow2(n);
    let mut nodes = vec![[0u8; 32]; 2 * p];

    // Fill leaf positions [p .. p+n)
    for (i, h) in leaf_hashes.iter().enumerate() {
        nodes[p + i] = *h;
    }
    // Pad with last leaf hash if n < p
    for i in n..p {
        nodes[p + i] = if n > 0 { leaf_hashes[n - 1] } else { [0u8; 32] };
    }
    // Build internal nodes bottom-up
    for i in (1..p).rev() {
        nodes[i] = hash_internal(&nodes[2 * i], &nodes[2 * i + 1]);
    }
    nodes
}

/// Encode `data` into `n` shards (k data, n-k parity) and build a Merkle tree.
/// Uses PKCS#7 padding: the last byte indicates the number of padding bytes.
pub fn encode(data: &[u8], k: usize, n: usize) -> Result<MerkleResult, CryptoError> {
    let rs = reed_solomon(k, n)?;

    // Reserve at least one padding byte so decode never mistakes a real tail byte for PKCS#7.
    let shard_len = (data.len() + 1 + k - 1) / k;
    let mut padded = data.to_vec();
    let pad_len = shard_len * k - data.len();
    padded.resize(shard_len * k, pad_len as u8);

    // Build shards: k data shards + parity (empty initially)
    let mut shards: Vec<Vec<u8>> = (0..k)
        .map(|i| padded[i * shard_len..(i + 1) * shard_len].to_vec())
        .collect();
    for _ in 0..(n - k) {
        shards.push(vec![0u8; shard_len]);
    }

    rs.encode(&mut shards)
        .map_err(|e| CryptoError::ReedSolomonError(e.to_string()))?;

    // Compute leaf hashes
    let leaf_hashes: Vec<[u8; 32]> = shards.iter().map(|s| hash_leaf(s)).collect();

    let p = next_pow2(n);
    let nodes = build_tree(&leaf_hashes);
    let root = nodes[1];

    // Build proofs
    let proofs: Vec<MerkleProof> = (0..n)
        .map(|i| {
            let mut siblings = Vec::new();
            let mut t = i + p;
            while t > 1 {
                let sib = t ^ 1;
                siblings.push(nodes[sib]);
                t >>= 1;
            }
            MerkleProof {
                leaf_index: i,
                siblings,
            }
        })
        .collect();

    Ok(MerkleResult {
        root,
        shards,
        proofs,
    })
}

/// Verify a Merkle proof for a shard.
pub fn verify_shard(shard: &[u8], proof: &MerkleProof, root: &[u8; 32]) -> bool {
    let mut acc = hash_leaf(shard);
    let mut idx = proof.leaf_index;
    for sib in &proof.siblings {
        acc = if (idx & 1) != 0 {
            // odd = right child, sibling is to the left
            hash_internal(sib, &acc)
        } else {
            // even = left child, sibling is to the right
            hash_internal(&acc, sib)
        };
        idx >>= 1;
    }
    acc == *root
}

fn trim_padding(mut out: Vec<u8>, shard_len: usize) -> Vec<u8> {
    if !out.is_empty() {
        let pad_len = out[out.len() - 1] as usize;
        if pad_len > 0 && pad_len <= shard_len {
            let data_len = out.len() - pad_len;
            let mut valid_padding = true;
            for byte in &out[data_len..] {
                if *byte != pad_len as u8 {
                    valid_padding = false;
                    break;
                }
            }
            if valid_padding {
                out.truncate(data_len);
            }
        }
    }
    out
}

fn decode_impl(
    available: Vec<ShardBundle>,
    root: &[u8; 32],
    k: usize,
    n: usize,
    verify: bool,
) -> Result<Vec<u8>, CryptoError> {
    if verify {
        for (_idx, shard, proof) in &available {
            if !verify_shard(shard, proof, root) {
                return Err(CryptoError::VerificationFailed);
            }
        }
    }

    if available.len() < k {
        return Err(CryptoError::InsufficientShares {
            need: k,
            got: available.len(),
        });
    }

    let rs = reed_solomon(k, n)?;
    let shard_len = available.first().map(|(_, s, _)| s.len()).unwrap_or(0);

    let mut shards: Vec<Option<Vec<u8>>> = vec![None; n];
    for (idx, shard, _) in available {
        shards[idx] = Some(shard);
    }

    rs.reconstruct_data(&mut shards)
        .map_err(|e| CryptoError::ReedSolomonError(e.to_string()))?;

    let mut out = Vec::with_capacity(k * shard_len);
    for shard in shards.iter().take(k) {
        out.extend_from_slice(shard.as_ref().unwrap());
    }

    Ok(trim_padding(out, shard_len))
}

/// Decode data from a subset of shards (with their indices) that pass Merkle verification.
/// `available`: list of (shard_index, shard_data, proof).
/// Removes PKCS#7 padding from the result.
#[allow(dead_code)]
pub fn decode(
    available: &[(usize, Vec<u8>, MerkleProof)],
    root: &[u8; 32],
    k: usize,
    n: usize,
) -> Result<Vec<u8>, CryptoError> {
    decode_impl(available.to_vec(), root, k, n, true)
}

pub fn decode_owned(
    available: Vec<ShardBundle>,
    root: &[u8; 32],
    k: usize,
    n: usize,
) -> Result<Vec<u8>, CryptoError> {
    decode_impl(available, root, k, n, true)
}

pub fn decode_trusted_owned(
    available: Vec<ShardBundle>,
    root: &[u8; 32],
    k: usize,
    n: usize,
) -> Result<Vec<u8>, CryptoError> {
    decode_impl(available, root, k, n, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let data = b"merkle-test";
        let k = 2;
        let n = 4;
        let result = encode(data, k, n).unwrap();
        assert_eq!(result.proofs.len(), n);
        assert_eq!(result.shards.len(), n);

        let available: Vec<_> = (0..n)
            .map(|i| (i, result.shards[i].clone(), result.proofs[i].clone()))
            .collect();
        let decoded = decode(&available, &result.root, k, n).unwrap();
        assert!(decoded.starts_with(data));
    }

    #[test]
    fn test_proof_verification() {
        let data = b"merkle-test";
        let k = 2;
        let n = 4;
        let result = encode(data, k, n).unwrap();

        for i in 0..n {
            assert!(verify_shard(
                &result.shards[i],
                &result.proofs[i],
                &result.root
            ));
        }
    }

    #[test]
    fn test_detect_tampering() {
        let data = b"tamper-test";
        let k = 2;
        let n = 4;
        let result = encode(data, k, n).unwrap();

        let mut tampered = result.shards[1].clone();
        tampered[0] ^= 0xFF;
        assert!(!verify_shard(&tampered, &result.proofs[1], &result.root));
    }

    #[test]
    fn test_decode_with_minimum_shards() {
        let data = b"reconstruct from minimum shards";
        let k = 3;
        let n = 6;
        let result = encode(data, k, n).unwrap();

        let available = vec![
            (0, result.shards[0].clone(), result.proofs[0].clone()),
            (2, result.shards[2].clone(), result.proofs[2].clone()),
            (4, result.shards[4].clone(), result.proofs[4].clone()),
        ];
        let decoded = decode(&available, &result.root, k, n).unwrap();
        assert!(decoded.starts_with(data));
    }

    #[test]
    fn test_decode_tampered_shard_fails() {
        let data = b"should fail";
        let k = 2;
        let n = 4;
        let result = encode(data, k, n).unwrap();

        let mut tampered = result.shards[0].clone();
        tampered[0] ^= 0xFF;
        let available = vec![
            (0, tampered, result.proofs[0].clone()),
            (1, result.shards[1].clone(), result.proofs[1].clone()),
        ];
        assert!(decode(&available, &result.root, k, n).is_err());
    }

    #[test]
    fn test_roundtrip_when_payload_len_is_divisible_by_k() {
        let data = vec![0xAB; 364];
        let k = 4;
        let n = 10;
        let result = encode(&data, k, n).unwrap();

        let available: Vec<_> = (0..k)
            .map(|i| (i, result.shards[i].clone(), result.proofs[i].clone()))
            .collect();
        let decoded = decode(&available, &result.root, k, n).unwrap();

        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_trusted_owned_matches_verified_decode() {
        let data = b"trusted-path";
        let k = 4;
        let n = 10;
        let result = encode(data, k, n).unwrap();

        let available: Vec<_> = (0..k)
            .map(|i| (i, result.shards[i].clone(), result.proofs[i].clone()))
            .collect();
        let trusted = decode_trusted_owned(available.clone(), &result.root, k, n).unwrap();
        let verified = decode_owned(available, &result.root, k, n).unwrap();

        assert_eq!(trusted, verified);
        assert_eq!(trusted, data);
    }
}
