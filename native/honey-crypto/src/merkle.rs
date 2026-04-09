use reed_solomon_erasure::galois_8::ReedSolomon;
use sha2::{Digest, Sha256};

use crate::crypto_error::CryptoError;

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

fn build_tree(leaf_hashes: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let n = leaf_hashes.len();
    let p = next_pow2(n);
    let mut nodes = vec![[0u8; 32]; 2 * p];

    for (i, h) in leaf_hashes.iter().enumerate() {
        nodes[p + i] = *h;
    }
    for i in n..p {
        nodes[p + i] = if n > 0 { leaf_hashes[n - 1] } else { [0u8; 32] };
    }
    for i in (1..p).rev() {
        nodes[i] = hash_internal(&nodes[2 * i], &nodes[2 * i + 1]);
    }
    nodes
}

/// Encode `data` into `n` shards (k data, n-k parity) and build a Merkle tree.
/// Uses PKCS#7 padding: the last byte indicates the number of padding bytes.
pub fn encode(data: &[u8], k: usize, n: usize) -> Result<MerkleResult, CryptoError> {
    let rs = reed_solomon(k, n)?;

    let shard_len = (data.len() + 1).div_ceil(k);
    let mut padded = data.to_vec();
    let pad_len = shard_len * k - data.len();
    padded.resize(shard_len * k, pad_len as u8);

    let mut shards: Vec<Vec<u8>> = (0..k)
        .map(|i| padded[i * shard_len..(i + 1) * shard_len].to_vec())
        .collect();
    for _ in 0..(n - k) {
        shards.push(vec![0u8; shard_len]);
    }

    rs.encode(&mut shards)
        .map_err(|e| CryptoError::ReedSolomonError(e.to_string()))?;

    let leaf_hashes: Vec<[u8; 32]> = shards.iter().map(|s| hash_leaf(s)).collect();

    let p = next_pow2(n);
    let nodes = build_tree(&leaf_hashes);
    let root = nodes[1];

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
            hash_internal(sib, &acc)
        } else {
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
        out.extend_from_slice(shard.as_ref().expect("data shard must be reconstructed"));
    }

    Ok(trim_padding(out, shard_len))
}

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
        let result = encode(data, 2, 4).expect("encode should succeed");
        assert_eq!(result.proofs.len(), 4);
        assert_eq!(result.shards.len(), 4);

        let available: Vec<_> = (0..4)
            .map(|i| (i, result.shards[i].clone(), result.proofs[i].clone()))
            .collect();
        let decoded = decode(&available, &result.root, 2, 4).expect("decode should succeed");
        assert!(decoded.starts_with(data));
    }

    #[test]
    fn test_proof_verification() {
        let data = b"merkle-test";
        let result = encode(data, 2, 4).expect("encode should succeed");

        for i in 0..4 {
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
        let result = encode(data, 2, 4).expect("encode should succeed");

        let mut tampered = result.shards[1].clone();
        tampered[0] ^= 0xFF;
        assert!(!verify_shard(&tampered, &result.proofs[1], &result.root));
    }
}
