use crate::bls::{g1::G1, g2::G2};
use sha2::{Digest, Sha256};

pub fn hash_g(p: &G1) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(p.to_compressed_bytes());
    h.finalize().into()
}

pub fn hash_h(u: &G1, v: &[u8]) -> G2 {
    const DST: &[u8] = b"TPKE_HASH_H_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    let mut msg = Vec::with_capacity(48 + v.len());
    msg.extend_from_slice(&u.to_compressed_bytes());
    msg.extend_from_slice(v);
    G2::hash_to_g2(&msg, DST)
}
