use crate::crypto::bls::{g1::G1, g2::G2};
use blst::{blst_p1_compress, blst_p1_to_affine};
use sha2::{Digest, Sha256};

pub fn hash_g(p: &G1) -> [u8; 32] {
    let mut compressed = [0u8; 48];
    unsafe {
        blst_p1_compress(compressed.as_mut_ptr(), &p.inner);
    }
    let mut h = Sha256::new();
    h.update(&compressed);
    h.finalize().into()
}

pub fn hash_h(u: &G1, v: &[u8]) -> G2 {
    const DST: &[u8] = b"TPKE_HASH_H_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    let mut compressed = [0u8; 48];
    unsafe {
        blst_p1_compress(compressed.as_mut_ptr(), &u.inner);
    }
    let mut msg = Vec::with_capacity(48 + v.len());
    msg.extend_from_slice(&compressed);
    msg.extend_from_slice(v);
    G2::hash_to_g2(&msg, DST)
}

pub fn g1_to_bytes(p: &G1) -> Vec<u8> {
    let mut compressed = [0u8; 48];
    unsafe {
        blst_p1_compress(compressed.as_mut_ptr(), &p.inner);
    }
    compressed.to_vec()
}

pub fn g1_from_bytes(bytes: &[u8]) -> Result<G1, String> {
    if bytes.len() != 48 {
        return Err(format!("expected 48 bytes for G1, got {}", bytes.len()));
    }
    let mut p = G1::identity();
    unsafe {
        let mut p_affine = std::mem::zeroed::<blst::blst_p1_affine>();
        blst_p1_to_affine(&mut p_affine, &p.inner);

        let res = blst::blst_p1_uncompress(&mut p_affine, bytes.as_ptr());
        if res != blst::BLST_ERROR::BLST_SUCCESS {
            return Err("invalid G1 point bytes".into());
        }
        blst::blst_p1_from_affine(&mut p.inner, &p_affine);
    }
    Ok(p)
}
