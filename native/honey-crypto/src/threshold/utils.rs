use crate::bls::{fr::Fr, g1::G1, g2::G2};
use blst::{
    blst_bendian_from_scalar, blst_p1_compress, blst_p2, blst_p2_affine, blst_p2_compress,
    blst_p2_from_affine, blst_p2_uncompress, blst_scalar, blst_scalar_from_fr,
};
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::mem::MaybeUninit;

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

pub fn fr_to_bytes(value: &Fr) -> Vec<u8> {
    let mut bytes = [0u8; 32];
    unsafe {
        let mut scalar = MaybeUninit::<blst_scalar>::uninit();
        blst_scalar_from_fr(scalar.as_mut_ptr(), &value.inner);
        let scalar = scalar.assume_init();
        blst_bendian_from_scalar(bytes.as_mut_ptr(), &scalar);
    }
    bytes.to_vec()
}

pub fn fr_from_bytes(bytes: &[u8]) -> Result<Fr, String> {
    let arr: &[u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("expected 32 bytes for Fr, got {}", bytes.len()))?;
    Fr::from_scalar_bytes(arr).ok_or_else(|| "invalid Fr scalar bytes".into())
}

pub fn g1_from_bytes(bytes: &[u8]) -> Result<G1, String> {
    if bytes.len() != 48 {
        return Err(format!("expected 48 bytes for G1, got {}", bytes.len()));
    }
    unsafe {
        let mut p_affine = MaybeUninit::<blst::blst_p1_affine>::uninit();
        let res = blst::blst_p1_uncompress(p_affine.as_mut_ptr(), bytes.as_ptr());
        if res != blst::BLST_ERROR::BLST_SUCCESS {
            return Err("invalid G1 point bytes".into());
        }
        let p_affine = p_affine.assume_init();
        let mut inner = MaybeUninit::<blst::blst_p1>::uninit();
        blst::blst_p1_from_affine(inner.as_mut_ptr(), &p_affine);
        Ok(G1 {
            inner: inner.assume_init(),
        })
    }
}

pub fn g2_to_bytes(p: &G2) -> Vec<u8> {
    let mut compressed = [0u8; 96];
    unsafe {
        blst_p2_compress(compressed.as_mut_ptr(), &p.inner);
    }
    compressed.to_vec()
}

pub fn g2_from_bytes(bytes: &[u8]) -> Result<G2, String> {
    if bytes.len() != 96 {
        return Err(format!("expected 96 bytes for G2, got {}", bytes.len()));
    }

    unsafe {
        let mut p_affine = MaybeUninit::<blst_p2_affine>::uninit();
        let res = blst_p2_uncompress(p_affine.as_mut_ptr(), bytes.as_ptr());
        if res != blst::BLST_ERROR::BLST_SUCCESS {
            return Err("invalid G2 point bytes".into());
        }
        let p_affine = p_affine.assume_init();

        let mut inner = MaybeUninit::<blst_p2>::uninit();
        blst_p2_from_affine(inner.as_mut_ptr(), &p_affine);
        Ok(G2 {
            inner: inner.assume_init(),
        })
    }
}
