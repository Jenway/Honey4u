use super::fr::Fr;
use blst::{
    BLST_ERROR, blst_hash_to_g2, blst_p2, blst_p2_affine, blst_p2_compress, blst_p2_from_affine,
    blst_p2_generator, blst_p2_is_equal, blst_p2_mult, blst_p2_to_affine, blst_p2_uncompress,
    blst_scalar, blst_scalar_from_fr,
};
use std::mem::MaybeUninit;
/// BLS12-381 field/group wrappers
///
/// G2: BLS12-381 G2 point (blst_p2, Jacobian coordinates)
// ── G2 ──────────────────────────────────────────────────────────────────────

/// A point on the BLS12-381 G2 curve (Jacobian coordinates).
#[repr(transparent)]
#[derive(Clone, Debug, Copy)]
pub struct G2 {
    pub(crate) inner: blst_p2,
}

impl G2 {
    pub fn generator() -> Self {
        unsafe {
            let p = blst_p2_generator();
            G2 { inner: *p }
        }
    }

    pub fn identity() -> Self {
        G2::generator().scalar_mult(&Fr::from_u64(0))
    }

    /// Multiply this point by an Fr scalar.

    #[inline]
    pub fn scalar_mult(mut self, s: &Fr) -> G2 {
        unsafe {
            let mut scalar = MaybeUninit::<blst_scalar>::uninit();
            blst_scalar_from_fr(scalar.as_mut_ptr(), &s.inner);
            let scalar = scalar.assume_init();
            // Fr order r is 255 bits
            const FR_BITS: usize = 255;
            blst_p2_mult(&mut self.inner, &self.inner, scalar.b.as_ptr(), FR_BITS);
        }
        self
    }

    pub fn hash_to_g2(msg: &[u8], dst: &[u8]) -> Self {
        unsafe {
            let mut p = MaybeUninit::<blst_p2>::uninit();
            blst_hash_to_g2(
                p.as_mut_ptr(),
                msg.as_ptr(),
                msg.len(),
                dst.as_ptr(),
                dst.len(),
                std::ptr::null(),
                0,
            );
            G2 {
                inner: p.assume_init(),
            }
        }
    }

    pub fn to_affine(&self) -> blst_p2_affine {
        unsafe {
            let mut aff = MaybeUninit::<blst_p2_affine>::uninit();
            blst_p2_to_affine(aff.as_mut_ptr(), &self.inner);
            aff.assume_init()
        }
    }

    pub fn to_compressed_bytes(&self) -> [u8; 96] {
        let mut bytes = [0u8; 96];
        unsafe {
            blst_p2_compress(bytes.as_mut_ptr(), &self.inner);
        }
        bytes
    }

    pub fn from_compressed_bytes(bytes: &[u8; 96]) -> Result<Self, String> {
        unsafe {
            let mut affine = MaybeUninit::<blst_p2_affine>::uninit();
            let err = blst_p2_uncompress(affine.as_mut_ptr(), bytes.as_ptr());
            if err != BLST_ERROR::BLST_SUCCESS {
                return Err("invalid compressed G2 point".into());
            }
            let affine = affine.assume_init();
            let mut inner = MaybeUninit::<blst_p2>::uninit();
            blst_p2_from_affine(inner.as_mut_ptr(), &affine);
            Ok(G2 {
                inner: inner.assume_init(),
            })
        }
    }
}

impl PartialEq for G2 {
    fn eq(&self, other: &Self) -> bool {
        unsafe { blst_p2_is_equal(&self.inner, &other.inner) }
    }
}
