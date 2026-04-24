/// BLS12-381 field/group wrappers
///
/// G1: BLS12-381 G1 point (blst_p1, Jacobian coordinates)
use super::fr::Fr;
use blst::blst_scalar;
use blst::{
    blst_hash_to_g1, blst_p1, blst_p1_affine, blst_p1_generator, blst_p1_is_equal, blst_p1_mult,
    blst_p1_to_affine, blst_scalar_from_fr,
};
use std::mem::MaybeUninit;
// ── G1 ──────────────────────────────────────────────────────────────────────

/// A point on the BLS12-381 G1 curve (Jacobian coordinates).
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct G1 {
    pub(crate) inner: blst_p1,
}

impl G1 {
    pub fn generator() -> Self {
        unsafe {
            let p = blst_p1_generator();
            G1 { inner: *p }
        }
    }

    pub fn identity() -> Self {
        G1::generator().scalar_mult(&Fr::from_u64(0))
    }

    /// Multiply this point by an Fr scalar.
    #[inline]
    pub fn scalar_mult(mut self, s: &Fr) -> G1 {
        unsafe {
            let mut scalar = MaybeUninit::<blst_scalar>::uninit();
            blst_scalar_from_fr(scalar.as_mut_ptr(), &s.inner);
            let scalar = scalar.assume_init();
            // Fr order r is 255 bits
            const FR_BITS: usize = 255;
            blst_p1_mult(&mut self.inner, &self.inner, scalar.b.as_ptr(), FR_BITS);
        }
        self
    }

    pub fn hash_to_g1(msg: &[u8], dst: &[u8]) -> Self {
        unsafe {
            let mut p = MaybeUninit::<blst_p1>::uninit();
            blst_hash_to_g1(
                p.as_mut_ptr(),
                msg.as_ptr(),
                msg.len(),
                dst.as_ptr(),
                dst.len(),
                std::ptr::null(),
                0,
            );
            G1 {
                inner: p.assume_init(),
            }
        }
    }

    pub fn to_affine(&self) -> blst_p1_affine {
        unsafe {
            let mut aff = MaybeUninit::<blst_p1_affine>::uninit();
            blst_p1_to_affine(aff.as_mut_ptr(), &self.inner);
            aff.assume_init()
        }
    }
}

impl PartialEq for G1 {
    fn eq(&self, other: &Self) -> bool {
        unsafe { blst_p1_is_equal(&self.inner, &other.inner) }
    }
}
