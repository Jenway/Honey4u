/// BLS12-381 field/group wrappers
///
/// G1: BLS12-381 G1 point (blst_p1, Jacobian coordinates)
use super::fr::Fr;
use blst::blst_scalar;
use blst::{
    blst_hash_to_g1, blst_p1, blst_p1_affine, blst_p1_generator, blst_p1_is_equal, blst_p1_mult,
    blst_p1_to_affine, blst_scalar_from_fr,
};
// ── G1 ──────────────────────────────────────────────────────────────────────

/// A point on the BLS12-381 G1 curve (Jacobian coordinates).
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
        unsafe {
            G1 {
                inner: std::mem::zeroed(),
            }
        }
    }

    /// Multiply this point by an Fr scalar.
    #[inline]
    pub fn scalar_mult(mut self, s: &Fr) -> G1 {
        unsafe {
            let mut scalar = std::mem::zeroed::<blst_scalar>();
            blst_scalar_from_fr(&mut scalar, &s.inner);
            // Fr order r is 255 bits
            const FR_BITS: usize = 255;
            blst_p1_mult(&mut self.inner, &self.inner, scalar.b.as_ptr(), FR_BITS);
        }
        self
    }

    pub fn hash_to_g1(msg: &[u8], dst: &[u8]) -> Self {
        let mut p = unsafe { std::mem::zeroed::<blst_p1>() };
        unsafe {
            blst_hash_to_g1(
                &mut p,
                msg.as_ptr(),
                msg.len(),
                dst.as_ptr(),
                dst.len(),
                std::ptr::null(),
                0,
            );
        }
        G1 { inner: p }
    }

    pub fn to_affine(&self) -> blst_p1_affine {
        let mut aff = unsafe { std::mem::zeroed::<blst_p1_affine>() };
        unsafe { blst_p1_to_affine(&mut aff, &self.inner) };
        aff
    }
}

impl PartialEq for G1 {
    fn eq(&self, other: &Self) -> bool {
        unsafe { blst_p1_is_equal(&self.inner, &other.inner) }
    }
}
