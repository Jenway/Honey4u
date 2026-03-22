use super::fr::Fr;
use blst::{
    blst_hash_to_g2, blst_p2, blst_p2_add_or_double, blst_p2_affine, blst_p2_generator,
    blst_p2_is_equal, blst_p2_mult, blst_p2_to_affine, blst_scalar, blst_scalar_from_fr,
};
/// BLS12-381 field/group wrappers
///
/// G2: BLS12-381 G2 point (blst_p2, Jacobian coordinates)
// ── G2 ──────────────────────────────────────────────────────────────────────

/// A point on the BLS12-381 G2 curve (Jacobian coordinates).
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

    /// Multiply this point by an Fr scalar.

    #[inline]
    pub fn scalar_mult(mut self, s: &Fr) -> G2 {
        unsafe {
            let mut scalar = std::mem::zeroed::<blst_scalar>();
            blst_scalar_from_fr(&mut scalar, &s.inner);
            // Fr order r is 255 bits
            const FR_BITS: usize = 255;
            blst_p2_mult(&mut self.inner, &self.inner, scalar.b.as_ptr(), FR_BITS);
        }
        self
    }

    pub fn identity() -> Self {
        unsafe {
            G2 {
                inner: std::mem::zeroed(),
            }
        }
    }

    #[inline]
    pub fn add_assign(&mut self, other: &G2) {
        unsafe {
            blst_p2_add_or_double(&mut self.inner, &self.inner, &other.inner);
        }
    }

    pub fn hash_to_g2(msg: &[u8], dst: &[u8]) -> Self {
        unsafe {
            let mut p = std::mem::zeroed::<blst_p2>();
            blst_hash_to_g2(
                &mut p,
                msg.as_ptr(),
                msg.len(),
                dst.as_ptr(),
                dst.len(),
                std::ptr::null(),
                0,
            );
            G2 { inner: p }
        }
    }

    pub fn to_affine(&self) -> blst_p2_affine {
        unsafe {
            let mut aff = std::mem::zeroed::<blst_p2_affine>();
            blst_p2_to_affine(&mut aff, &self.inner);
            aff
        }
    }
}

impl PartialEq for G2 {
    fn eq(&self, other: &Self) -> bool {
        unsafe { blst_p2_is_equal(&self.inner, &other.inner) }
    }
}
