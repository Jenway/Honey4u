use blst::{
    blst_fr, blst_fr_from_uint64, blst_fr_inverse, blst_fr_mul, blst_fr_sub, blst_p1_add_or_double,
    blst_p1_mult, blst_p2_add_or_double, blst_p2_mult, blst_scalar, blst_scalar_from_fr,
};

use crate::crypto::{bls::g1::G1, bls::g2::G2, crypto_error::CryptoError};

/// Marker trait for group elements that can be used in Lagrange interpolation.
pub trait GroupElement: Clone {
    fn identity() -> Self;
    fn add_assign(&mut self, other: &Self);
    fn scalar_mult(self, s: &blst_fr) -> Self;
}

/// Batch-invert a slice of Fr elements using the prefix-product trick.
fn batch_inverse(vec: &mut [blst_fr]) {
    let n = vec.len();
    if n == 0 {
        return;
    }
    unsafe {
        let mut prefix = vec![std::mem::zeroed::<blst_fr>(); n];
        prefix[0] = vec[0];
        for i in 1..n {
            blst_fr_mul(&mut prefix[i], &prefix[i - 1], &vec[i]);
        }

        let mut all_inv = std::mem::zeroed::<blst_fr>();
        blst_fr_inverse(&mut all_inv, &prefix[n - 1]);

        for i in (0..n).rev() {
            let cur = vec[i];
            if i > 0 {
                blst_fr_mul(&mut vec[i], &all_inv, &prefix[i - 1]);
            } else {
                vec[i] = all_inv;
            }
            blst_fr_mul(&mut all_inv, &all_inv, &cur);
        }
    }
}

/// Lagrange interpolation at x=0 over (player_id, group-element value) pairs.
pub fn interpolate_at_zero<G: GroupElement>(shares: &[(usize, G)]) -> Result<G, CryptoError> {
    let k = shares.len();
    if k == 0 {
        return Err(CryptoError::InvalidArgument("no shares provided".into()));
    }

    for i in 0..k {
        for j in 0..i {
            if shares[i].0 == shares[j].0 {
                return Err(CryptoError::InvalidArgument(
                    "duplicate player id in shares".into(),
                ));
            }
        }
    }

    unsafe {
        let mut xs = vec![std::mem::zeroed::<blst_fr>(); k];
        for i in 0..k {
            let limbs = [shares[i].0 as u64, 0, 0, 0];
            blst_fr_from_uint64(&mut xs[i], limbs.as_ptr());
        }

        // denominators[i] = Π_{j≠i}(x_i - x_j)
        let mut denominators = vec![std::mem::zeroed::<blst_fr>(); k];
        for i in 0..k {
            let limbs = [1u64, 0, 0, 0];
            blst_fr_from_uint64(&mut denominators[i], limbs.as_ptr());
            for j in 0..k {
                if i != j {
                    let mut tmp = std::mem::zeroed::<blst_fr>();
                    blst_fr_sub(&mut tmp, &xs[i], &xs[j]);
                    blst_fr_mul(&mut denominators[i], &denominators[i], &tmp);
                }
            }
        }
        batch_inverse(&mut denominators);

        let zero = std::mem::zeroed::<blst_fr>();
        let mut result = G::identity();
        for i in 0..k {
            // numerator_i = Π_{j≠i}(0 - x_j) = Π_{j≠i}(-x_j)
            let mut num = std::mem::zeroed::<blst_fr>();
            let limbs = [1u64, 0, 0, 0];
            blst_fr_from_uint64(&mut num, limbs.as_ptr());
            for j in 0..k {
                if i != j {
                    let mut tmp = std::mem::zeroed::<blst_fr>();
                    blst_fr_sub(&mut tmp, &zero, &xs[j]);
                    blst_fr_mul(&mut num, &num, &tmp);
                }
            }
            let mut lambda = std::mem::zeroed::<blst_fr>();
            blst_fr_mul(&mut lambda, &num, &denominators[i]);
            let term = shares[i].1.clone().scalar_mult(&lambda);
            result.add_assign(&term);
        }

        Ok(result)
    }
}

impl GroupElement for G1 {
    fn identity() -> Self {
        unsafe {
            G1 {
                inner: std::mem::zeroed(),
            }
        }
    }
    fn add_assign(&mut self, other: &Self) {
        unsafe {
            blst_p1_add_or_double(&mut self.inner, &self.inner, &other.inner);
        }
    }
    fn scalar_mult(mut self, s: &blst_fr) -> Self {
        unsafe {
            let mut scalar = std::mem::zeroed::<blst_scalar>();
            blst_scalar_from_fr(&mut scalar, s);
            blst_p1_mult(&mut self.inner, &self.inner, scalar.b.as_ptr(), 255);
        }
        self
    }
}

impl GroupElement for G2 {
    fn identity() -> Self {
        unsafe {
            G2 {
                inner: std::mem::zeroed(),
            }
        }
    }
    fn add_assign(&mut self, other: &Self) {
        unsafe {
            blst_p2_add_or_double(&mut self.inner, &self.inner, &other.inner);
        }
    }
    fn scalar_mult(mut self, s: &blst_fr) -> Self {
        unsafe {
            let mut scalar = std::mem::zeroed::<blst_scalar>();
            blst_scalar_from_fr(&mut scalar, s);
            blst_p2_mult(&mut self.inner, &self.inner, scalar.b.as_ptr(), 255);
        }
        self
    }
}
