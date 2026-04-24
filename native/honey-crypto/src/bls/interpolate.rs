use blst::{
    blst_fr, blst_fr_from_uint64, blst_fr_inverse, blst_fr_mul, blst_fr_sub, blst_p1_add_or_double,
    blst_p1_mult, blst_p2_add_or_double, blst_p2_mult, blst_scalar, blst_scalar_from_fr,
};
use std::mem::MaybeUninit;

use crate::{bls::g1::G1, bls::g2::G2, crypto_error::CryptoError};

/// Marker trait for group elements that can be used in Lagrange interpolation.
pub trait GroupElement: Clone {
    fn identity() -> Self;
    fn add_assign(&mut self, other: &Self);
    fn scalar_mult(self, s: &blst_fr) -> Self;
}

fn fr_from_u64(value: u64) -> blst_fr {
    unsafe {
        let mut fr = MaybeUninit::<blst_fr>::uninit();
        let limbs = [value, 0, 0, 0];
        blst_fr_from_uint64(fr.as_mut_ptr(), limbs.as_ptr());
        fr.assume_init()
    }
}

fn fr_mul(left: &blst_fr, right: &blst_fr) -> blst_fr {
    unsafe {
        let mut out = MaybeUninit::<blst_fr>::uninit();
        blst_fr_mul(out.as_mut_ptr(), left, right);
        out.assume_init()
    }
}

fn fr_sub(left: &blst_fr, right: &blst_fr) -> blst_fr {
    unsafe {
        let mut out = MaybeUninit::<blst_fr>::uninit();
        blst_fr_sub(out.as_mut_ptr(), left, right);
        out.assume_init()
    }
}

fn fr_inverse(value: &blst_fr) -> blst_fr {
    unsafe {
        let mut out = MaybeUninit::<blst_fr>::uninit();
        blst_fr_inverse(out.as_mut_ptr(), value);
        out.assume_init()
    }
}

fn scalar_from_fr(value: &blst_fr) -> blst_scalar {
    unsafe {
        let mut scalar = MaybeUninit::<blst_scalar>::uninit();
        blst_scalar_from_fr(scalar.as_mut_ptr(), value);
        scalar.assume_init()
    }
}

/// Batch-invert a slice of Fr elements using the prefix-product trick.
fn batch_inverse(vec: &mut [blst_fr]) {
    let n = vec.len();
    if n == 0 {
        return;
    }
    let mut prefix = vec![vec[0]; n];
    for i in 1..n {
        prefix[i] = fr_mul(&prefix[i - 1], &vec[i]);
    }

    let mut all_inv = fr_inverse(&prefix[n - 1]);

    for i in (0..n).rev() {
        let cur = vec[i];
        if i > 0 {
            vec[i] = fr_mul(&all_inv, &prefix[i - 1]);
        } else {
            vec[i] = all_inv;
        }
        all_inv = fr_mul(&all_inv, &cur);
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

    let xs = shares
        .iter()
        .map(|(player_id, _)| fr_from_u64(*player_id as u64))
        .collect::<Vec<_>>();

    // denominators[i] = Π_{j≠i}(x_i - x_j)
    let mut denominators = vec![fr_from_u64(1); k];
    for i in 0..k {
        for j in 0..k {
            if i != j {
                let tmp = fr_sub(&xs[i], &xs[j]);
                denominators[i] = fr_mul(&denominators[i], &tmp);
            }
        }
    }
    batch_inverse(&mut denominators);

    let zero = fr_from_u64(0);
    let mut result = G::identity();
    for i in 0..k {
        // numerator_i = Π_{j≠i}(0 - x_j) = Π_{j≠i}(-x_j)
        let mut num = fr_from_u64(1);
        for j in 0..k {
            if i != j {
                let tmp = fr_sub(&zero, &xs[j]);
                num = fr_mul(&num, &tmp);
            }
        }
        let lambda = fr_mul(&num, &denominators[i]);
        let term = shares[i].1.clone().scalar_mult(&lambda);
        result.add_assign(&term);
    }

    Ok(result)
}

impl GroupElement for G1 {
    fn identity() -> Self {
        G1::identity()
    }
    fn add_assign(&mut self, other: &Self) {
        unsafe {
            blst_p1_add_or_double(&mut self.inner, &self.inner, &other.inner);
        }
    }
    fn scalar_mult(mut self, s: &blst_fr) -> Self {
        unsafe {
            let scalar = scalar_from_fr(s);
            blst_p1_mult(&mut self.inner, &self.inner, scalar.b.as_ptr(), 255);
        }
        self
    }
}

impl GroupElement for G2 {
    fn identity() -> Self {
        G2::identity()
    }
    fn add_assign(&mut self, other: &Self) {
        unsafe {
            blst_p2_add_or_double(&mut self.inner, &self.inner, &other.inner);
        }
    }
    fn scalar_mult(mut self, s: &blst_fr) -> Self {
        unsafe {
            let scalar = scalar_from_fr(s);
            blst_p2_mult(&mut self.inner, &self.inner, scalar.b.as_ptr(), 255);
        }
        self
    }
}
