use blst::{blst_fr, blst_fr_add, blst_fr_mul};
use std::mem::MaybeUninit;

use crate::bls::fr::Fr;
use rand::rand_core::{CryptoRng, Rng};

/// Generate a Shamir secret-sharing polynomial of degree k-1 over Fr.
/// Returns (master_secret, coefficients), where coefficients[0] = master_secret.
pub fn random_poly<R: Rng + CryptoRng>(k: usize, rng: &mut R) -> Vec<Fr> {
    (0..k).map(|_| Fr::random(rng)).collect()
}
/// Evaluate a polynomial at x using Horner's method.
/// coeffs[0] is the constant term.
pub fn poly_eval(coeffs: &[Fr], x: &Fr) -> Fr {
    if coeffs.is_empty() {
        return Fr::from_u64(0);
    }
    let mut result = coeffs[coeffs.len() - 1];
    for c in coeffs[..coeffs.len() - 1].iter().rev() {
        // result = result.mul(x).add(c);
        unsafe {
            let mut tmp = MaybeUninit::<blst_fr>::uninit();
            blst_fr_mul(tmp.as_mut_ptr(), &result.inner, &x.inner);
            let tmp = tmp.assume_init();
            blst_fr_add(&mut result.inner, &tmp, &c.inner);
        }
    }
    result
}
