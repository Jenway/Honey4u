use blst::{blst_fr, blst_fr_add, blst_fr_mul};

use crate::crypto::bls::fr::Fr;

/// Generate a Shamir secret-sharing polynomial of degree k-1 over Fr.
/// Returns (master_secret, coefficients), where coefficients[0] = master_secret.
pub fn random_poly(k: usize) -> Vec<Fr> {
    (0..k).map(|_| Fr::random()).collect()
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
            let mut tmp = std::mem::zeroed::<blst_fr>();
            blst_fr_mul(&mut tmp, &result.inner, &x.inner);
            blst_fr_add(&mut result.inner, &tmp, &c.inner);
        }
    }
    result
}
