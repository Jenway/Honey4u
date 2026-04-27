use super::g1::G1;
use super::g2::G2;
use blst::{
    blst_final_exp, blst_fp12, blst_fp12_is_one, blst_fp12_mul, blst_miller_loop, blst_p1_affine,
    blst_p1_cneg, blst_p1_to_affine,
};
use std::mem::MaybeUninit;

// ── Pairing ──────────────────────────────────────────────────────────────────

/// Check e(q1, p1) == e(q2, p2)  via  e(q1,p1) · e(−q2,p2) == 1.
pub fn verify_pairing_equality(q1: &G2, p1: &G1, q2: &G2, p2: &G1) -> bool {
    let p1_aff = p1.to_affine();
    let q1_aff = q1.to_affine();
    let q2_aff = q2.to_affine();

    // Negate p2
    let mut neg_p2_inner = p2.inner;
    unsafe { blst_p1_cneg(&mut neg_p2_inner, true) };
    let neg_p2_aff = unsafe {
        let mut aff = MaybeUninit::<blst_p1_affine>::uninit();
        blst_p1_to_affine(aff.as_mut_ptr(), &neg_p2_inner);
        aff.assume_init()
    };

    unsafe {
        let mut loop1 = MaybeUninit::<blst_fp12>::uninit();
        let mut loop2 = MaybeUninit::<blst_fp12>::uninit();
        blst_miller_loop(loop1.as_mut_ptr(), &q1_aff, &p1_aff);
        blst_miller_loop(loop2.as_mut_ptr(), &q2_aff, &neg_p2_aff);
        let loop1 = loop1.assume_init();
        let loop2 = loop2.assume_init();

        let mut product = MaybeUninit::<blst_fp12>::uninit();
        blst_fp12_mul(product.as_mut_ptr(), &loop1, &loop2);
        let product = product.assume_init();

        let mut result = MaybeUninit::<blst_fp12>::uninit();
        blst_final_exp(result.as_mut_ptr(), &product);
        let result = result.assume_init();
        blst_fp12_is_one(&result)
    }
}
