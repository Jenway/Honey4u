use super::g1::G1;
use super::g2::G2;
use blst::{
    blst_final_exp, blst_fp12, blst_fp12_is_one, blst_fp12_mul, blst_miller_loop, blst_p1_affine,
    blst_p1_cneg, blst_p1_to_affine,
};

// ── Pairing ──────────────────────────────────────────────────────────────────

/// Check e(q1, p1) == e(q2, p2)  via  e(q1,p1) · e(−q2,p2) == 1.
pub fn verify_pairing_equality(q1: &G2, p1: &G1, q2: &G2, p2: &G1) -> bool {
    let p1_aff = p1.to_affine();
    let q1_aff = q1.to_affine();
    let q2_aff = q2.to_affine();

    // Negate p2
    let mut neg_p2_inner = p2.inner;
    unsafe { blst_p1_cneg(&mut neg_p2_inner, true) };
    let mut neg_p2_aff = unsafe { std::mem::zeroed::<blst_p1_affine>() };
    unsafe { blst_p1_to_affine(&mut neg_p2_aff, &neg_p2_inner) };

    unsafe {
        let mut loop1 = std::mem::zeroed::<blst_fp12>();
        let mut loop2 = std::mem::zeroed::<blst_fp12>();
        blst_miller_loop(&mut loop1, &q1_aff, &p1_aff);
        blst_miller_loop(&mut loop2, &q2_aff, &neg_p2_aff);
        let mut product = std::mem::zeroed::<blst_fp12>();
        blst_fp12_mul(&mut product, &loop1, &loop2);
        let mut result = std::mem::zeroed::<blst_fp12>();
        blst_final_exp(&mut result, &product);
        blst_fp12_is_one(&result)
    }
}
