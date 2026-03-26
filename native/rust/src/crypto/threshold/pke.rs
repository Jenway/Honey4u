use crate::crypto::crypto_error::CryptoError;

use super::{
    keygen::{Ciphertext, PartialDecryptionShare, PkePrivateKeyShare, PkePublicParams},
    utils::{hash_g, hash_h},
};
use crate::crypto::bls::{
    fr::Fr, g1::G1, g2::G2, interpolate::interpolate_at_zero, pairing::verify_pairing_equality,
};

/// Encrypt a 32-byte message under the master public key.
pub fn seal(mpk: &G1, msg: [u8; 32]) -> Ciphertext {
    let r = Fr::random();

    // U = r·G1
    let u = G1::generator().scalar_mult(&r);

    // mask = hashG(r·mpk)
    let mask_point = mpk.clone().scalar_mult(&r);
    let mask = hash_g(&mask_point);

    // V = msg ⊕ mask
    let mut v = [0u8; 32];
    for i in 0..32 {
        v[i] = msg[i] ^ mask[i];
    }

    // H = hashH(U, V), W = r·H
    let h = hash_h(&u, &v);
    let w = h.scalar_mult(&r);

    Ciphertext { u, v, w }
}

/// Verify that the ciphertext is well-formed: e(W, G1_gen) == e(H(U,V), U).
fn verify_encapsulation(ct: &Ciphertext) -> bool {
    let h = hash_h(&ct.u, &ct.v);
    // verify_pairing_equality(q1:G2, p1:G1, q2:G2, p2:G1)
    // e(w, G1_gen) == e(H(u,v), u)
    verify_pairing_equality(&ct.w, &G1::generator(), &h, &ct.u)
}

/// Verify a partial decryption share against the player's verification key.
pub fn verify_share(
    params: &PkePublicParams,
    share: &PartialDecryptionShare,
    ct: &Ciphertext,
) -> bool {
    let id = share.player_id;
    if id < 1 || id > params.total_players {
        return false;
    }
    let ver_key = &params.verification_vector[id - 1];
    // e(G2_gen, share_val) == e(ver_key, U)
    verify_pairing_equality(&G2::generator(), &share.value, ver_key, &ct.u)
}

/// Compute a partial decryption share for player i.
pub fn partial_open(
    share: &PkePrivateKeyShare,
    ct: &Ciphertext,
) -> Result<PartialDecryptionShare, CryptoError> {
    if !verify_encapsulation(ct) {
        return Err(CryptoError::InvalidCiphertext);
    }
    let value = ct.u.clone().scalar_mult(&share.secret);
    Ok(PartialDecryptionShare {
        player_id: share.player_id,
        value,
    })
}

/// Public API to verify ciphertext correctness.
pub fn verify_ciphertext(_params: &PkePublicParams, ct: &Ciphertext) -> Result<(), CryptoError> {
    if !verify_encapsulation(ct) {
        return Err(CryptoError::InvalidCiphertext);
    }
    Ok(())
}

/// Combine partial decryption shares to recover the plaintext.
pub fn open(
    params: &PkePublicParams,
    ct: &Ciphertext,
    shares: &[PartialDecryptionShare],
) -> Result<[u8; 32], CryptoError> {
    if shares.len() < params.threshold {
        return Err(CryptoError::InsufficientShares {
            need: params.threshold,
            got: shares.len(),
        });
    }

    for s in shares {
        if !verify_share(params, s, ct) {
            return Err(CryptoError::VerificationFailed);
        }
    }

    let pairs: Vec<(usize, G1)> = shares.iter().map(|s| (s.player_id, s.value)).collect();
    let recovered = interpolate_at_zero(&pairs)?;

    let mask = hash_g(&recovered);
    let mut msg = [0u8; 32];
    for i in 0..32 {
        msg[i] = ct.v[i] ^ mask[i];
    }
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::super::keygen::{PkeKeySet, generate_pke_keys};
    use super::*;

    fn make_msg(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        let bytes = s.as_bytes();
        let len = bytes.len().min(32);
        out[..len].copy_from_slice(&bytes[..len]);
        out
    }

    struct Fixture {
        ks: PkeKeySet,
    }

    impl Fixture {
        fn new(n: usize, k: usize) -> Self {
            let ks = generate_pke_keys(n, k).unwrap();
            Fixture { ks }
        }
    }

    #[test]
    fn test_seal_and_open_success() {
        let f = Fixture::new(5, 3);
        let msg = make_msg("HoneyBadger BFT is robust!");
        let ct = seal(&f.ks.public_params.master_public_key, msg);

        let shares: Vec<_> = [1usize, 3, 5]
            .iter()
            .map(|&id| partial_open(&f.ks.private_shares[id - 1], &ct).unwrap())
            .collect();

        let opened = open(&f.ks.public_params, &ct, &shares).unwrap();
        assert_eq!(opened, msg);
    }

    #[test]
    fn test_open_fails_invalid_share() {
        let f = Fixture::new(5, 3);
        let msg = make_msg("This should not decrypt");
        let ct = seal(&f.ks.public_params.master_public_key, msg);

        let mut shares: Vec<_> = [1usize, 2]
            .iter()
            .map(|&id| partial_open(&f.ks.private_shares[id - 1], &ct).unwrap())
            .collect();

        // Forge a bad share for player 3
        let bad = PartialDecryptionShare {
            player_id: 3,
            value: G1::generator(),
        };
        shares.push(bad);

        assert!(open(&f.ks.public_params, &ct, &shares).is_err());
    }

    #[test]
    fn test_open_fails_insufficient_shares() {
        let f = Fixture::new(5, 3);
        let msg = make_msg("Not enough shares");
        let ct = seal(&f.ks.public_params.master_public_key, msg);

        let shares: Vec<_> = [1usize, 2]
            .iter()
            .map(|&id| partial_open(&f.ks.private_shares[id - 1], &ct).unwrap())
            .collect();

        assert!(open(&f.ks.public_params, &ct, &shares).is_err());
    }

    #[test]
    fn test_open_fails_duplicate_player() {
        let f = Fixture::new(5, 3);
        let msg = make_msg("Duplicate share");
        let ct = seal(&f.ks.public_params.master_public_key, msg);

        let s = partial_open(&f.ks.private_shares[0], &ct).unwrap();
        let shares = vec![s.clone(), s.clone(), s];

        assert!(open(&f.ks.public_params, &ct, &shares).is_err());
    }
}
