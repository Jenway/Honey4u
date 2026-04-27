use crate::crypto_error::CryptoError;

use crate::bls::{g1::G1, g2::G2, pairing::verify_pairing_equality};
use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};

use super::keygen::{PartialSignature, SigPrivateKeyShare, SigPublicParams};

use crate::bls::interpolate::interpolate_at_zero;

const DST_SIG: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
static HASH_TO_G1_CACHE: LazyLock<RwLock<HashMap<Vec<u8>, G1>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

fn hashed_message(msg: &[u8]) -> G1 {
    if let Ok(cache) = HASH_TO_G1_CACHE.read()
        && let Some(value) = cache.get(msg)
    {
        return *value;
    }

    let hashed = G1::hash_to_g1(msg, DST_SIG);
    if let Ok(mut cache) = HASH_TO_G1_CACHE.write() {
        cache.entry(msg.to_vec()).or_insert(hashed);
    }
    hashed
}

/// Produce a partial BLS signature from a key share.
pub fn sign(share: &SigPrivateKeyShare, msg: &[u8]) -> PartialSignature {
    let h = G1::hash_to_g1(msg, DST_SIG);
    let sig = h.scalar_mult(&share.secret);
    PartialSignature {
        player_id: share.player_id,
        value: sig,
    }
}

/// Verify a single partial signature against the player's verification key.
pub fn verify_share(
    params: &SigPublicParams,
    partial_sig: &PartialSignature,
    msg: &[u8],
) -> Result<(), CryptoError> {
    let id = partial_sig.player_id;
    if id < 1 || id > params.total_players {
        return Err(CryptoError::InvalidArgument(format!(
            "player_id {id} out of range 1..={}",
            params.total_players
        )));
    }
    let ver_key = &params.verification_vector[id - 1];
    let h = hashed_message(msg);
    if !verify_pairing_equality(ver_key, &h, &G2::generator(), &partial_sig.value) {
        return Err(CryptoError::VerificationFailed);
    }
    Ok(())
}

/// Verify a combined threshold signature against the master verification key.
pub fn verify_combined(params: &SigPublicParams, sig: &G1, msg: &[u8]) -> Result<(), CryptoError> {
    let h = hashed_message(msg);
    if !verify_pairing_equality(&params.master_public_key, &h, &G2::generator(), sig) {
        return Err(CryptoError::VerificationFailed);
    }
    Ok(())
}

/// Combine k partial signatures via Lagrange interpolation and verify the result.
/// Returns the combined signature if verification succeeds.
pub fn combine_with_verify(
    params: &SigPublicParams,
    msg: &[u8],
    partial_sigs: &[PartialSignature],
) -> Result<G1, CryptoError> {
    // Verify each share first (also catches duplicate player_ids via verify_share checks)
    for ps in partial_sigs {
        verify_share(params, ps, msg)?;
    }

    if partial_sigs.len() != params.threshold {
        return Err(CryptoError::InsufficientShares {
            need: params.threshold,
            got: partial_sigs.len(),
        });
    }

    let share_pairs: Vec<(usize, G1)> = partial_sigs
        .iter()
        .map(|ps| (ps.player_id, ps.value))
        .collect();

    let combined = interpolate_at_zero(&share_pairs)?;

    verify_combined(params, &combined, msg)?;
    Ok(combined)
}

/// Combine shares that have already been individually verified by the caller.
/// Still verifies the final combined signature before returning it.
pub fn combine_trusted(
    params: &SigPublicParams,
    msg: &[u8],
    partial_sigs: &[PartialSignature],
) -> Result<G1, CryptoError> {
    if partial_sigs.len() != params.threshold {
        return Err(CryptoError::InsufficientShares {
            need: params.threshold,
            got: partial_sigs.len(),
        });
    }

    let mut seen = std::collections::HashSet::with_capacity(partial_sigs.len());
    let share_pairs: Vec<(usize, G1)> = partial_sigs
        .iter()
        .map(|ps| {
            if !seen.insert(ps.player_id) {
                return Err(CryptoError::InvalidArgument(format!(
                    "duplicate player_id {}",
                    ps.player_id
                )));
            }
            Ok((ps.player_id, ps.value))
        })
        .collect::<Result<_, _>>()?;

    let combined = interpolate_at_zero(&share_pairs)?;
    verify_combined(params, &combined, msg)?;
    Ok(combined)
}

#[cfg(test)]
mod tests {
    use super::super::keygen::{SigKeySet, generate_sig_keys};
    use super::*;

    struct Fixture {
        ks: SigKeySet,
        msg: Vec<u8>,
    }

    impl Fixture {
        fn new(n: usize, k: usize) -> Self {
            let ks = generate_sig_keys(n, k).unwrap();
            Fixture {
                ks,
                msg: b"HoneyBadger-GTest".to_vec(),
            }
        }
    }

    #[test]
    fn test_end_to_end() {
        let n = 10;
        let k = 5;
        let f = Fixture::new(n, k);
        let params = &f.ks.public_params;
        let shares = &f.ks.private_shares;

        let partials: Vec<_> = (0..k).map(|i| sign(&shares[i], &f.msg)).collect();

        for ps in &partials {
            verify_share(params, ps, &f.msg).unwrap();
        }

        combine_with_verify(params, &f.msg, &partials).unwrap();
    }

    #[test]
    fn test_not_enough_shares() {
        let f = Fixture::new(10, 5);
        let partials: Vec<_> = (0..2)
            .map(|i| sign(&f.ks.private_shares[i], &f.msg))
            .collect();
        assert!(combine_with_verify(&f.ks.public_params, &f.msg, &partials).is_err());
    }

    #[test]
    fn test_invalid_share_verification() {
        let f = Fixture::new(10, 5);
        let ps = sign(&f.ks.private_shares[0], &f.msg);
        let wrong_msg = b"WrongMessage";
        assert!(verify_share(&f.ks.public_params, &ps, wrong_msg).is_err());
    }

    #[test]
    fn test_duplicate_player_ids() {
        let f = Fixture::new(5, 3);
        let p1 = sign(&f.ks.private_shares[0], &f.msg);
        let p2 = sign(&f.ks.private_shares[0], &f.msg); // same player
        let p3 = sign(&f.ks.private_shares[1], &f.msg);
        let partials = vec![p1, p2, p3];
        assert!(combine_with_verify(&f.ks.public_params, &f.msg, &partials).is_err());
    }

    #[test]
    fn test_invalid_player_id() {
        let f = Fixture::new(5, 3);
        let mut ps = sign(&f.ks.private_shares[0], &f.msg);
        ps.player_id = 999;
        assert!(verify_share(&f.ks.public_params, &ps, &f.msg).is_err());
    }

    #[test]
    fn test_verify_combined() {
        let f = Fixture::new(5, 3);
        let partials: Vec<_> = (0..3)
            .map(|i| sign(&f.ks.private_shares[i], &f.msg))
            .collect();
        let combined = combine_with_verify(&f.ks.public_params, &f.msg, &partials).unwrap();

        verify_combined(&f.ks.public_params, &combined, &f.msg).unwrap();
        assert!(verify_combined(&f.ks.public_params, &combined, b"WrongMessage").is_err());
    }
}
