use crate::crypto::crypto_error::CryptoError;

use crate::crypto::bls::{g1::G1, pairing::core_verify_pk_in_g2};

use super::keygen::{PartialSignature, SigPrivateKeyShare, SigPublicParams};

use crate::crypto::bls::interpolate::interpolate_at_zero;

const DST_SIG: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

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
    if !core_verify_pk_in_g2(&partial_sig.value, ver_key, msg, DST_SIG) {
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

    if !core_verify_pk_in_g2(&combined, &params.master_public_key, msg, DST_SIG) {
        return Err(CryptoError::VerificationFailed);
    }
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
}
