use crate::crypto::crypto_error::CryptoError;

use serde::{Deserialize, Serialize};

use crate::crypto::bls::{
    fr::Fr,
    g1::G1,
    g2::G2,
    poly::{poly_eval, random_poly},
};

// ── Types for Threshold Signatures (pk∈G2, sig∈G1) ──────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigPublicParams {
    pub total_players: usize,
    pub threshold: usize,
    /// Master public key: a₀·G2.
    pub master_public_key: G2,
    /// Per-player verification keys: share_i·G2.
    pub verification_vector: Vec<G2>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigKeySet {
    pub public_params: SigPublicParams,
    pub private_shares: Vec<SigPrivateKeyShare>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigPrivateKeyShare {
    pub player_id: usize,
    pub secret: Fr,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartialSignature {
    pub player_id: usize,
    pub value: G1,
}

// ── Types for Threshold PKE (mpk∈G1, ver_keys∈G2) ──────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PkePublicParams {
    pub total_players: usize,
    pub threshold: usize,
    /// Master public key: a₀·G1.
    pub master_public_key: G1,
    /// Per-player verification keys: share_i·G2.
    pub verification_vector: Vec<G2>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PkeKeySet {
    pub public_params: PkePublicParams,
    pub private_shares: Vec<PkePrivateKeyShare>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PkePrivateKeyShare {
    pub player_id: usize,
    pub secret: Fr,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ciphertext {
    pub u: G1,
    pub v: [u8; 32],
    pub w: G2,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartialDecryptionShare {
    pub player_id: usize,
    pub value: G1,
}

// ── Key generation (generic) ─────────────────────────────────────────────────

/// Generate key material for threshold signatures.
/// Master PK = a₀·G2, verification keys = poly(i)·G2.
pub fn generate_sig_keys(n: usize, k: usize) -> Result<SigKeySet, CryptoError> {
    if k < 1 || k > n {
        return Err(CryptoError::InvalidArgument("k must be 1..=n".into()));
    }
    let poly = random_poly(k);
    let master_secret = poly[0];
    let master_pk = G2::generator().scalar_mult(&master_secret);

    let mut private_shares = Vec::with_capacity(n);
    let mut verification_vector = Vec::with_capacity(n);

    for player_id in 1..=n {
        let x = Fr::from_u64(player_id as u64);
        let share_secret = poly_eval(&poly, &x);
        private_shares.push(SigPrivateKeyShare {
            player_id,
            secret: share_secret,
        });
        let ver_key = G2::generator().scalar_mult(&share_secret);
        verification_vector.push(ver_key);
    }

    Ok(SigKeySet {
        public_params: SigPublicParams {
            total_players: n,
            threshold: k,
            master_public_key: master_pk,
            verification_vector,
        },
        private_shares,
    })
}

/// Generate key material for threshold PKE.
/// Master PK = a₀·G1, verification keys = poly(i)·G2.
pub fn generate_pke_keys(n: usize, k: usize) -> Result<PkeKeySet, CryptoError> {
    if k < 1 || k > n {
        return Err(CryptoError::InvalidArgument("k must be 1..=n".into()));
    }
    let poly = random_poly(k);
    let master_secret = poly[0];
    let master_pk = G1::generator().scalar_mult(&master_secret);

    let mut private_shares = Vec::with_capacity(n);
    let mut verification_vector = Vec::with_capacity(n);

    for player_id in 1..=n {
        let x = Fr::from_u64(player_id as u64);
        let share_secret = poly_eval(&poly, &x);
        private_shares.push(PkePrivateKeyShare {
            player_id,
            secret: share_secret,
        });
        let ver_key = G2::generator().scalar_mult(&share_secret);
        verification_vector.push(ver_key);
    }

    Ok(PkeKeySet {
        public_params: PkePublicParams {
            total_players: n,
            threshold: k,
            master_public_key: master_pk,
            verification_vector,
        },
        private_shares,
    })
}

// ── Serialization support ────────────────────────────────────────────────────
