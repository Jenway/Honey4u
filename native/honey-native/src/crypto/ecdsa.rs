use k256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
#[allow(unused_imports)]
use k256::elliptic_curve::sec1::ToEncodedPoint;

use crate::crypto::crypto_error::CryptoError;

/// Signs `msg` (SHA-256 hash is computed internally) with the given private key.
/// Returns compact 64-byte signature (r || s).
pub fn sign(priv_key: &[u8; 32], msg: &[u8]) -> Result<[u8; 64], CryptoError> {
    let signing_key = SigningKey::from_bytes(priv_key.into())
        .map_err(|e| CryptoError::EcdsaError(e.to_string()))?;
    let sig: Signature = signing_key.sign(msg);
    Ok(sig.to_bytes().into())
}

/// Returns compressed 33-byte public key for the given private key.
pub fn get_public_key(priv_key: &[u8; 32]) -> Result<[u8; 33], CryptoError> {
    let signing_key = SigningKey::from_bytes(priv_key.into())
        .map_err(|e| CryptoError::EcdsaError(e.to_string()))?;
    let verifying_key = signing_key.verifying_key();
    let encoded = verifying_key.to_encoded_point(true);
    let bytes = encoded.as_bytes();
    let mut out = [0u8; 33];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// Verifies a compact 64-byte signature against the compressed 33-byte public key.
pub fn verify(pub_key: &[u8; 33], msg: &[u8], sig_bytes: &[u8; 64]) -> bool {
    let verifying_key = match VerifyingKey::from_sec1_bytes(pub_key) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = match Signature::from_bytes(sig_bytes.into()) {
        Ok(s) => s,
        Err(_) => return false,
    };
    verifying_key.verify(msg, &sig).is_ok()
}

/// Verify that `sigmas` contains at least `threshold` distinct valid ECDSA
/// signatures over `digest`.  Each entry is `(node_id, sig)`.
///
/// This is the shared primitive behind CBC-validate, PRBC-proof-validate,
/// PB-proof-verify, PCBC-proof-verify, and SPBC sigma checks.
pub fn verify_threshold_sigs(
    pub_keys: &[[u8; 33]],
    digest: &[u8],
    sigmas: &[(i32, [u8; 64])],
    threshold: usize,
) -> bool {
    if sigmas.len() < threshold {
        return false;
    }
    let mut seen = std::collections::HashSet::new();
    let mut valid = 0usize;
    for (nid, sig) in sigmas {
        if *nid < 0 || (*nid as usize) >= pub_keys.len() {
            continue;
        }
        if !seen.insert(*nid) {
            continue;
        }
        if verify(&pub_keys[*nid as usize], digest, sig) {
            valid += 1;
        }
    }
    valid >= threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIV_KEY: [u8; 32] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x77, 0x88,
    ];

    #[test]
    fn test_sign_and_verify() {
        let msg = b"this is a test message for signing";
        let pub_key = get_public_key(&PRIV_KEY).unwrap();
        let sig = sign(&PRIV_KEY, msg).unwrap();
        assert!(verify(&pub_key, msg, &sig));
    }

    #[test]
    fn test_verify_wrong_pub_key() {
        let msg = b"this is a test message for signing";
        let mut wrong_key = PRIV_KEY;
        wrong_key[0] ^= 0xFF;
        let wrong_pub = get_public_key(&wrong_key).unwrap();
        let sig = sign(&PRIV_KEY, msg).unwrap();
        assert!(!verify(&wrong_pub, msg, &sig));
    }

    #[test]
    fn test_verify_wrong_message() {
        let msg = b"this is a test message for signing";
        let wrong_msg = b"this is a test message for signing!";
        let pub_key = get_public_key(&PRIV_KEY).unwrap();
        let sig = sign(&PRIV_KEY, msg).unwrap();
        assert!(!verify(&pub_key, wrong_msg, &sig));
    }

    #[test]
    fn test_verify_tampered_sig() {
        let msg = b"this is a test message for signing";
        let pub_key = get_public_key(&PRIV_KEY).unwrap();
        let mut sig = sign(&PRIV_KEY, msg).unwrap();
        sig[10] ^= 0xFF;
        assert!(!verify(&pub_key, msg, &sig));
    }

    #[test]
    fn test_invalid_private_key() {
        let zero_key = [0u8; 32];
        assert!(sign(&zero_key, b"test").is_err());
        assert!(get_public_key(&zero_key).is_err());
    }
}
