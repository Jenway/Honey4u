use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};

use crate::crypto::crypto_error::CryptoError;

/// Encrypts plaintext with AES-256-GCM.
/// Returns nonce (12 bytes) || ciphertext+tag.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::AesError)?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| CryptoError::AesError)?;
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypts ciphertext (nonce || ciphertext+tag) with AES-256-GCM.
pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < 12 {
        return Err(CryptoError::AesError);
    }
    let (nonce_bytes, ct) = data.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::AesError)?;
    let nonce = Nonce::from_slice(nonce_bytes.try_into().expect("nonce must be 12 bytes"));
    cipher.decrypt(nonce, ct).map_err(|_| CryptoError::AesError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"Some secret message to encrypt";
        let ciphertext = encrypt(&key, plaintext).unwrap();
        assert!(ciphertext.len() > plaintext.len());
        let decrypted = decrypt(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let plaintext = b"hello world";
        let ciphertext = encrypt(&key, plaintext).unwrap();
        assert!(decrypt(&wrong_key, &ciphertext).is_err());
    }

    #[test]
    fn test_decrypt_short_ciphertext_fails() {
        let key = [0u8; 32];
        assert!(decrypt(&key, &[0u8; 5]).is_err());
    }
}
