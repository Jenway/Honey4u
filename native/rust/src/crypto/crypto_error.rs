use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("AES error")]
    AesError,
    #[error("ECDSA error: {0}")]
    EcdsaError(String),
    #[error("Invalid key")]
    InvalidKey,
    #[error("Verification failed")]
    VerificationFailed,
    #[error("Invalid ciphertext")]
    InvalidCiphertext,
    #[error("Insufficient shares: need {need}, got {got}")]
    InsufficientShares { need: usize, got: usize },
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
    #[error("Blst error")]
    BlstError,
    #[error("Reed-Solomon error: {0}")]
    ReedSolomonError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
}
