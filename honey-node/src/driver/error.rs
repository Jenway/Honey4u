use std::io;

pub(crate) type DriverResult<T> = Result<T, DriverError>;

#[derive(Debug, thiserror::Error)]
pub(crate) enum DriverError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("clock error: {0}")]
    Clock(String),
    #[error("transport error: {0}")]
    Transport(#[from] io::Error),
    #[error("wire error: {0}")]
    Wire(String),
    #[error("pool-fetch error: {0}")]
    PoolFetch(String),
    #[error(transparent)]
    ProposalResolution(#[from] crate::driver::mempool::fetch::ProposalResolutionError),
    #[error("ACS {operation} failed: {message}")]
    Acs {
        operation: &'static str,
        message: String,
    },
    #[error("HoneyBadger crypto error: {0}")]
    HoneyBadgerCrypto(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("driver invariant violated: {0}")]
    Invariant(String),
    #[error("driver round {round_id}: timed out after {timeout_seconds:.3}s while {stage}")]
    Timeout {
        round_id: usize,
        timeout_seconds: f64,
        stage: String,
    },
    #[error("output error: {0}")]
    Output(String),
}

impl DriverError {
    pub(in crate::driver) fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    pub(in crate::driver) fn clock(message: impl Into<String>) -> Self {
        Self::Clock(message.into())
    }

    pub(in crate::driver) fn wire(message: impl Into<String>) -> Self {
        Self::Wire(message.into())
    }

    pub(in crate::driver) fn pool_fetch(message: impl Into<String>) -> Self {
        Self::PoolFetch(message.into())
    }

    pub(in crate::driver) fn acs(operation: &'static str, message: impl Into<String>) -> Self {
        Self::Acs {
            operation,
            message: message.into(),
        }
    }

    pub(in crate::driver) fn honey_badger_crypto(message: impl Into<String>) -> Self {
        Self::HoneyBadgerCrypto(message.into())
    }

    pub(in crate::driver) fn serialization(message: impl Into<String>) -> Self {
        Self::Serialization(message.into())
    }

    pub(in crate::driver) fn invariant(message: impl Into<String>) -> Self {
        Self::Invariant(message.into())
    }

    pub(in crate::driver) fn output(message: impl Into<String>) -> Self {
        Self::Output(message.into())
    }
}
