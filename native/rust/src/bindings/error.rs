use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use crate::crypto;

impl From<crypto::crypto_error::CryptoError> for PyErr {
    fn from(err: crypto::crypto_error::CryptoError) -> Self {
        PyErr::new::<PyValueError, _>(err.to_string())
    }
}
