use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use crate::crypto;

#[pyfunction]
fn aes_encrypt(py: Python<'_>, key_bin: &[u8], plaintext: &[u8]) -> PyResult<Vec<u8>> {
    if key_bin.len() != 32 {
        return Err(PyValueError::new_err("AES key must be 32 bytes"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(key_bin);
    let plaintext = plaintext.to_vec();
    py.allow_threads(move || {
        crypto::aes::encrypt(&key, &plaintext).map_err(|e| PyValueError::new_err(e.to_string()))
    })
}

#[pyfunction]
fn aes_decrypt(py: Python<'_>, key_bin: &[u8], ciphertext: &[u8]) -> PyResult<Vec<u8>> {
    if key_bin.len() != 32 {
        return Err(PyValueError::new_err("AES key must be 32 bytes"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(key_bin);
    let ciphertext = ciphertext.to_vec();
    py.allow_threads(move || {
        crypto::aes::decrypt(&key, &ciphertext).map_err(|e| PyValueError::new_err(e.to_string()))
    })
}

// Binding definitions
#[pymodule]
pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(aes_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(aes_decrypt, m)?)?;
    Ok(())
}
