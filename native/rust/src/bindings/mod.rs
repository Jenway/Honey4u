use pyo3::prelude::*;

mod aes;
mod error;
mod key_storage;
mod merkle;
mod threshold_pke;
mod threshold_sig;

pub fn register_all(m: &Bound<'_, PyModule>) -> PyResult<()> {
    merkle::register(m)?;
    threshold_sig::register(m)?;
    threshold_pke::register(m)?;
    aes::register(m)?;
    key_storage::register(m)?;
    Ok(())
}
