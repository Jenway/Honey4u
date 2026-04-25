use pyo3::prelude::*;

mod ecdsa;
mod merkle;
mod threshold_sig;

pub fn register_all(m: &Bound<'_, PyModule>) -> PyResult<()> {
    merkle::register(m)?;
    threshold_sig::register(m)?;
    ecdsa::register(m)?;
    Ok(())
}
