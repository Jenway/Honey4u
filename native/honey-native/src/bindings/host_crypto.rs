/// Coarse-grained key-generation entry points for the Python ACS host.
///
/// These functions generate all cryptographic material for an N-node cluster
/// and return it as a list of per-node JSON strings — one per node — so that
/// the Python host never needs to construct or hold native key objects.
///
/// The JSON schema mirrors the format expected by `build_crypto_params_from_json`
/// in `honey_acs/host_crypto.py`.
use honey_crypto::host_crypto::{
    generate_dumbo_crypto_payloads_json as generate_dumbo_crypto_payloads_json_rust,
    generate_hb_crypto_payloads_json as generate_hb_crypto_payloads_json_rust,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

// ---------------------------------------------------------------------------
// PyO3 functions
// ---------------------------------------------------------------------------

/// Generate per-node HoneyBadger crypto payloads as JSON strings.
///
/// Returns a `list[str]` of length `nodes`. Each element is a compact JSON
/// object containing ACS-host signature/ECDSA material plus the TPKE material
/// that the Rust HoneyBadger outer driver still consumes directly.
#[pyfunction]
pub fn generate_hb_crypto_payloads_json(
    py: Python<'_>,
    nodes: usize,
    faulty: usize,
) -> PyResult<Vec<String>> {
    py.detach(move || generate_hb_crypto_payloads_json_rust(nodes, faulty))
        .map_err(PyValueError::new_err)
}

/// Generate per-node Dumbo crypto payloads as JSON strings.
///
/// Returns a `list[str]` of length `nodes`. Each element is a compact JSON
/// object containing ACS-host signature/ECDSA material plus the TPKE material
/// that the Rust HoneyBadger outer driver still consumes directly.
#[pyfunction]
pub fn generate_dumbo_crypto_payloads_json(
    py: Python<'_>,
    nodes: usize,
    faulty: usize,
) -> PyResult<Vec<String>> {
    py.detach(move || generate_dumbo_crypto_payloads_json_rust(nodes, faulty))
        .map_err(PyValueError::new_err)
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_hb_crypto_payloads_json, m)?)?;
    m.add_function(wrap_pyfunction!(generate_dumbo_crypto_payloads_json, m)?)?;
    Ok(())
}
