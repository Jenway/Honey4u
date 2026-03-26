use crate::crypto;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use rand::rngs::OsRng;

fn copy_fixed<const N: usize>(value: &[u8], label: &str) -> PyResult<[u8; N]> {
    value
        .try_into()
        .map_err(|_| PyValueError::new_err(format!("{label} must be {N} bytes")))
}

#[pyfunction]
fn ecdsa_generate_keys(players: usize) -> PyResult<(Vec<Vec<u8>>, Vec<Vec<u8>>)> {
    let mut public_keys = Vec::with_capacity(players);
    let mut private_keys = Vec::with_capacity(players);

    for _ in 0..players {
        let signing_key = k256::ecdsa::SigningKey::random(&mut OsRng);
        let priv_key = signing_key.to_bytes();
        let priv_bytes = priv_key.to_vec();
        let priv_fixed = copy_fixed::<32>(&priv_bytes, "private key")?;
        let pub_key = crypto::ecdsa::get_public_key(&priv_fixed)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;

        public_keys.push(pub_key.to_vec());
        private_keys.push(priv_bytes);
    }

    Ok((public_keys, private_keys))
}

#[pyfunction]
fn ecdsa_public_key_from_private(priv_key: &[u8]) -> PyResult<Vec<u8>> {
    let priv_fixed = copy_fixed::<32>(priv_key, "private key")?;
    let pub_key = crypto::ecdsa::get_public_key(&priv_fixed)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(pub_key.to_vec())
}

#[pyfunction]
fn ecdsa_sign(priv_key: &[u8], msg: &[u8]) -> PyResult<Vec<u8>> {
    let priv_fixed = copy_fixed::<32>(priv_key, "private key")?;
    let sig = crypto::ecdsa::sign(&priv_fixed, msg)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(sig.to_vec())
}

#[pyfunction]
fn ecdsa_verify(pub_key: &[u8], msg: &[u8], sig_bytes: &[u8]) -> PyResult<bool> {
    let pub_fixed = copy_fixed::<33>(pub_key, "public key")?;
    let sig_fixed = copy_fixed::<64>(sig_bytes, "signature")?;
    Ok(crypto::ecdsa::verify(&pub_fixed, msg, &sig_fixed))
}

#[pyfunction]
fn ecdsa_verify_threshold_sigs(
    pub_keys: Vec<Vec<u8>>,
    digest: &[u8],
    sigmas: Vec<(i32, Vec<u8>)>,
    threshold: usize,
) -> PyResult<bool> {
    let pub_keys_fixed = pub_keys
        .iter()
        .map(|pub_key| copy_fixed::<33>(pub_key, "public key"))
        .collect::<PyResult<Vec<_>>>()?;
    let sigmas_fixed = sigmas
        .iter()
        .map(|(node_id, sig)| Ok((*node_id, copy_fixed::<64>(sig, "signature")?)))
        .collect::<PyResult<Vec<_>>>()?;

    Ok(crypto::ecdsa::verify_threshold_sigs(
        &pub_keys_fixed,
        digest,
        &sigmas_fixed,
        threshold,
    ))
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(ecdsa_generate_keys, m)?)?;
    m.add_function(wrap_pyfunction!(ecdsa_public_key_from_private, m)?)?;
    m.add_function(wrap_pyfunction!(ecdsa_sign, m)?)?;
    m.add_function(wrap_pyfunction!(ecdsa_verify, m)?)?;
    m.add_function(wrap_pyfunction!(ecdsa_verify_threshold_sigs, m)?)?;
    Ok(())
}
