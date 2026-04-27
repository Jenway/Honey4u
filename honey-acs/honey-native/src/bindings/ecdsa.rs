use std::collections::HashSet;

use honey_crypto::ecdsa;
use k256::elliptic_curve::rand_core::OsRng;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

fn copy_fixed<const N: usize>(value: &[u8], label: &str) -> PyResult<[u8; N]> {
    value
        .try_into()
        .map_err(|_| PyValueError::new_err(format!("{label} must be {N} bytes")))
}

#[pyfunction]
fn ecdsa_generate_keys(py: Python<'_>, players: usize) -> PyResult<(Vec<Vec<u8>>, Vec<Vec<u8>>)> {
    py.detach(move || {
        let mut public_keys = Vec::with_capacity(players);
        let mut private_keys = Vec::with_capacity(players);

        for _ in 0..players {
            let signing_key = k256::ecdsa::SigningKey::random(&mut OsRng);
            let priv_key = signing_key.to_bytes();
            let priv_bytes = priv_key.to_vec();
            let priv_fixed = copy_fixed::<32>(&priv_bytes, "private key")?;
            let pub_key = ecdsa::get_public_key(&priv_fixed)
                .map_err(|e| PyValueError::new_err(e.to_string()))?;

            public_keys.push(pub_key.to_vec());
            private_keys.push(priv_bytes);
        }

        Ok((public_keys, private_keys))
    })
}

#[pyfunction]
fn ecdsa_public_key_from_private(py: Python<'_>, priv_key: &[u8]) -> PyResult<Vec<u8>> {
    let priv_fixed = copy_fixed::<32>(priv_key, "private key")?;
    py.detach(move || {
        let pub_key =
            ecdsa::get_public_key(&priv_fixed).map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(pub_key.to_vec())
    })
}

#[pyfunction]
fn ecdsa_sign(py: Python<'_>, priv_key: &[u8], msg: &[u8]) -> PyResult<Vec<u8>> {
    let priv_fixed = copy_fixed::<32>(priv_key, "private key")?;
    let msg = msg.to_vec();
    py.detach(move || {
        let sig =
            ecdsa::sign(&priv_fixed, &msg).map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(sig.to_vec())
    })
}

#[pyfunction]
fn ecdsa_verify(py: Python<'_>, pub_key: &[u8], msg: &[u8], sig_bytes: &[u8]) -> PyResult<bool> {
    let pub_fixed = copy_fixed::<33>(pub_key, "public key")?;
    let sig_fixed = copy_fixed::<64>(sig_bytes, "signature")?;
    let msg = msg.to_vec();
    py.detach(move || Ok(ecdsa::verify(&pub_fixed, &msg, &sig_fixed)))
}

#[pyfunction]
fn ecdsa_verify_threshold_sigs(
    py: Python<'_>,
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

    let digest = digest.to_vec();
    py.detach(move || {
        Ok(ecdsa::verify_threshold_sigs(
            &pub_keys_fixed,
            &digest,
            &sigmas_fixed,
            threshold,
        ))
    })
}

/// PRBC (Provable Reliable Broadcast) crypto runtime, exposed to Python.
/// Holds all nodes' public keys and the local node's optional private key.
/// Encapsulates the dedup/bounds validation for `verify_ready_proof`.
#[pyclass]
pub struct PrbcCryptoRuntime {
    public_keys: Vec<Vec<u8>>,
    private_key: Option<Vec<u8>>,
}

#[pymethods]
impl PrbcCryptoRuntime {
    #[new]
    #[pyo3(signature = (public_keys, private_key = None))]
    fn new(public_keys: Vec<Vec<u8>>, private_key: Option<Vec<u8>>) -> Self {
        Self {
            public_keys,
            private_key,
        }
    }

    #[getter]
    fn players(&self) -> usize {
        self.public_keys.len()
    }

    /// Sign `digest` with this node's ECDSA private key.
    fn sign_ready(&self, py: Python<'_>, digest: &[u8]) -> PyResult<Vec<u8>> {
        let priv_bytes = self
            .private_key
            .as_ref()
            .ok_or_else(|| PyValueError::new_err("PRBC ECDSA private key is not configured"))?;
        let priv_fixed = copy_fixed::<32>(priv_bytes, "private key")?;
        let digest = digest.to_vec();
        py.detach(move || {
            let sig = ecdsa::sign(&priv_fixed, &digest)
                .map_err(|e| PyValueError::new_err(e.to_string()))?;
            Ok(sig.to_vec())
        })
    }

    /// Verify a single ECDSA signature from `player_id` over `digest`.
    fn verify_ready_signature(
        &self,
        py: Python<'_>,
        player_id: usize,
        signature: &[u8],
        digest: &[u8],
    ) -> PyResult<bool> {
        if player_id >= self.public_keys.len() {
            return Ok(false);
        }
        let pub_fixed = copy_fixed::<33>(&self.public_keys[player_id], "public key")?;
        let sig_fixed = copy_fixed::<64>(signature, "signature")?;
        let digest = digest.to_vec();
        py.detach(move || Ok(ecdsa::verify(&pub_fixed, &digest, &sig_fixed)))
    }

    /// Verify a threshold proof: `sigmas` is a sequence of `(player_id, signature)` pairs.
    ///
    /// Validates that:
    ///   - enough signatures are provided (`len >= threshold`)
    ///   - all player_ids are in-bounds
    ///   - no player_id is duplicated
    /// Then delegates to the ECDSA multi-sig verifier.
    fn verify_ready_proof(
        &self,
        py: Python<'_>,
        digest: &[u8],
        sigmas: Vec<(usize, Vec<u8>)>,
        threshold: usize,
    ) -> PyResult<bool> {
        if sigmas.len() < threshold {
            return Ok(false);
        }
        let pub_keys_len = self.public_keys.len();
        let mut seen: HashSet<usize> = HashSet::new();
        for (player_id, _) in &sigmas {
            if *player_id >= pub_keys_len || !seen.insert(*player_id) {
                return Ok(false);
            }
        }
        let pub_keys_fixed = self
            .public_keys
            .iter()
            .map(|pk| copy_fixed::<33>(pk, "public key"))
            .collect::<PyResult<Vec<_>>>()?;
        let sigmas_fixed = sigmas
            .iter()
            .map(|(node_id, sig)| Ok((*node_id as i32, copy_fixed::<64>(sig, "signature")?)))
            .collect::<PyResult<Vec<_>>>()?;
        let digest = digest.to_vec();
        py.detach(move || {
            Ok(ecdsa::verify_threshold_sigs(
                &pub_keys_fixed,
                &digest,
                &sigmas_fixed,
                threshold,
            ))
        })
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(ecdsa_generate_keys, m)?)?;
    m.add_function(wrap_pyfunction!(ecdsa_public_key_from_private, m)?)?;
    m.add_function(wrap_pyfunction!(ecdsa_sign, m)?)?;
    m.add_function(wrap_pyfunction!(ecdsa_verify, m)?)?;
    m.add_function(wrap_pyfunction!(ecdsa_verify_threshold_sigs, m)?)?;
    m.add_class::<PrbcCryptoRuntime>()?;
    Ok(())
}
