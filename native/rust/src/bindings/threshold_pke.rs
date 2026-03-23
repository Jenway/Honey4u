use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use crate::crypto;

/// Offline generation of threshold PKE keys.
/// Returns the public params, full public key, and a list of private secret shares as bytes.
#[pyfunction]
fn pke_generate_keys(
    players: usize,
    threshold: usize,
) -> PyResult<(Vec<u8>, Vec<u8>, Vec<Vec<u8>>)> {
    let keyset = crypto::threshold::keygen::generate_pke_keys(players, threshold)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;

    let params_bin = bincode::serialize(&keyset.public_params)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;

    let pk_bin = bincode::serialize(&keyset.public_params.master_public_key)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;

    let mut shares_bin = Vec::with_capacity(players);
    for share in keyset.private_shares {
        let share_bin =
            bincode::serialize(&share).map_err(|e| PyValueError::new_err(e.to_string()))?;
        shares_bin.push(share_bin);
    }

    Ok((params_bin, pk_bin, shares_bin))
}

#[pyfunction]
fn pke_encrypt(pk_bin: &[u8], msg: &[u8]) -> PyResult<Vec<u8>> {
    if msg.len() != 32 {
        return Err(PyValueError::new_err(
            "Message must be exactly 32 bytes for PKE",
        ));
    }
    let mut msg_arr = [0u8; 32];
    msg_arr.copy_from_slice(msg);

    let pk: crypto::bls::g1::G1 =
        bincode::deserialize(pk_bin).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let ct = crypto::threshold::pke::seal(&pk, msg_arr);
    bincode::serialize(&ct).map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pyclass]
pub struct ThresholdDecryptor {
    player_id: usize,
    public_params: crypto::threshold::keygen::PkePublicParams,
    private_share: crypto::threshold::keygen::PkePrivateKeyShare,
}

#[pymethods]
impl ThresholdDecryptor {
    #[new]
    fn new(player_id: usize, params_bin: &[u8], share_bin: &[u8]) -> PyResult<Self> {
        let public_params: crypto::threshold::keygen::PkePublicParams =
            bincode::deserialize(params_bin).map_err(|e| PyValueError::new_err(e.to_string()))?;

        let private_share: crypto::threshold::keygen::PkePrivateKeyShare =
            bincode::deserialize(share_bin).map_err(|e| PyValueError::new_err(e.to_string()))?;

        Ok(Self {
            player_id,
            public_params,
            private_share,
        })
    }

    #[getter]
    fn player_id(&self) -> usize {
        self.player_id
    }

    fn decrypt_share(&self, ct_bin: &[u8]) -> PyResult<Vec<u8>> {
        let ct: crypto::threshold::keygen::Ciphertext =
            bincode::deserialize(ct_bin).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let share = crypto::threshold::pke::partial_open(&self.private_share, &ct)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        bincode::serialize(&share).map_err(|e| PyValueError::new_err(e.to_string()))
    }

    fn verify_share(&self, _player_id: usize, ct_bin: &[u8], share_bin: &[u8]) -> PyResult<bool> {
        let ct: crypto::threshold::keygen::Ciphertext =
            bincode::deserialize(ct_bin).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let share: crypto::threshold::keygen::PartialDecryptionShare =
            bincode::deserialize(share_bin).map_err(|e| PyValueError::new_err(e.to_string()))?;

        Ok(crypto::threshold::pke::verify_share(
            &self.public_params,
            &share,
            &ct,
        ))
    }

    fn combine_shares(&self, ct_bin: &[u8], shares_bin: Vec<Vec<u8>>) -> PyResult<Vec<u8>> {
        let ct: crypto::threshold::keygen::Ciphertext =
            bincode::deserialize(ct_bin).map_err(|e| PyValueError::new_err(e.to_string()))?;

        let mut shares = Vec::with_capacity(shares_bin.len());
        for share_bin in shares_bin {
            let share: crypto::threshold::keygen::PartialDecryptionShare =
                bincode::deserialize(&share_bin)
                    .map_err(|e| PyValueError::new_err(e.to_string()))?;
            shares.push(share);
        }

        let msg = crypto::threshold::pke::open(&self.public_params, &ct, &shares)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(msg.to_vec())
    }
}

// PKE helper functions
#[pyfunction]
fn pke_verify_ciphertext(params_bin: &[u8], ct_bin: &[u8]) -> PyResult<bool> {
    let params: crypto::threshold::keygen::PkePublicParams =
        bincode::deserialize(params_bin).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let ct: crypto::threshold::keygen::Ciphertext =
        bincode::deserialize(ct_bin).map_err(|e| PyValueError::new_err(e.to_string()))?;

    match crypto::threshold::pke::verify_ciphertext(&params, &ct) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[pyfunction]
fn pke_partial_open(share_bin: &[u8], ct_bin: &[u8]) -> PyResult<Vec<u8>> {
    let share: crypto::threshold::keygen::PkePrivateKeyShare =
        bincode::deserialize(share_bin).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let ct: crypto::threshold::keygen::Ciphertext =
        bincode::deserialize(ct_bin).map_err(|e| PyValueError::new_err(e.to_string()))?;

    let partial_share = crypto::threshold::pke::partial_open(&share, &ct)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    bincode::serialize(&partial_share).map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn pke_open(params_bin: &[u8], ct_bin: &[u8], shares_bin: Vec<Vec<u8>>) -> PyResult<Vec<u8>> {
    let params: crypto::threshold::keygen::PkePublicParams =
        bincode::deserialize(params_bin).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let ct: crypto::threshold::keygen::Ciphertext =
        bincode::deserialize(ct_bin).map_err(|e| PyValueError::new_err(e.to_string()))?;

    let mut shares = Vec::with_capacity(shares_bin.len());
    for share_bin in shares_bin {
        let share: crypto::threshold::keygen::PartialDecryptionShare =
            bincode::deserialize(&share_bin).map_err(|e| PyValueError::new_err(e.to_string()))?;
        shares.push(share);
    }

    let msg = crypto::threshold::pke::open(&params, &ct, &shares)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(msg.to_vec())
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(pke_generate_keys, m)?)?;
    m.add_function(wrap_pyfunction!(pke_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(pke_verify_ciphertext, m)?)?;
    m.add_function(wrap_pyfunction!(pke_partial_open, m)?)?;
    m.add_function(wrap_pyfunction!(pke_open, m)?)?;
    m.add_class::<ThresholdDecryptor>()?;
    Ok(())
}
