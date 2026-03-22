use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

mod crypto;
mod key_storage;

impl From<crypto::crypto_error::CryptoError> for PyErr {
    fn from(err: crypto::crypto_error::CryptoError) -> Self {
        PyErr::new::<PyValueError, _>(err.to_string())
    }
}

use crypto::threshold::utils::{g1_from_bytes, g1_to_bytes};

/// Offline generation of threshold signature keys.
/// Returns the public params and a list of private secret shares as bytes.
#[pyfunction]
fn sig_generate_keys(players: usize, threshold: usize) -> PyResult<(Vec<u8>, Vec<Vec<u8>>)> {
    let keyset = crypto::threshold::keygen::generate_sig_keys(players, threshold)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;

    let params_bin = bincode::serialize(&keyset.public_params)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;

    let mut shares_bin = Vec::with_capacity(players);
    for share in keyset.private_shares {
        let share_bin =
            bincode::serialize(&share).map_err(|e| PyValueError::new_err(e.to_string()))?;
        shares_bin.push(share_bin);
    }

    Ok((params_bin, shares_bin))
}

/// A resident pointer to the node's threshold state.
/// Reads its private share and the common public parameters from memory.
#[pyclass]
pub struct ThresholdSigner {
    player_id: usize,
    public_params: crypto::threshold::keygen::SigPublicParams,
    private_share: crypto::threshold::keygen::SigPrivateKeyShare,
}

#[pymethods]
impl ThresholdSigner {
    #[new]
    fn new(player_id: usize, params_bin: &[u8], share_bin: &[u8]) -> PyResult<Self> {
        let public_params: crypto::threshold::keygen::SigPublicParams =
            bincode::deserialize(params_bin).map_err(|e| PyValueError::new_err(e.to_string()))?;

        let private_share: crypto::threshold::keygen::SigPrivateKeyShare =
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

    /// Sign a message using the resident private share. Returns serialized G1 bytes.
    fn sign(&self, msg: &[u8]) -> PyResult<Vec<u8>> {
        let partial = crypto::threshold::sig::sign(&self.private_share, msg);
        Ok(g1_to_bytes(&partial.value))
    }

    /// Verify another node's share signature.
    fn verify_share(&self, player_id: usize, sig_bytes: &[u8], msg: &[u8]) -> PyResult<bool> {
        let value = g1_from_bytes(sig_bytes).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let partial_sig = crypto::threshold::keygen::PartialSignature { player_id, value };
        Ok(crypto::threshold::sig::verify_share(&self.public_params, &partial_sig, msg).is_ok())
    }

    /// Combine multiple valid signature shares.
    /// `shares` is a list of tuples containing (player_id, signature_bytes).
    fn combine_shares(&self, shares: Vec<(usize, Vec<u8>)>, msg: &[u8]) -> PyResult<Vec<u8>> {
        let mut partial_sigs = Vec::with_capacity(shares.len());
        for (id, sig_bytes) in shares {
            let value =
                g1_from_bytes(&sig_bytes).map_err(|e| PyValueError::new_err(e.to_string()))?;
            partial_sigs.push(crypto::threshold::keygen::PartialSignature {
                player_id: id,
                value,
            });
        }

        match crypto::threshold::sig::combine_with_verify(&self.public_params, msg, &partial_sigs) {
            Ok(combined_sig) => Ok(g1_to_bytes(&combined_sig)),
            Err(e) => Err(e.into()),
        }
    }
}

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

// AES encryption/decryption functions
#[pyfunction]
fn aes_encrypt(key_bin: &[u8], plaintext: &[u8]) -> PyResult<Vec<u8>> {
    if key_bin.len() != 32 {
        return Err(PyValueError::new_err("AES key must be 32 bytes"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(key_bin);
    crypto::aes::encrypt(&key, plaintext).map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn aes_decrypt(key_bin: &[u8], ciphertext: &[u8]) -> PyResult<Vec<u8>> {
    if key_bin.len() != 32 {
        return Err(PyValueError::new_err("AES key must be 32 bytes"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(key_bin);
    crypto::aes::decrypt(&key, ciphertext).map_err(|e| PyValueError::new_err(e.to_string()))
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

// Binding definitions
#[pymodule]
fn honey_native(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sig_generate_keys, m)?)?;
    m.add_function(wrap_pyfunction!(pke_generate_keys, m)?)?;
    m.add_function(wrap_pyfunction!(pke_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(pke_verify_ciphertext, m)?)?;
    m.add_function(wrap_pyfunction!(pke_partial_open, m)?)?;
    m.add_function(wrap_pyfunction!(pke_open, m)?)?;
    m.add_function(wrap_pyfunction!(aes_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(aes_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(key_storage::save_sig_keys, m)?)?;
    m.add_function(wrap_pyfunction!(key_storage::save_pke_keys, m)?)?;
    m.add_function(wrap_pyfunction!(key_storage::load_sig_keys, m)?)?;
    m.add_function(wrap_pyfunction!(key_storage::load_pke_keys, m)?)?;
    m.add_class::<ThresholdSigner>()?;
    m.add_class::<ThresholdDecryptor>()?;
    Ok(())
}
