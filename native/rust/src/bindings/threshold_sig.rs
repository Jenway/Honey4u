use crate::crypto;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use crate::crypto::threshold::utils::{g1_from_bytes, g1_to_bytes};

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

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sig_generate_keys, m)?)?;
    m.add_class::<ThresholdSigner>()?;
    Ok(())
}
