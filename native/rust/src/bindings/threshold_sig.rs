use crate::crypto;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use crate::archive::api as archive_api;
use crate::archive::crypto_wire::{SigPrivateKeyShareWire, SigPublicParamsWire};
use crate::crypto::threshold::utils::{g1_from_bytes, g1_to_bytes};

#[pyclass(from_py_object)]
#[derive(Clone)]
pub struct SigPublicKey {
    inner: crypto::threshold::keygen::SigPublicParams,
}

#[pymethods]
impl SigPublicKey {
    #[getter]
    fn players(&self) -> usize {
        self.inner.total_players
    }

    #[getter]
    fn threshold(&self) -> usize {
        self.inner.threshold
    }

    fn verify_share(
        &self,
        py: Python<'_>,
        player_id: usize,
        sig_bytes: &[u8],
        msg: &[u8],
    ) -> PyResult<bool> {
        let value = match g1_from_bytes(sig_bytes) {
            Ok(value) => value,
            Err(_) => return Ok(false),
        };
        let partial_sig = crypto::threshold::keygen::PartialSignature {
            player_id: player_id + 1,
            value,
        };
        let msg = msg.to_vec();
        py.detach(move || {
            Ok(crypto::threshold::sig::verify_share(&self.inner, &partial_sig, &msg).is_ok())
        })
    }

    fn verify_combined(&self, py: Python<'_>, sig_bytes: &[u8], msg: &[u8]) -> PyResult<bool> {
        let sig = match g1_from_bytes(sig_bytes) {
            Ok(value) => value,
            Err(_) => return Ok(false),
        };
        let msg = msg.to_vec();
        py.detach(move || {
            Ok(crypto::threshold::sig::verify_combined(&self.inner, &sig, &msg).is_ok())
        })
    }

    fn combine_shares(
        &self,
        py: Python<'_>,
        shares: Vec<(usize, Vec<u8>)>,
        msg: &[u8],
    ) -> PyResult<Vec<u8>> {
        let mut partial_sigs = Vec::with_capacity(shares.len());
        for (player_id, sig_bytes) in shares {
            let value =
                g1_from_bytes(&sig_bytes).map_err(|e| PyValueError::new_err(e.to_string()))?;
            partial_sigs.push(crypto::threshold::keygen::PartialSignature {
                player_id: player_id + 1,
                value,
            });
        }

        let msg = msg.to_vec();
        py.detach(move || {
            match crypto::threshold::sig::combine_with_verify(&self.inner, &msg, &partial_sigs) {
                Ok(combined_sig) => Ok(g1_to_bytes(&combined_sig)),
                Err(e) => Err(e.into()),
            }
        })
    }

    fn to_bytes(&self, py: Python<'_>) -> PyResult<Vec<u8>> {
        let wire = SigPublicParamsWire::from_runtime(&self.inner);
        py.detach(move || archive_api::encode(&wire))
    }

    #[staticmethod]
    fn from_bytes(py: Python<'_>, b: &[u8]) -> PyResult<Self> {
        let payload = b.to_vec();
        let wire: SigPublicParamsWire = py.detach(move || archive_api::decode(&payload))?;
        let inner = wire
            .into_runtime()
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self { inner })
    }
}

#[pyclass(from_py_object)]
#[derive(Clone)]
pub struct SigPrivateShare {
    inner: crypto::threshold::keygen::SigPrivateKeyShare,
}

#[pymethods]
impl SigPrivateShare {
    #[getter]
    fn player_id(&self) -> usize {
        self.inner.player_id - 1
    }

    fn sign(&self, py: Python<'_>, msg: &[u8]) -> PyResult<Vec<u8>> {
        let msg = msg.to_vec();
        py.detach(move || {
            let partial = crypto::threshold::sig::sign(&self.inner, &msg);
            Ok(g1_to_bytes(&partial.value))
        })
    }

    fn to_bytes(&self, py: Python<'_>) -> PyResult<Vec<u8>> {
        let wire = SigPrivateKeyShareWire::from_runtime(&self.inner);
        py.detach(move || archive_api::encode(&wire))
    }

    #[staticmethod]
    fn from_bytes(py: Python<'_>, b: &[u8]) -> PyResult<Self> {
        let payload = b.to_vec();
        let wire: SigPrivateKeyShareWire = py.detach(move || archive_api::decode(&payload))?;
        let inner = wire
            .into_runtime()
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self { inner })
    }
}

#[pyfunction]
fn sig_generate(
    py: Python<'_>,
    players: usize,
    threshold: usize,
) -> PyResult<(SigPublicKey, Vec<SigPrivateShare>)> {
    let keyset = py.detach(move || {
        crypto::threshold::keygen::generate_sig_keys(players, threshold)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    })?;

    let public_key = SigPublicKey {
        inner: keyset.public_params,
    };
    let private_shares = keyset
        .private_shares
        .into_iter()
        .map(|inner| SigPrivateShare { inner })
        .collect();

    Ok((public_key, private_shares))
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sig_generate, m)?)?;
    m.add_class::<SigPublicKey>()?;
    m.add_class::<SigPrivateShare>()?;
    Ok(())
}
