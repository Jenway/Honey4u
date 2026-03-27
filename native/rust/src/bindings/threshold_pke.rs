use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use rand::RngExt;

use crate::archive::api as archive_api;
use crate::archive::crypto_wire::{
    CiphertextWire, PartialDecryptionShareWire, PkePrivateKeyShareWire, PkePublicParamsWire,
};
use crate::archive::wire::EncryptedBatchWire;
use crate::crypto;
use crate::crypto::threshold::utils::g1_to_bytes;

fn encode_ciphertext(value: &crypto::threshold::keygen::Ciphertext) -> PyResult<Vec<u8>> {
    archive_api::encode(&CiphertextWire::from_runtime(value))
}

fn decode_ciphertext(payload: &[u8]) -> PyResult<crypto::threshold::keygen::Ciphertext> {
    let wire: CiphertextWire = archive_api::decode(payload)?;
    wire.into_runtime()
        .map_err(|e| PyValueError::new_err(e.to_string()))
}

fn encode_share(value: &crypto::threshold::keygen::PartialDecryptionShare) -> PyResult<Vec<u8>> {
    archive_api::encode(&PartialDecryptionShareWire::from_runtime(value))
}

fn decode_share(payload: &[u8]) -> PyResult<crypto::threshold::keygen::PartialDecryptionShare> {
    let wire: PartialDecryptionShareWire = archive_api::decode(payload)?;
    wire.into_runtime()
        .map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pyclass(from_py_object)]
#[derive(Clone)]
pub struct PkePublicKey {
    inner: crypto::threshold::keygen::PkePublicParams,
}

#[pymethods]
impl PkePublicKey {
    #[getter]
    fn players(&self) -> usize {
        self.inner.total_players
    }

    #[getter]
    fn threshold(&self) -> usize {
        self.inner.threshold
    }

    fn encrypt(&self, py: Python<'_>, msg: &[u8]) -> PyResult<Vec<u8>> {
        if msg.len() != 32 {
            return Err(PyValueError::new_err(
                "Message must be exactly 32 bytes for PKE",
            ));
        }
        let mut msg_arr = [0u8; 32];
        msg_arr.copy_from_slice(msg);
        let master_public_key = self.inner.master_public_key.clone();
        py.detach(move || {
            let ct = crypto::threshold::pke::seal(&master_public_key, msg_arr);
            encode_ciphertext(&ct)
        })
    }

    fn verify_ciphertext(&self, ct_bin: &[u8]) -> PyResult<bool> {
        let ct = match decode_ciphertext(ct_bin) {
            Ok(ct) => ct,
            Err(_) => return Ok(false),
        };

        match crypto::threshold::pke::verify_ciphertext(&self.inner, &ct) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn verify_share(&self, player_id: usize, ct_bin: &[u8], share_bin: &[u8]) -> PyResult<bool> {
        let ct = match decode_ciphertext(ct_bin) {
            Ok(ct) => ct,
            Err(_) => return Ok(false),
        };
        let share = match decode_share(share_bin) {
            Ok(share) => share,
            Err(_) => return Ok(false),
        };

        if share.player_id != player_id + 1 {
            return Ok(false);
        }

        Ok(crypto::threshold::pke::verify_share(
            &self.inner,
            &share,
            &ct,
        ))
    }

    fn combine_shares(
        &self,
        py: Python<'_>,
        ct_bin: &[u8],
        shares_bin: Vec<Vec<u8>>,
    ) -> PyResult<Vec<u8>> {
        let ct = decode_ciphertext(ct_bin)?;

        let mut shares = Vec::with_capacity(shares_bin.len());
        for share_bin in shares_bin {
            shares.push(decode_share(&share_bin)?);
        }

        let public_params = self.inner.clone();
        py.detach(move || {
            let msg = crypto::threshold::pke::open(&public_params, &ct, &shares)
                .map_err(|e| PyValueError::new_err(e.to_string()))?;
            Ok(msg.to_vec())
        })
    }

    fn master_public_key_bytes(&self) -> PyResult<Vec<u8>> {
        Ok(g1_to_bytes(&self.inner.master_public_key))
    }

    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        archive_api::encode(&PkePublicParamsWire::from_runtime(&self.inner))
    }

    #[staticmethod]
    fn from_bytes(b: &[u8]) -> PyResult<Self> {
        let wire: PkePublicParamsWire = archive_api::decode(b)?;
        let inner = wire
            .into_runtime()
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self { inner })
    }
}

#[pyclass(from_py_object)]
#[derive(Clone)]
pub struct PkePrivateShare {
    inner: crypto::threshold::keygen::PkePrivateKeyShare,
}

#[pymethods]
impl PkePrivateShare {
    #[getter]
    fn player_id(&self) -> usize {
        self.inner.player_id - 1
    }

    fn decrypt_share(&self, py: Python<'_>, ct_bin: &[u8]) -> PyResult<Vec<u8>> {
        let ct = decode_ciphertext(ct_bin)?;
        let private_share = self.inner.clone();
        py.detach(move || {
            let share = crypto::threshold::pke::partial_open(&private_share, &ct)
                .map_err(|e| PyValueError::new_err(e.to_string()))?;
            encode_share(&share)
        })
    }

    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        archive_api::encode(&PkePrivateKeyShareWire::from_runtime(&self.inner))
    }

    #[staticmethod]
    fn from_bytes(b: &[u8]) -> PyResult<Self> {
        let wire: PkePrivateKeyShareWire = archive_api::decode(b)?;
        let inner = wire
            .into_runtime()
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self { inner })
    }
}

#[pyfunction]
fn pke_generate(
    players: usize,
    threshold: usize,
) -> PyResult<(PkePublicKey, Vec<PkePrivateShare>)> {
    let keyset = crypto::threshold::keygen::generate_pke_keys(players, threshold)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;

    let public_key = PkePublicKey {
        inner: keyset.public_params,
    };
    let private_shares = keyset
        .private_shares
        .into_iter()
        .map(|inner| PkePrivateShare { inner })
        .collect();

    Ok((public_key, private_shares))
}

#[pyfunction]
fn seal_encrypted_batch(py: Python<'_>, pk: &PkePublicKey, payload: &[u8]) -> PyResult<Vec<u8>> {
    let master_public_key = pk.inner.master_public_key.clone();
    let payload = payload.to_vec();
    py.detach(move || {
        let mut key = [0u8; 32];
        let mut rng = rand::rng();
        rng.fill(&mut key);
        let ciphertext = crypto::aes::encrypt(&key, &payload)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let encrypted_key =
            encode_ciphertext(&crypto::threshold::pke::seal(&master_public_key, key))?;
        archive_api::encode(&EncryptedBatchWire {
            encrypted_key,
            ciphertext,
        })
    })
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(pke_generate, m)?)?;
    m.add_function(wrap_pyfunction!(seal_encrypted_batch, m)?)?;
    m.add_class::<PkePublicKey>()?;
    m.add_class::<PkePrivateShare>()?;
    Ok(())
}
