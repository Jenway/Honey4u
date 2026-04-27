use std::collections::HashMap;

use honey_crypto::bls::g1::G1;
use honey_crypto::threshold;
use honey_crypto::threshold::keygen::PartialSignature;
use honey_wire::api::{decode_result, encode_result};
use honey_wire::crypto_wire::{SigPrivateKeyShareWire, SigPublicParamsWire};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

fn parse_g1_compressed(bytes: &[u8]) -> Result<G1, String> {
    let arr: &[u8; 48] = bytes
        .try_into()
        .map_err(|_| format!("expected 48 bytes for G1, got {}", bytes.len()))?;
    G1::from_compressed_bytes(arr)
}

// Internal structs — no longer exposed as pyclasses.
#[derive(Clone)]
struct SigPublicKey {
    inner: threshold::keygen::SigPublicParams,
}

#[derive(Clone)]
struct SigPrivateShare {
    inner: threshold::keygen::SigPrivateKeyShare,
}

/// Combined threshold-signature runtime exposed to Python.
/// Holds the public params and an optional private share.
#[pyclass]
pub struct ThresholdSignatureRuntime {
    public_key: SigPublicKey,
    private_share: Option<SigPrivateShare>,
}

#[pymethods]
impl ThresholdSignatureRuntime {
    /// Deserialise from wire-format bytes.
    /// `pk` is mandatory; `sk` is optional (verify-only if omitted).
    #[staticmethod]
    #[pyo3(signature = (pk, sk = None))]
    fn from_bytes(py: Python<'_>, pk: &[u8], sk: Option<&[u8]>) -> PyResult<Self> {
        let pk_bytes = pk.to_vec();
        let sk_bytes = sk.map(|b| b.to_vec());
        py.detach(move || {
            let wire: SigPublicParamsWire =
                decode_result(&pk_bytes).map_err(PyValueError::new_err)?;
            let inner = wire
                .into_runtime()
                .map_err(|e| PyValueError::new_err(e.to_string()))?;
            let public_key = SigPublicKey { inner };
            let private_share = match sk_bytes {
                Some(b) => {
                    let wire: SigPrivateKeyShareWire =
                        decode_result(&b).map_err(PyValueError::new_err)?;
                    let inner = wire
                        .into_runtime()
                        .map_err(|e| PyValueError::new_err(e.to_string()))?;
                    Some(SigPrivateShare { inner })
                }
                None => None,
            };
            Ok(Self {
                public_key,
                private_share,
            })
        })
    }

    #[getter]
    fn players(&self) -> usize {
        self.public_key.inner.total_players
    }

    #[getter]
    fn threshold(&self) -> usize {
        self.public_key.inner.threshold
    }

    /// Produce a partial (threshold) signature share for `msg`.
    /// Requires the private share to be present.
    fn sign_share(&self, py: Python<'_>, msg: &[u8]) -> PyResult<Vec<u8>> {
        let share = self.private_share.as_ref().ok_or_else(|| {
            PyValueError::new_err("threshold signature private share is not configured")
        })?;
        let inner = share.inner.clone();
        let msg = msg.to_vec();
        py.detach(move || {
            let partial = threshold::sig::sign(&inner, &msg);
            Ok(partial.value.to_compressed_bytes().to_vec())
        })
    }

    /// Verify a single partial signature share from `player_id`.
    fn verify_share(
        &self,
        py: Python<'_>,
        player_id: usize,
        sig_bytes: &[u8],
        msg: &[u8],
    ) -> PyResult<bool> {
        let value = match parse_g1_compressed(sig_bytes) {
            Ok(value) => value,
            Err(_) => return Ok(false),
        };
        let partial_sig = PartialSignature {
            player_id: player_id + 1, // internal representation is 1-indexed
            value,
        };
        let params = self.public_key.inner.clone();
        let msg = msg.to_vec();
        py.detach(move || Ok(threshold::sig::verify_share(&params, &partial_sig, &msg).is_ok()))
    }

    /// Batch-verify multiple partial signature shares.
    /// Each entry is `(player_id, sig_bytes, msg)`.
    fn verify_share_batch(
        &self,
        py: Python<'_>,
        shares: Vec<(usize, Vec<u8>, Vec<u8>)>,
    ) -> PyResult<Vec<bool>> {
        let mut partials = Vec::with_capacity(shares.len());
        for (player_id, sig_bytes, msg) in shares {
            let partial = match parse_g1_compressed(&sig_bytes) {
                Ok(value) => Some(PartialSignature {
                    player_id: player_id + 1,
                    value,
                }),
                Err(_) => None,
            };
            partials.push((partial, msg));
        }
        let params = self.public_key.inner.clone();
        py.detach(move || {
            Ok(partials
                .into_iter()
                .map(|(partial, msg)| {
                    partial.is_some_and(|partial_sig| {
                        threshold::sig::verify_share(&params, &partial_sig, &msg).is_ok()
                    })
                })
                .collect())
        })
    }

    /// Combine partial signatures with cryptographic verification of each share.
    /// `shares` is a list of `(player_id, sig_bytes)` pairs.
    fn combine_shares(
        &self,
        py: Python<'_>,
        shares: Vec<(usize, Vec<u8>)>,
        msg: &[u8],
    ) -> PyResult<Vec<u8>> {
        let mut partial_sigs = Vec::with_capacity(shares.len());
        for (player_id, sig_bytes) in shares {
            let value = parse_g1_compressed(&sig_bytes)
                .map_err(|e| PyValueError::new_err(e.to_string()))?;
            partial_sigs.push(PartialSignature {
                player_id: player_id + 1,
                value,
            });
        }
        let params = self.public_key.inner.clone();
        let msg = msg.to_vec();
        py.detach(
            move || match threshold::sig::combine_with_verify(&params, &msg, &partial_sigs) {
                Ok(combined_sig) => Ok(combined_sig.to_compressed_bytes().to_vec()),
                Err(e) => Err(PyValueError::new_err(e.to_string())),
            },
        )
    }

    /// Combine partial signatures without re-verifying each share (caller trusts them).
    /// Accepts a dict `{player_id: sig_bytes}` from Python (auto-converted to HashMap).
    fn combine_trusted_shares(
        &self,
        py: Python<'_>,
        shares: HashMap<usize, Vec<u8>>,
        msg: &[u8],
    ) -> PyResult<Vec<u8>> {
        let mut partial_sigs = Vec::with_capacity(shares.len());
        for (player_id, sig_bytes) in shares {
            let value = parse_g1_compressed(&sig_bytes)
                .map_err(|e| PyValueError::new_err(e.to_string()))?;
            partial_sigs.push(PartialSignature {
                player_id: player_id + 1,
                value,
            });
        }
        let params = self.public_key.inner.clone();
        let msg = msg.to_vec();
        py.detach(
            move || match threshold::sig::combine_trusted(&params, &msg, &partial_sigs) {
                Ok(combined_sig) => Ok(combined_sig.to_compressed_bytes().to_vec()),
                Err(e) => Err(PyValueError::new_err(e.to_string())),
            },
        )
    }

    /// Verify a fully combined threshold signature.
    fn verify_combined(&self, py: Python<'_>, sig_bytes: &[u8], msg: &[u8]) -> PyResult<bool> {
        let sig = match parse_g1_compressed(sig_bytes) {
            Ok(value) => value,
            Err(_) => return Ok(false),
        };
        let params = self.public_key.inner.clone();
        let msg = msg.to_vec();
        py.detach(move || Ok(threshold::sig::verify_combined(&params, &sig, &msg).is_ok()))
    }
}

/// Generate a fresh threshold-signature key set.
/// Returns `(pk_bytes, [sk_bytes_0, sk_bytes_1, ...])` — raw bytes,
/// ready to pass to `ThresholdSignatureRuntime.from_bytes`.
#[pyfunction]
fn sig_generate(
    py: Python<'_>,
    players: usize,
    threshold: usize,
) -> PyResult<(Vec<u8>, Vec<Vec<u8>>)> {
    py.detach(move || {
        let keyset = threshold::keygen::generate_sig_keys(players, threshold)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;

        let pk_wire = SigPublicParamsWire::from_runtime(&keyset.public_params);
        let pk_bytes = encode_result(&pk_wire).map_err(PyValueError::new_err)?;

        let sk_bytes_list = keyset
            .private_shares
            .into_iter()
            .map(|share| {
                let wire = SigPrivateKeyShareWire::from_runtime(&share);
                encode_result(&wire).map_err(PyValueError::new_err)
            })
            .collect::<PyResult<Vec<_>>>()?;

        Ok((pk_bytes, sk_bytes_list))
    })
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sig_generate, m)?)?;
    m.add_class::<ThresholdSignatureRuntime>()?;
    Ok(())
}
