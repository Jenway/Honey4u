/// Coarse-grained key-generation entry points for the Python ACS host.
///
/// These functions generate all cryptographic material for an N-node cluster
/// and return it as a list of per-node JSON strings — one per node — so that
/// the Python host never needs to construct or hold native key objects.
///
/// The JSON schema mirrors the format expected by `build_crypto_params_from_json`
/// in `honey_acs/host_crypto.py`.
use honey_crypto::threshold;
use k256::elliptic_curve::rand_core::OsRng;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use serde_json::json;

use crate::crypto;
use crate::wire::api as archive_api;
use crate::wire::crypto_wire::{
    PkePrivateKeyShareWire, PkePublicParamsWire, SigPrivateKeyShareWire, SigPublicParamsWire,
};

// ---------------------------------------------------------------------------
// Internal helpers — pure Rust, no GIL required
// ---------------------------------------------------------------------------

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sig_pk_hex(params: &threshold::keygen::SigPublicParams) -> Result<String, String> {
    archive_api::encode(&SigPublicParamsWire::from_runtime(params))
        .map(|b| to_hex(&b))
        .map_err(|e| e.to_string())
}

fn sig_sk_hex(share: &threshold::keygen::SigPrivateKeyShare) -> Result<String, String> {
    archive_api::encode(&SigPrivateKeyShareWire::from_runtime(share))
        .map(|b| to_hex(&b))
        .map_err(|e| e.to_string())
}

fn pke_pk_hex(params: &threshold::keygen::PkePublicParams) -> Result<String, String> {
    archive_api::encode(&PkePublicParamsWire::from_runtime(params))
        .map(|b| to_hex(&b))
        .map_err(|e| e.to_string())
}

fn pke_sk_hex(share: &threshold::keygen::PkePrivateKeyShare) -> Result<String, String> {
    archive_api::encode(&PkePrivateKeyShareWire::from_runtime(share))
        .map(|b| to_hex(&b))
        .map_err(|e| e.to_string())
}

/// Generate ECDSA keys for `count` nodes.
/// Returns `(public_keys_hex, private_keys_hex)` each of length `count`.
fn ecdsa_generate(count: usize) -> Result<(Vec<String>, Vec<String>), String> {
    let mut pks = Vec::with_capacity(count);
    let mut sks = Vec::with_capacity(count);
    for _ in 0..count {
        let signing_key = k256::ecdsa::SigningKey::random(&mut OsRng);
        let priv_bytes = signing_key.to_bytes().to_vec();
        let priv_fixed: [u8; 32] = priv_bytes
            .as_slice()
            .try_into()
            .expect("k256 private key is always 32 bytes");
        let pub_key = crypto::ecdsa::get_public_key(&priv_fixed).map_err(|e| e.to_string())?;
        pks.push(to_hex(&pub_key));
        sks.push(to_hex(&priv_bytes));
    }
    Ok((pks, sks))
}

// ---------------------------------------------------------------------------
// PyO3 functions
// ---------------------------------------------------------------------------

/// Generate per-node HoneyBadger crypto payloads as JSON strings.
///
/// Returns a `list[str]` of length `nodes`. Each element is a compact JSON
/// object containing the threshold-signature, threshold-PKE, and ECDSA key
/// material for one node, ready to pass to `build_crypto_params_from_json`.
#[pyfunction]
pub fn generate_hb_crypto_payloads_json(
    py: Python<'_>,
    nodes: usize,
    faulty: usize,
) -> PyResult<Vec<String>> {
    py.detach(move || {
        let sig =
            threshold::keygen::generate_sig_keys(nodes, faulty + 1).map_err(|e| e.to_string())?;
        let pke =
            threshold::keygen::generate_pke_keys(nodes, faulty + 1).map_err(|e| e.to_string())?;
        let (ecdsa_pks, ecdsa_sks) = ecdsa_generate(nodes)?;

        let shared_sig_pk = sig_pk_hex(&sig.public_params)?;
        let shared_pke_pk = pke_pk_hex(&pke.public_params)?;

        (0..nodes)
            .map(|pid| {
                let sig_sk = sig_sk_hex(&sig.private_shares[pid])?;
                let enc_sk = pke_sk_hex(&pke.private_shares[pid])?;
                let payload = json!({
                    "sig_pk":    shared_sig_pk,
                    "sig_sk":    sig_sk,
                    "enc_pk":    shared_pke_pk,
                    "enc_sk":    enc_sk,
                    "ecdsa_pks": ecdsa_pks,
                    "ecdsa_sk":  ecdsa_sks[pid],
                });
                serde_json::to_string(&payload).map_err(|e| e.to_string())
            })
            .collect::<Result<Vec<_>, String>>()
    })
    .map_err(PyValueError::new_err)
}

/// Generate per-node Dumbo crypto payloads as JSON strings.
///
/// Returns a `list[str]` of length `nodes`. Each element is a compact JSON
/// object containing coin-signature, proof-signature, threshold-PKE, and
/// ECDSA key material for one node.
#[pyfunction]
pub fn generate_dumbo_crypto_payloads_json(
    py: Python<'_>,
    nodes: usize,
    faulty: usize,
) -> PyResult<Vec<String>> {
    py.detach(move || {
        let coin =
            threshold::keygen::generate_sig_keys(nodes, faulty + 1).map_err(|e| e.to_string())?;
        let proof = threshold::keygen::generate_sig_keys(nodes, nodes - faulty)
            .map_err(|e| e.to_string())?;
        let pke =
            threshold::keygen::generate_pke_keys(nodes, faulty + 1).map_err(|e| e.to_string())?;
        let (ecdsa_pks, ecdsa_sks) = ecdsa_generate(nodes)?;

        let shared_coin_pk = sig_pk_hex(&coin.public_params)?;
        let shared_proof_pk = sig_pk_hex(&proof.public_params)?;
        let shared_pke_pk = pke_pk_hex(&pke.public_params)?;

        (0..nodes)
            .map(|pid| {
                let coin_sk = sig_sk_hex(&coin.private_shares[pid])?;
                let proof_sk = sig_sk_hex(&proof.private_shares[pid])?;
                let enc_sk = pke_sk_hex(&pke.private_shares[pid])?;
                let payload = json!({
                    "sig_pk":       shared_coin_pk,
                    "sig_sk":       coin_sk,
                    "enc_pk":       shared_pke_pk,
                    "enc_sk":       enc_sk,
                    "ecdsa_pks":    ecdsa_pks,
                    "ecdsa_sk":     ecdsa_sks[pid],
                    "proof_sig_pk": shared_proof_pk,
                    "proof_sig_sk": proof_sk,
                });
                serde_json::to_string(&payload).map_err(|e| e.to_string())
            })
            .collect::<Result<Vec<_>, String>>()
    })
    .map_err(PyValueError::new_err)
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_hb_crypto_payloads_json, m)?)?;
    m.add_function(wrap_pyfunction!(generate_dumbo_crypto_payloads_json, m)?)?;
    Ok(())
}
