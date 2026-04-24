use k256::ecdsa::SigningKey;
use k256::elliptic_curve::rand_core::OsRng;
use serde_json::json;

use crate::wire::api::encode_result;
use crate::wire::crypto_wire::{
    PkePrivateKeyShareWire, PkePublicParamsWire, SigPrivateKeyShareWire, SigPublicParamsWire,
};
use honey_crypto::ecdsa;
use honey_crypto::threshold;

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sig_pk_hex(params: &threshold::keygen::SigPublicParams) -> Result<String, String> {
    encode_result(&SigPublicParamsWire::from_runtime(params)).map(|b| to_hex(&b))
}

fn sig_sk_hex(share: &threshold::keygen::SigPrivateKeyShare) -> Result<String, String> {
    encode_result(&SigPrivateKeyShareWire::from_runtime(share)).map(|b| to_hex(&b))
}

fn pke_pk_hex(params: &threshold::keygen::PkePublicParams) -> Result<String, String> {
    encode_result(&PkePublicParamsWire::from_runtime(params)).map(|b| to_hex(&b))
}

fn pke_sk_hex(share: &threshold::keygen::PkePrivateKeyShare) -> Result<String, String> {
    encode_result(&PkePrivateKeyShareWire::from_runtime(share)).map(|b| to_hex(&b))
}

fn ecdsa_generate(count: usize) -> Result<(Vec<String>, Vec<String>), String> {
    let mut pks = Vec::with_capacity(count);
    let mut sks = Vec::with_capacity(count);
    for _ in 0..count {
        let signing_key = SigningKey::random(&mut OsRng);
        let priv_bytes = signing_key.to_bytes().to_vec();
        let priv_fixed: [u8; 32] = priv_bytes
            .as_slice()
            .try_into()
            .expect("k256 private key is always 32 bytes");
        let pub_key = ecdsa::get_public_key(&priv_fixed).map_err(|e| e.to_string())?;
        pks.push(to_hex(&pub_key));
        sks.push(to_hex(&priv_bytes));
    }
    Ok((pks, sks))
}

pub fn generate_hb_crypto_payloads_json(
    nodes: usize,
    faulty: usize,
) -> Result<Vec<String>, String> {
    let sig = threshold::keygen::generate_sig_keys(nodes, faulty + 1).map_err(|e| e.to_string())?;
    let pke = threshold::keygen::generate_pke_keys(nodes, faulty + 1).map_err(|e| e.to_string())?;
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
        .collect()
}

pub fn generate_dumbo_crypto_payloads_json(
    nodes: usize,
    faulty: usize,
) -> Result<Vec<String>, String> {
    let coin =
        threshold::keygen::generate_sig_keys(nodes, faulty + 1).map_err(|e| e.to_string())?;
    let proof =
        threshold::keygen::generate_sig_keys(nodes, nodes - faulty).map_err(|e| e.to_string())?;
    let pke = threshold::keygen::generate_pke_keys(nodes, faulty + 1).map_err(|e| e.to_string())?;
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
        .collect()
}
