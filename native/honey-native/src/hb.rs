use rand::RngExt;
use std::collections::{BTreeMap, HashSet};
use std::thread;

use crate::archive::api::{decode_result, encode_result};
use crate::archive::crypto_wire::{
    CiphertextWire, PartialDecryptionShareWire, PkePrivateKeyShareWire, PkePublicParamsWire,
};
use crate::archive::wire::{EncryptedBatchWire, TxBatchWire};
use crate::crypto;
use honey_crypto::threshold;
use honey_crypto::threshold::keygen::{
    Ciphertext, PartialDecryptionShare, PkePrivateKeyShare, PkePublicParams,
};

pub use honey_crypto::threshold::keygen::{
    PartialDecryptionShare as HbPartialDecryptionShare, PkePrivateKeyShare as HbPkePrivateKeyShare,
    PkePublicParams as HbPkePublicParams,
};

struct BatchDecryptState {
    encrypted_key: Ciphertext,
    ciphertext: Vec<u8>,
    shares: BTreeMap<usize, PartialDecryptionShare>,
    plaintext: Option<Vec<u8>>,
    needs_open: bool,
}

pub struct BatchDecryptor {
    params: PkePublicParams,
    states: Vec<BatchDecryptState>,
}

fn encode_ciphertext(value: &Ciphertext) -> Result<Vec<u8>, String> {
    encode_result(&CiphertextWire::from_runtime(value))
}

fn decode_ciphertext(payload: &[u8]) -> Result<Ciphertext, String> {
    let wire: CiphertextWire = decode_result(payload)?;
    wire.into_runtime()
}

fn encode_share(value: &PartialDecryptionShare) -> Result<Vec<u8>, String> {
    encode_result(&PartialDecryptionShareWire::from_runtime(value))
}

fn decode_share(payload: &[u8]) -> Result<PartialDecryptionShare, String> {
    let wire: PartialDecryptionShareWire = decode_result(payload)?;
    wire.into_runtime()
}

fn decode_encrypted_batch(payload: &[u8]) -> Result<(Ciphertext, Vec<u8>), String> {
    let wire: EncryptedBatchWire = decode_result(payload)?;
    Ok((decode_ciphertext(&wire.encrypted_key)?, wire.ciphertext))
}

pub fn encode_json_string(value: &str) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|err| err.to_string())
}

pub fn encode_tx_batch(items: Vec<Vec<u8>>) -> Result<Vec<u8>, String> {
    encode_result(&TxBatchWire { items })
}

pub fn decode_tx_batch(payload: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let wire: TxBatchWire = decode_result(payload)?;
    Ok(wire.items)
}

pub fn merge_tx_batches_bytes(blocks: Vec<Vec<u8>>) -> Result<Vec<u8>, String> {
    let mut ordered_results = Vec::new();
    let mut seen = HashSet::new();

    for payload in blocks {
        let wire: TxBatchWire = decode_result(&payload)?;
        for raw_tx in wire.items {
            if seen.insert(raw_tx.clone()) {
                ordered_results.push(raw_tx);
            }
        }
    }

    encode_result(&TxBatchWire {
        items: ordered_results,
    })
}

pub fn decode_pke_public_params(payload: &[u8]) -> Result<PkePublicParams, String> {
    let wire: PkePublicParamsWire = decode_result(payload)?;
    wire.into_runtime()
}

pub fn decode_pke_private_share(payload: &[u8]) -> Result<PkePrivateKeyShare, String> {
    let wire: PkePrivateKeyShareWire = decode_result(payload)?;
    wire.into_runtime()
}

pub fn seal_encrypted_batch(
    public_params: &PkePublicParams,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let mut key = [0u8; 32];
    let mut rng = rand::rng();
    rng.fill(&mut key);
    let ciphertext = crypto::aes::encrypt(&key, payload).map_err(|err| err.to_string())?;
    let encrypted_key =
        encode_ciphertext(&threshold::pke::seal(&public_params.master_public_key, key))?;
    encode_result(&EncryptedBatchWire {
        encrypted_key,
        ciphertext,
    })
}

impl BatchDecryptor {
    pub fn new(public_params: PkePublicParams, batches: Vec<Vec<u8>>) -> Result<Self, String> {
        let mut states = Vec::with_capacity(batches.len());
        for batch in batches {
            let (encrypted_key, ciphertext) = decode_encrypted_batch(&batch)?;
            threshold::pke::verify_ciphertext(&public_params, &encrypted_key)
                .map_err(|err| err.to_string())?;
            states.push(BatchDecryptState {
                encrypted_key,
                ciphertext,
                shares: BTreeMap::new(),
                plaintext: None,
                needs_open: false,
            });
        }

        Ok(Self {
            params: public_params,
            states,
        })
    }

    pub fn batch_count(&self) -> usize {
        self.states.len()
    }

    pub fn local_shares(&self, share: &PkePrivateKeyShare) -> Result<Vec<Vec<u8>>, String> {
        self.local_runtime_shares(share)?
            .into_iter()
            .map(|share| encode_share(&share))
            .collect()
    }

    pub fn local_runtime_shares(
        &self,
        share: &PkePrivateKeyShare,
    ) -> Result<Vec<PartialDecryptionShare>, String> {
        let mut shares = Vec::with_capacity(self.states.len());
        for state in &self.states {
            let share = threshold::pke::partial_open_trusted(share, &state.encrypted_key);
            shares.push(share);
        }
        Ok(shares)
    }

    pub fn local_runtime_share_bundles(
        &self,
        private_shares: &[(usize, PkePrivateKeyShare)],
    ) -> Result<Vec<(usize, Vec<Option<PartialDecryptionShare>>)>, String> {
        if private_shares.len() <= 1 {
            return private_shares
                .iter()
                .map(|(pid, private_share)| {
                    Ok((
                        *pid,
                        self.local_runtime_shares(private_share)?
                            .into_iter()
                            .map(Some)
                            .collect::<Vec<_>>(),
                    ))
                })
                .collect();
        }

        thread::scope(|scope| -> Result<Vec<_>, String> {
            let handles = private_shares
                .iter()
                .map(|(pid, private_share)| {
                    scope.spawn(move || {
                        Ok::<_, String>((
                            *pid,
                            self.local_runtime_shares(private_share)?
                                .into_iter()
                                .map(Some)
                                .collect::<Vec<_>>(),
                        ))
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .map_err(|_| String::from("HB runtime share worker panicked"))?
                })
                .collect()
        })
    }

    pub fn ingest_bundle(
        &mut self,
        sender_id: usize,
        shares: Vec<Option<Vec<u8>>>,
    ) -> Result<Vec<usize>, String> {
        if shares.len() != self.states.len() {
            return Err(String::from(
                "share bundle length does not match batch count",
            ));
        }

        let runtime_shares = shares
            .into_iter()
            .map(|maybe_share| match maybe_share {
                Some(share_payload) => decode_share(&share_payload).map(Some),
                None => Ok(None),
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.ingest_runtime_bundle(sender_id, runtime_shares)
    }

    pub fn ingest_runtime_bundle(
        &mut self,
        sender_id: usize,
        shares: Vec<Option<PartialDecryptionShare>>,
    ) -> Result<Vec<usize>, String> {
        if shares.len() != self.states.len() {
            return Err(String::from(
                "share bundle length does not match batch count",
            ));
        }

        for (state, maybe_share) in self.states.iter_mut().zip(shares) {
            if state.plaintext.is_some() || state.shares.contains_key(&sender_id) {
                continue;
            }

            let Some(share_payload) = maybe_share else {
                continue;
            };

            if share_payload.player_id != sender_id + 1 {
                continue;
            }
            if !threshold::pke::verify_share(&self.params, &share_payload, &state.encrypted_key) {
                continue;
            }

            state.shares.insert(sender_id, share_payload);
            state.needs_open = true;
        }

        let mut decrypted = Vec::new();
        for (index, state) in self.states.iter_mut().enumerate() {
            if state.plaintext.is_some()
                || !state.needs_open
                || state.shares.len() < self.params.threshold
            {
                continue;
            }

            let shares = state.shares.values().cloned().collect::<Vec<_>>();
            match threshold::pke::open(&self.params, &state.encrypted_key, &shares) {
                Ok(opened_key) => match crypto::aes::decrypt(&opened_key, &state.ciphertext) {
                    Ok(plaintext) => {
                        state.plaintext = Some(plaintext);
                        state.needs_open = false;
                        decrypted.push(index);
                    }
                    Err(_) => {
                        state.needs_open = false;
                    }
                },
                Err(_) => {
                    state.needs_open = false;
                }
            }
        }

        Ok(decrypted)
    }

    pub fn ingest_trusted_runtime_bundle(
        &mut self,
        sender_id: usize,
        shares: Vec<Option<PartialDecryptionShare>>,
    ) -> Result<Vec<usize>, String> {
        if shares.len() != self.states.len() {
            return Err(String::from(
                "share bundle length does not match batch count",
            ));
        }

        for (state, maybe_share) in self.states.iter_mut().zip(shares) {
            if state.plaintext.is_some() || state.shares.contains_key(&sender_id) {
                continue;
            }

            let Some(share_payload) = maybe_share else {
                continue;
            };

            if share_payload.player_id != sender_id + 1 {
                continue;
            }

            state.shares.insert(sender_id, share_payload);
            state.needs_open = true;
        }

        let mut decrypted = Vec::new();
        for (index, state) in self.states.iter_mut().enumerate() {
            if state.plaintext.is_some()
                || !state.needs_open
                || state.shares.len() < self.params.threshold
            {
                continue;
            }

            let shares = state.shares.values().cloned().collect::<Vec<_>>();
            match threshold::pke::open_trusted(&self.params, &state.encrypted_key, &shares) {
                Ok(opened_key) => match crypto::aes::decrypt(&opened_key, &state.ciphertext) {
                    Ok(plaintext) => {
                        state.plaintext = Some(plaintext);
                        state.needs_open = false;
                        decrypted.push(index);
                    }
                    Err(_) => {
                        state.needs_open = false;
                    }
                },
                Err(_) => {
                    state.needs_open = false;
                }
            }
        }

        Ok(decrypted)
    }

    pub fn is_complete(&self) -> bool {
        self.states.iter().all(|state| state.plaintext.is_some())
    }

    pub fn plaintexts(&self) -> Vec<Option<Vec<u8>>> {
        self.states
            .iter()
            .map(|state| state.plaintext.clone())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Public surface for honey-node crate (bypasses the Python layer)
// ---------------------------------------------------------------------------

/// Decoded pool-fetch message extracted from a raw protocol-envelope wire payload.
pub enum PoolFetchWire {
    Request {
        sender: u32,
        item_id: String,
        origin_round: u32,
        origin_sender: u32,
        roothash: Vec<u8>,
    },
    Response {
        sender: u32,
        item_id: String,
        payload: Vec<u8>,
    },
}

/// Verify ≥ `threshold` distinct valid ECDSA signatures over `digest`.
///
/// `pub_keys`: compressed 33-byte secp256k1 public keys, indexed by node-id.
/// `sigmas`:   `(node_id_0based as i32, raw_64b_signature)` pairs.
pub fn ecdsa_verify_threshold_sigs(
    pub_keys: &[[u8; 33]],
    digest: &[u8],
    sigmas: &[(i32, [u8; 64])],
    threshold: usize,
) -> bool {
    crate::crypto::ecdsa::verify_threshold_sigs(pub_keys, digest, sigmas, threshold)
}

/// Decode a `DUMBO_POOL` message from a raw protocol-envelope wire payload.
///
/// Returns `Ok(Some(_))` for pool-fetch messages, `Ok(None)` for every other
/// channel, and `Err(_)` if the bytes are malformed.
pub fn decode_pool_fetch_from_wire(bytes: &[u8]) -> Result<Option<PoolFetchWire>, String> {
    use crate::archive::wire::{ChannelWire, MessageWire};
    let wire: crate::archive::wire::ProtocolEnvelopeWire =
        crate::archive::api::decode_result(bytes)?;
    if !matches!(wire.channel, ChannelWire::DumboPool) {
        return Ok(None);
    }
    let sender = wire.sender;
    match wire.message {
        MessageWire::PoolFetchRequest {
            item_id,
            origin_round,
            origin_sender,
            roothash,
        } => Ok(Some(PoolFetchWire::Request {
            sender,
            item_id,
            origin_round,
            origin_sender,
            roothash,
        })),
        MessageWire::PoolFetchResponse { item_id, payload } => Ok(Some(PoolFetchWire::Response {
            sender,
            item_id,
            payload,
        })),
        _ => Err(String::from(
            "unexpected message type in DUMBO_POOL envelope",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use honey_crypto::threshold::keygen::generate_pke_keys;

    #[test]
    fn test_hb_block_round_trip_and_merge() {
        let keyset = generate_pke_keys(4, 3).expect("key generation should succeed");
        let payloads = ["node-0", "node-1", "node-2", "node-3"]
            .into_iter()
            .map(|value| {
                let tx = encode_json_string(value).expect("json string should encode");
                let batch = encode_tx_batch(vec![tx]).expect("tx batch should encode");
                seal_encrypted_batch(&keyset.public_params, &batch)
                    .expect("encrypted batch should encode")
            })
            .collect::<Vec<_>>();

        let mut decryptor = BatchDecryptor::new(keyset.public_params.clone(), payloads)
            .expect("decryptor should build");
        assert_eq!(decryptor.batch_count(), 4);

        for (sender_id, share) in keyset.private_shares.iter().enumerate() {
            let bundle = decryptor
                .local_shares(share)
                .expect("local shares should derive")
                .into_iter()
                .map(Some)
                .collect::<Vec<_>>();
            decryptor
                .ingest_bundle(sender_id, bundle)
                .expect("share bundle should ingest");
        }

        assert!(decryptor.is_complete());

        let plaintexts = decryptor
            .plaintexts()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        let merged = merge_tx_batches_bytes(plaintexts).expect("batches should merge");
        let merged_items = decode_tx_batch(&merged).expect("merged block should decode");
        assert_eq!(merged_items.len(), 4);
    }
}
