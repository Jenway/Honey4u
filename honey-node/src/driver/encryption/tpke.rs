use rand::RngExt;
use std::collections::BTreeMap;
use std::thread;

use crate::driver::error::{DriverError, DriverResult};
use honey_crypto::aes;
use honey_crypto::threshold;
use honey_crypto::threshold::keygen::{
    Ciphertext, PartialDecryptionShare, PkePrivateKeyShare, PkePublicParams,
};
use honey_wire::api::{decode_result, encode_result};
use honey_wire::crypto_wire::{CiphertextWire, PartialDecryptionShareWire};
use honey_wire::format::EncryptedBatchWire;

struct BatchDecryptState {
    encrypted_key: Ciphertext,
    ciphertext: Vec<u8>,
    verified_shares: BTreeMap<usize, PartialDecryptionShare>,
    plaintext: Option<Vec<u8>>,
    needs_open: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ShareIngestResult {
    Ignored,
    Accepted,
    Decrypted,
}

impl ShareIngestResult {
    pub(crate) fn is_progress(self) -> bool {
        !matches!(self, Self::Ignored)
    }
}

pub(crate) struct DecryptItem {
    params: PkePublicParams,
    state: BatchDecryptState,
}

pub struct BatchDecryptor {
    items: Vec<DecryptItem>,
}

fn encode_ciphertext(value: &Ciphertext) -> DriverResult<Vec<u8>> {
    encode_result(&CiphertextWire::from_runtime(value)).map_err(DriverError::serialization)
}

fn decode_ciphertext(payload: &[u8]) -> DriverResult<Ciphertext> {
    let wire: CiphertextWire = decode_result(payload).map_err(DriverError::serialization)?;
    wire.into_runtime()
        .map_err(DriverError::honey_badger_crypto)
}

pub(crate) fn encode_tpke_share(value: &PartialDecryptionShare) -> DriverResult<Vec<u8>> {
    encode_result(&PartialDecryptionShareWire::from_runtime(value))
        .map_err(DriverError::serialization)
}

fn decode_tpke_share(payload: &[u8]) -> DriverResult<PartialDecryptionShare> {
    let wire: PartialDecryptionShareWire =
        decode_result(payload).map_err(DriverError::serialization)?;
    wire.into_runtime()
        .map_err(DriverError::honey_badger_crypto)
}

fn decode_encrypted_batch(payload: &[u8]) -> DriverResult<(Ciphertext, Vec<u8>)> {
    let wire: EncryptedBatchWire = decode_result(payload).map_err(DriverError::serialization)?;
    Ok((decode_ciphertext(&wire.encrypted_key)?, wire.ciphertext))
}

pub(crate) fn seal_encrypted_batch(
    public_params: &PkePublicParams,
    payload: &[u8],
) -> DriverResult<Vec<u8>> {
    let mut key = [0u8; 32];
    let mut rng = rand::rng();
    rng.fill(&mut key);
    let ciphertext = aes::encrypt(&key, payload)
        .map_err(|err| DriverError::honey_badger_crypto(err.to_string()))?;
    let encrypted_key =
        encode_ciphertext(&threshold::pke::seal(&public_params.master_public_key, key))?;
    encode_result(&EncryptedBatchWire {
        encrypted_key,
        ciphertext,
    })
    .map_err(DriverError::serialization)
}

#[allow(dead_code)]
impl BatchDecryptor {
    pub fn new(public_params: PkePublicParams, batches: Vec<Vec<u8>>) -> DriverResult<Self> {
        let mut items = Vec::with_capacity(batches.len());
        for batch in batches {
            items.push(DecryptItem::new(public_params.clone(), batch)?);
        }

        Ok(Self { items })
    }

    #[allow(dead_code)]
    pub fn batch_count(&self) -> usize {
        self.items.len()
    }

    pub fn local_shares(&self, share: &PkePrivateKeyShare) -> DriverResult<Vec<Vec<u8>>> {
        self.local_runtime_shares(share)?
            .into_iter()
            .map(|share| encode_tpke_share(&share))
            .collect()
    }

    pub fn local_runtime_shares(
        &self,
        share: &PkePrivateKeyShare,
    ) -> DriverResult<Vec<PartialDecryptionShare>> {
        let mut shares = Vec::with_capacity(self.items.len());
        for item in &self.items {
            let share = item.local_share(share)?;
            shares.push(share);
        }
        Ok(shares)
    }

    #[allow(clippy::type_complexity, dead_code)]
    pub fn local_runtime_share_bundles(
        &self,
        private_shares: &[(usize, PkePrivateKeyShare)],
    ) -> DriverResult<Vec<(usize, Vec<Option<PartialDecryptionShare>>)>> {
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

        thread::scope(|scope| -> DriverResult<Vec<_>> {
            let handles = private_shares
                .iter()
                .map(|(pid, private_share)| {
                    scope.spawn(move || {
                        Ok::<_, DriverError>((
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
                    handle.join().map_err(|_| {
                        DriverError::honey_badger_crypto("HB runtime share worker panicked")
                    })?
                })
                .collect()
        })
    }

    pub fn ingest_bundle(
        &mut self,
        sender_id: usize,
        shares: Vec<Option<Vec<u8>>>,
    ) -> DriverResult<Vec<usize>> {
        if shares.len() != self.items.len() {
            return Err(DriverError::invariant(
                "share bundle length does not match batch count",
            ));
        }

        let runtime_shares = shares
            .into_iter()
            .map(|maybe_share| match maybe_share {
                Some(share_payload) => decode_tpke_share(&share_payload).map(Some),
                None => Ok(None),
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.ingest_runtime_bundle(sender_id, runtime_shares)
    }

    pub fn ingest_runtime_bundle(
        &mut self,
        sender_id: usize,
        shares: Vec<Option<PartialDecryptionShare>>,
    ) -> DriverResult<Vec<usize>> {
        if shares.len() != self.items.len() {
            return Err(DriverError::invariant(
                "share bundle length does not match batch count",
            ));
        }

        let mut decrypted = Vec::new();
        for (index, (item, maybe_share)) in self.items.iter_mut().zip(shares).enumerate() {
            let Some(share_payload) = maybe_share else {
                continue;
            };
            if matches!(
                item.ingest_verified_share(sender_id, share_payload)?,
                ShareIngestResult::Decrypted
            ) {
                decrypted.push(index);
            }
        }

        Ok(decrypted)
    }

    #[allow(dead_code)]
    pub fn ingest_trusted_runtime_bundle(
        &mut self,
        sender_id: usize,
        shares: Vec<Option<PartialDecryptionShare>>,
    ) -> DriverResult<Vec<usize>> {
        if shares.len() != self.items.len() {
            return Err(DriverError::invariant(
                "share bundle length does not match batch count",
            ));
        }

        let mut decrypted = Vec::new();
        for (index, (item, maybe_share)) in self.items.iter_mut().zip(shares).enumerate() {
            let Some(share_payload) = maybe_share else {
                continue;
            };
            if matches!(
                item.ingest_verified_share(sender_id, share_payload)?,
                ShareIngestResult::Decrypted
            ) {
                decrypted.push(index);
            }
        }

        Ok(decrypted)
    }

    pub fn is_complete(&self) -> bool {
        self.items.iter().all(DecryptItem::is_complete)
    }

    pub fn plaintexts(&self) -> Vec<Option<Vec<u8>>> {
        self.items.iter().map(DecryptItem::plaintext).collect()
    }
}

impl DecryptItem {
    pub fn new(public_params: PkePublicParams, batch: Vec<u8>) -> DriverResult<Self> {
        let (encrypted_key, ciphertext) = decode_encrypted_batch(&batch)?;
        threshold::pke::verify_ciphertext(&public_params, &encrypted_key)
            .map_err(|err| DriverError::honey_badger_crypto(err.to_string()))?;
        Ok(Self {
            params: public_params,
            state: BatchDecryptState {
                encrypted_key,
                ciphertext,
                verified_shares: BTreeMap::new(),
                plaintext: None,
                needs_open: false,
            },
        })
    }

    pub fn is_complete(&self) -> bool {
        self.state.plaintext.is_some()
    }

    pub fn plaintext(&self) -> Option<Vec<u8>> {
        self.state.plaintext.clone()
    }

    pub fn verified_share_count(&self) -> usize {
        self.state.verified_shares.len()
    }

    pub fn local_share(&self, share: &PkePrivateKeyShare) -> DriverResult<PartialDecryptionShare> {
        Ok(threshold::pke::partial_open_trusted(
            share,
            &self.state.encrypted_key,
        ))
    }

    pub fn ingest_untrusted_share(
        &mut self,
        sender_id: usize,
        share_payload: &[u8],
    ) -> DriverResult<ShareIngestResult> {
        let share = decode_tpke_share(share_payload)?;
        self.ingest_share(sender_id, share, false)
    }

    pub fn ingest_verified_share(
        &mut self,
        sender_id: usize,
        share: PartialDecryptionShare,
    ) -> DriverResult<ShareIngestResult> {
        self.ingest_share(sender_id, share, true)
    }

    fn ingest_share(
        &mut self,
        sender_id: usize,
        share: PartialDecryptionShare,
        trusted: bool,
    ) -> DriverResult<ShareIngestResult> {
        if self.state.plaintext.is_some() || self.state.verified_shares.contains_key(&sender_id) {
            return Ok(ShareIngestResult::Ignored);
        }
        if share.player_id != sender_id + 1 {
            return Ok(ShareIngestResult::Ignored);
        }
        if !trusted
            && !threshold::pke::verify_share(&self.params, &share, &self.state.encrypted_key)
        {
            return Ok(ShareIngestResult::Ignored);
        }

        self.state.verified_shares.insert(sender_id, share);
        self.state.needs_open = true;
        if self.try_open_verified_shares()? {
            Ok(ShareIngestResult::Decrypted)
        } else {
            Ok(ShareIngestResult::Accepted)
        }
    }

    fn try_open_verified_shares(&mut self) -> DriverResult<bool> {
        if self.state.plaintext.is_some()
            || !self.state.needs_open
            || self.state.verified_shares.len() < self.params.threshold
        {
            return Ok(false);
        }

        let shares = self
            .state
            .verified_shares
            .values()
            .cloned()
            .collect::<Vec<_>>();
        match threshold::pke::open_trusted(&self.params, &self.state.encrypted_key, &shares) {
            Ok(opened_key) => match aes::decrypt(&opened_key, &self.state.ciphertext) {
                Ok(plaintext) => {
                    self.state.plaintext = Some(plaintext);
                    self.state.needs_open = false;
                    Ok(true)
                }
                Err(_) => {
                    self.state.needs_open = false;
                    Ok(false)
                }
            },
            Err(_) => {
                self.state.needs_open = false;
                Ok(false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::encryption::{
        decode_tx_batch, encode_json_string, encode_tx_batch, merge_tx_batches_bytes,
    };
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

    #[test]
    fn test_item_rejects_bad_share_before_trusted_open() {
        let keyset = generate_pke_keys(4, 3).expect("key generation should succeed");
        let tx = encode_json_string("node-0").expect("json string should encode");
        let batch = encode_tx_batch(vec![tx]).expect("tx batch should encode");
        let sealed = seal_encrypted_batch(&keyset.public_params, &batch)
            .expect("encrypted batch should encode");
        let mut item =
            DecryptItem::new(keyset.public_params.clone(), sealed).expect("item should build");

        let bad_share = encode_tpke_share(&threshold::pke::partial_open_trusted(
            &keyset.private_shares[1],
            &item.state.encrypted_key,
        ))
        .expect("bad share should encode");
        let result = item
            .ingest_untrusted_share(0, &bad_share)
            .expect("ingest should not fail");
        assert_eq!(result, ShareIngestResult::Ignored);
        assert_eq!(item.verified_share_count(), 0);
        assert!(!item.is_complete());

        for (sender_id, share) in keyset.private_shares.iter().enumerate().take(3) {
            let share = item.local_share(share).expect("local share should derive");
            let result = item
                .ingest_verified_share(sender_id, share)
                .expect("trusted ingest should succeed");
            if sender_id < 2 {
                assert!(matches!(
                    result,
                    ShareIngestResult::Accepted | ShareIngestResult::Decrypted
                ));
            }
        }

        assert!(item.is_complete());
    }
}
