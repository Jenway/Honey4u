use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyModule, PyString, PyTuple};
use serde_json::Value as JsonValue;
use std::collections::HashSet;
use std::convert::TryFrom;

use crate::archive::api as archive_api;
use crate::archive::wire::{
    AbaPayloadWire, ChannelWire, EncryptedBatchWire, MessageWire, PdStoreRecordWire, PrbcProofWire,
    ProtocolEnvelopeWire, ThresholdShareProofWire, TxBatchWire,
};

fn parse_tx_json(raw: &[u8]) -> PyResult<JsonValue> {
    serde_json::from_slice(raw).map_err(|e| PyValueError::new_err(e.to_string()))
}

fn json_value_to_py(py: Python<'_>, value: JsonValue) -> PyResult<Py<PyAny>> {
    match value {
        JsonValue::Null => Ok(py.None()),
        JsonValue::Bool(value) => Ok(value.into_pyobject(py)?.to_owned().into_any().unbind()),
        JsonValue::Number(value) => {
            if let Some(value) = value.as_i64() {
                Ok(value.into_pyobject(py)?.unbind().into())
            } else if let Some(value) = value.as_u64() {
                Ok(value.into_pyobject(py)?.unbind().into())
            } else if let Some(value) = value.as_f64() {
                Ok(value.into_pyobject(py)?.unbind().into())
            } else {
                Err(PyValueError::new_err("invalid JSON number"))
            }
        }
        JsonValue::String(value) => Ok(PyString::new(py, &value).into_any().unbind()),
        JsonValue::Array(items) => {
            let mut py_items = Vec::with_capacity(items.len());
            for item in items {
                py_items.push(json_value_to_py(py, item)?);
            }
            Ok(PyList::new(py, py_items)?.into_any().unbind())
        }
        JsonValue::Object(entries) => {
            let py_dict = PyDict::new(py);
            for (key, value) in entries {
                py_dict.set_item(key, json_value_to_py(py, value)?)?;
            }
            Ok(py_dict.into_any().unbind())
        }
    }
}

fn merge_tx_batches_bytes_inner(blocks: Vec<Vec<u8>>) -> PyResult<Vec<Vec<u8>>> {
    let mut ordered_results = Vec::new();
    let mut seen = HashSet::new();

    for payload in blocks {
        let wire: TxBatchWire = archive_api::decode(&payload)?;

        for raw_tx in wire.items {
            if !seen.insert(raw_tx.clone()) {
                continue;
            }
            ordered_results.push(raw_tx);
        }
    }

    Ok(ordered_results)
}

fn merge_tx_batches_inner(blocks: Vec<Vec<u8>>) -> PyResult<Vec<JsonValue>> {
    merge_tx_batches_bytes_inner(blocks)?
        .into_iter()
        .map(|raw_tx| parse_tx_json(&raw_tx))
        .collect()
}

fn to_u32(value: usize, name: &str) -> PyResult<u32> {
    u32::try_from(value).map_err(|_| PyValueError::new_err(format!("{name} does not fit into u32")))
}

fn channel_from_str(value: &str) -> PyResult<ChannelWire> {
    match value {
        "ACS_COIN" => Ok(ChannelWire::AcsCoin),
        "ACS_RBC" => Ok(ChannelWire::AcsRbc),
        "ACS_ABA" => Ok(ChannelWire::AcsAba),
        "DUMBO_PRBC" => Ok(ChannelWire::DumboPrbc),
        "DUMBO_PROOF" => Ok(ChannelWire::DumboProof),
        "DUMBO_MVBA" => Ok(ChannelWire::DumboMvba),
        "DUMBO_POOL" => Ok(ChannelWire::DumboPool),
        "TPKE" => Ok(ChannelWire::Tpke),
        _ => Err(PyValueError::new_err("invalid channel tag")),
    }
}

fn channel_to_str(value: &ChannelWire) -> &'static str {
    match value {
        ChannelWire::AcsCoin => "ACS_COIN",
        ChannelWire::AcsRbc => "ACS_RBC",
        ChannelWire::AcsAba => "ACS_ABA",
        ChannelWire::DumboPrbc => "DUMBO_PRBC",
        ChannelWire::DumboProof => "DUMBO_PROOF",
        ChannelWire::DumboMvba => "DUMBO_MVBA",
        ChannelWire::DumboPool => "DUMBO_POOL",
        ChannelWire::Tpke => "TPKE",
    }
}

fn extract_prbc_proof_wire(proof: &Bound<'_, PyAny>) -> PyResult<PrbcProofWire> {
    let roothash = proof.getattr("roothash")?.extract::<Vec<u8>>()?;
    let sigmas = proof
        .getattr("sigmas")?
        .extract::<Vec<(usize, Vec<u8>)>>()?
        .into_iter()
        .map(|(sender, signature)| Ok((to_u32(sender, "PrbcProof.sender")?, signature)))
        .collect::<PyResult<Vec<_>>>()?;
    Ok(PrbcProofWire { roothash, sigmas })
}

fn build_prbc_proof_object(
    py: Python<'_>,
    prbc_mod: &Bound<'_, PyModule>,
    proof: PrbcProofWire,
) -> PyResult<Py<PyAny>> {
    let sigmas = proof
        .sigmas
        .into_iter()
        .map(|(sender, signature)| (sender as usize, PyBytes::new(py, &signature)))
        .collect::<Vec<_>>();
    let sigmas_tuple = PyTuple::new(py, sigmas)?;
    Ok(prbc_mod
        .getattr("PrbcProof")?
        .call1((PyBytes::new(py, &proof.roothash), sigmas_tuple))?
        .unbind())
}

fn extract_threshold_share_proof_wire(
    proof: &Bound<'_, PyAny>,
) -> PyResult<ThresholdShareProofWire> {
    Ok(ThresholdShareProofWire {
        roothash: proof.getattr("roothash")?.extract::<Vec<u8>>()?,
        signature: proof.getattr("signature")?.extract::<Vec<u8>>()?,
    })
}

fn build_threshold_share_proof_object(
    py: Python<'_>,
    mvba_mod: &Bound<'_, PyModule>,
    proof: ThresholdShareProofWire,
) -> PyResult<Py<PyAny>> {
    Ok(mvba_mod
        .getattr("ThresholdShareProof")?
        .call1((
            PyBytes::new(py, &proof.roothash),
            PyBytes::new(py, &proof.signature),
        ))?
        .unbind())
}

fn extract_pd_store_record_wire(store: &Bound<'_, PyAny>) -> PyResult<PdStoreRecordWire> {
    Ok(PdStoreRecordWire {
        roothash: store.getattr("roothash")?.extract()?,
        stripe_owner: to_u32(
            store.getattr("stripe_owner")?.extract::<usize>()?,
            "PdStoreRecord.stripe_owner",
        )?,
        stripe: store.getattr("stripe")?.extract()?,
        merkle_proof: store.getattr("merkle_proof")?.extract()?,
    })
}

fn build_pd_store_record_object(
    py: Python<'_>,
    mvba_mod: &Bound<'_, PyModule>,
    store: PdStoreRecordWire,
) -> PyResult<Py<PyAny>> {
    Ok(mvba_mod
        .getattr("PdStoreRecord")?
        .call1((
            PyBytes::new(py, &store.roothash),
            store.stripe_owner as usize,
            PyBytes::new(py, &store.stripe),
            PyBytes::new(py, &store.merkle_proof),
        ))?
        .unbind())
}

fn extract_ba_payload_wire(py: Python<'_>, message: &Bound<'_, PyAny>) -> PyResult<AbaPayloadWire> {
    let payload = extract_message_wire(py, message)?;
    match payload {
        MessageWire::BaEst { epoch, value } => Ok(AbaPayloadWire::BaEst { epoch, value }),
        MessageWire::BaAux { epoch, value } => Ok(AbaPayloadWire::BaAux { epoch, value }),
        MessageWire::BaConf { epoch, values } => Ok(AbaPayloadWire::BaConf { epoch, values }),
        _ => Err(PyValueError::new_err(
            "MvbaAbaMessage.payload must be BaEst, BaAux, or BaConf",
        )),
    }
}

fn build_aba_payload_object(
    py: Python<'_>,
    messages_mod: &Bound<'_, PyModule>,
    payload: AbaPayloadWire,
) -> PyResult<Py<PyAny>> {
    match payload {
        AbaPayloadWire::BaEst { epoch, value } => Ok(messages_mod
            .getattr("BaEst")?
            .call1((epoch as usize, value as usize))?
            .unbind()),
        AbaPayloadWire::BaAux { epoch, value } => Ok(messages_mod
            .getattr("BaAux")?
            .call1((epoch as usize, value as usize))?
            .unbind()),
        AbaPayloadWire::BaConf { epoch, values } => {
            let values = values
                .into_iter()
                .map(|value| value as usize)
                .collect::<Vec<_>>();
            let values_tuple = PyTuple::new(py, values)?;
            Ok(messages_mod
                .getattr("BaConf")?
                .call1((epoch as usize, values_tuple))?
                .unbind())
        }
    }
}

fn extract_message_wire(py: Python<'_>, message: &Bound<'_, PyAny>) -> PyResult<MessageWire> {
    let message_type = message
        .getattr("__class__")?
        .getattr("__name__")?
        .extract::<String>()?;
    match message_type.as_str() {
        "RbcVal" => Ok(MessageWire::RbcVal {
            roothash: message.getattr("roothash")?.extract()?,
            proof: message.getattr("proof")?.extract()?,
            stripe: message.getattr("stripe")?.extract()?,
            stripe_index: to_u32(message.getattr("stripe_index")?.extract()?, "stripe_index")?,
        }),
        "RbcEcho" => Ok(MessageWire::RbcEcho {
            roothash: message.getattr("roothash")?.extract()?,
            proof: message.getattr("proof")?.extract()?,
            stripe: message.getattr("stripe")?.extract()?,
            stripe_index: to_u32(message.getattr("stripe_index")?.extract()?, "stripe_index")?,
        }),
        "RbcReady" => Ok(MessageWire::RbcReady {
            roothash: message.getattr("roothash")?.extract()?,
        }),
        "BaEst" => Ok(MessageWire::BaEst {
            epoch: to_u32(message.getattr("epoch")?.extract()?, "epoch")?,
            value: to_u32(message.getattr("value")?.extract()?, "value")?,
        }),
        "BaAux" => Ok(MessageWire::BaAux {
            epoch: to_u32(message.getattr("epoch")?.extract()?, "epoch")?,
            value: to_u32(message.getattr("value")?.extract()?, "value")?,
        }),
        "BaConf" => {
            let values = message.getattr("values")?.extract::<Vec<usize>>()?;
            let values = values
                .into_iter()
                .map(|value| to_u32(value, "BaConf.value"))
                .collect::<PyResult<Vec<u32>>>()?;
            Ok(MessageWire::BaConf {
                epoch: to_u32(message.getattr("epoch")?.extract()?, "epoch")?,
                values,
            })
        }
        "CoinShareMessage" => Ok(MessageWire::CoinShareMessage {
            round_id: to_u32(message.getattr("round_id")?.extract()?, "round_id")?,
            signature: message.getattr("signature")?.extract()?,
        }),
        "PrbcVal" => Ok(MessageWire::PrbcVal {
            leader: to_u32(message.getattr("leader")?.extract()?, "leader")?,
            roothash: message.getattr("roothash")?.extract()?,
            proof: message.getattr("proof")?.extract()?,
            stripe: message.getattr("stripe")?.extract()?,
            stripe_index: to_u32(message.getattr("stripe_index")?.extract()?, "stripe_index")?,
        }),
        "PrbcEcho" => Ok(MessageWire::PrbcEcho {
            leader: to_u32(message.getattr("leader")?.extract()?, "leader")?,
            roothash: message.getattr("roothash")?.extract()?,
            proof: message.getattr("proof")?.extract()?,
            stripe: message.getattr("stripe")?.extract()?,
            stripe_index: to_u32(message.getattr("stripe_index")?.extract()?, "stripe_index")?,
        }),
        "PrbcReady" => Ok(MessageWire::PrbcReady {
            leader: to_u32(message.getattr("leader")?.extract()?, "leader")?,
            roothash: message.getattr("roothash")?.extract()?,
            signature: message.getattr("signature")?.extract()?,
        }),
        "DumboProofDiffuse" => Ok(MessageWire::DumboProofDiffuse {
            leader: to_u32(message.getattr("leader")?.extract()?, "leader")?,
            proof: extract_prbc_proof_wire(&message.getattr("proof")?)?,
        }),
        "PdStore" => Ok(MessageWire::PdStore {
            leader: to_u32(message.getattr("leader")?.extract()?, "leader")?,
            roothash: message.getattr("roothash")?.extract()?,
            stripe: message.getattr("stripe")?.extract()?,
            merkle_proof: message.getattr("merkle_proof")?.extract()?,
        }),
        "PdStored" => Ok(MessageWire::PdStored {
            leader: to_u32(message.getattr("leader")?.extract()?, "leader")?,
            roothash: message.getattr("roothash")?.extract()?,
            share: message.getattr("share")?.extract()?,
        }),
        "PdLock" => Ok(MessageWire::PdLock {
            leader: to_u32(message.getattr("leader")?.extract()?, "leader")?,
            proof: extract_threshold_share_proof_wire(&message.getattr("proof")?)?,
        }),
        "PdLocked" => Ok(MessageWire::PdLocked {
            leader: to_u32(message.getattr("leader")?.extract()?, "leader")?,
            roothash: message.getattr("roothash")?.extract()?,
            share: message.getattr("share")?.extract()?,
        }),
        "PdDone" => Ok(MessageWire::PdDone {
            leader: to_u32(message.getattr("leader")?.extract()?, "leader")?,
            proof: extract_threshold_share_proof_wire(&message.getattr("proof")?)?,
        }),
        "MvbaRcPrepare" => Ok(MessageWire::MvbaRcPrepare {
            mvba_round: to_u32(message.getattr("mvba_round")?.extract()?, "mvba_round")?,
            leader: to_u32(message.getattr("leader")?.extract()?, "leader")?,
            proof: message
                .getattr("proof")?
                .extract::<Option<Py<PyAny>>>()?
                .map(|proof| extract_threshold_share_proof_wire(&proof.bind(py)))
                .transpose()?,
        }),
        "MvbaRcLock" => Ok(MessageWire::MvbaRcLock {
            mvba_round: to_u32(message.getattr("mvba_round")?.extract()?, "mvba_round")?,
            leader: to_u32(message.getattr("leader")?.extract()?, "leader")?,
            proof: extract_threshold_share_proof_wire(&message.getattr("proof")?)?,
        }),
        "MvbaRcStore" => Ok(MessageWire::MvbaRcStore {
            mvba_round: to_u32(message.getattr("mvba_round")?.extract()?, "mvba_round")?,
            leader: to_u32(message.getattr("leader")?.extract()?, "leader")?,
            store: extract_pd_store_record_wire(&message.getattr("store")?)?,
        }),
        "MvbaAbaMessage" => Ok(MessageWire::MvbaAbaMessage {
            mvba_round: to_u32(message.getattr("mvba_round")?.extract()?, "mvba_round")?,
            payload: extract_ba_payload_wire(py, &message.getattr("payload")?)?,
        }),
        "MvbaElectionCoinShare" => Ok(MessageWire::MvbaElectionCoinShare {
            coin_round: to_u32(message.getattr("coin_round")?.extract()?, "coin_round")?,
            signature: message.getattr("signature")?.extract()?,
        }),
        "MvbaAbaCoinShare" => Ok(MessageWire::MvbaAbaCoinShare {
            mvba_round: to_u32(message.getattr("mvba_round")?.extract()?, "mvba_round")?,
            coin_round: to_u32(message.getattr("coin_round")?.extract()?, "coin_round")?,
            signature: message.getattr("signature")?.extract()?,
        }),
        "PoolFetchRequest" => Ok(MessageWire::PoolFetchRequest {
            item_id: message.getattr("item_id")?.extract()?,
            origin_round: to_u32(message.getattr("origin_round")?.extract()?, "origin_round")?,
            origin_sender: to_u32(
                message.getattr("origin_sender")?.extract()?,
                "origin_sender",
            )?,
            roothash: message.getattr("roothash")?.extract()?,
        }),
        "PoolFetchResponse" => Ok(MessageWire::PoolFetchResponse {
            item_id: message.getattr("item_id")?.extract()?,
            payload: message.getattr("payload")?.extract()?,
        }),
        "TpkeShareBundle" => Ok(MessageWire::TpkeShareBundle {
            shares: message.getattr("shares")?.extract()?,
        }),
        "RawPayload" => Ok(MessageWire::RawPayload {
            data: message.getattr("data")?.extract()?,
        }),
        _ => Err(PyValueError::new_err("invalid message tag")),
    }
}

fn build_message_object(
    py: Python<'_>,
    messages_mod: &Bound<'_, PyModule>,
    wire: MessageWire,
) -> PyResult<Py<PyAny>> {
    let prbc_mod = PyModule::import(py, "honey.subprotocols.provable_reliable_broadcast")?;
    let dumbo_acs_mod = PyModule::import(py, "honey.acs.dumbo_acs")?;
    let mvba_mod = PyModule::import(py, "honey.subprotocols.dumbo_mvba")?;
    let pool_mod = PyModule::import(py, "honey.data.pool_reuse")?;
    match wire {
        MessageWire::RbcVal {
            roothash,
            proof,
            stripe,
            stripe_index,
        } => Ok(messages_mod
            .getattr("RbcVal")?
            .call1((
                PyBytes::new(py, &roothash),
                PyBytes::new(py, &proof),
                PyBytes::new(py, &stripe),
                stripe_index as usize,
            ))?
            .unbind()),
        MessageWire::RbcEcho {
            roothash,
            proof,
            stripe,
            stripe_index,
        } => Ok(messages_mod
            .getattr("RbcEcho")?
            .call1((
                PyBytes::new(py, &roothash),
                PyBytes::new(py, &proof),
                PyBytes::new(py, &stripe),
                stripe_index as usize,
            ))?
            .unbind()),
        MessageWire::RbcReady { roothash } => Ok(messages_mod
            .getattr("RbcReady")?
            .call1((PyBytes::new(py, &roothash),))?
            .unbind()),
        MessageWire::BaEst { epoch, value } => Ok(messages_mod
            .getattr("BaEst")?
            .call1((epoch as usize, value as usize))?
            .unbind()),
        MessageWire::BaAux { epoch, value } => Ok(messages_mod
            .getattr("BaAux")?
            .call1((epoch as usize, value as usize))?
            .unbind()),
        MessageWire::BaConf { epoch, values } => {
            let values = values
                .into_iter()
                .map(|value| value as usize)
                .collect::<Vec<_>>();
            let values_tuple = PyTuple::new(py, values)?;
            Ok(messages_mod
                .getattr("BaConf")?
                .call1((epoch as usize, values_tuple))?
                .unbind())
        }
        MessageWire::CoinShareMessage {
            round_id,
            signature,
        } => Ok(messages_mod
            .getattr("CoinShareMessage")?
            .call1((round_id as usize, PyBytes::new(py, &signature)))?
            .unbind()),
        MessageWire::PrbcVal {
            leader,
            roothash,
            proof,
            stripe,
            stripe_index,
        } => Ok(prbc_mod
            .getattr("PrbcVal")?
            .call1((
                leader as usize,
                PyBytes::new(py, &roothash),
                PyBytes::new(py, &proof),
                PyBytes::new(py, &stripe),
                stripe_index as usize,
            ))?
            .unbind()),
        MessageWire::PrbcEcho {
            leader,
            roothash,
            proof,
            stripe,
            stripe_index,
        } => Ok(prbc_mod
            .getattr("PrbcEcho")?
            .call1((
                leader as usize,
                PyBytes::new(py, &roothash),
                PyBytes::new(py, &proof),
                PyBytes::new(py, &stripe),
                stripe_index as usize,
            ))?
            .unbind()),
        MessageWire::PrbcReady {
            leader,
            roothash,
            signature,
        } => Ok(prbc_mod
            .getattr("PrbcReady")?
            .call1((
                leader as usize,
                PyBytes::new(py, &roothash),
                PyBytes::new(py, &signature),
            ))?
            .unbind()),
        MessageWire::DumboProofDiffuse { leader, proof } => Ok(dumbo_acs_mod
            .getattr("DumboProofDiffuse")?
            .call1((
                leader as usize,
                build_prbc_proof_object(py, &prbc_mod, proof)?,
            ))?
            .unbind()),
        MessageWire::PdStore {
            leader,
            roothash,
            stripe,
            merkle_proof,
        } => Ok(mvba_mod
            .getattr("PdStore")?
            .call1((
                leader as usize,
                PyBytes::new(py, &roothash),
                PyBytes::new(py, &stripe),
                PyBytes::new(py, &merkle_proof),
            ))?
            .unbind()),
        MessageWire::PdStored {
            leader,
            roothash,
            share,
        } => Ok(mvba_mod
            .getattr("PdStored")?
            .call1((
                leader as usize,
                PyBytes::new(py, &roothash),
                PyBytes::new(py, &share),
            ))?
            .unbind()),
        MessageWire::PdLock { leader, proof } => Ok(mvba_mod
            .getattr("PdLock")?
            .call1((
                leader as usize,
                build_threshold_share_proof_object(py, &mvba_mod, proof)?,
            ))?
            .unbind()),
        MessageWire::PdLocked {
            leader,
            roothash,
            share,
        } => Ok(mvba_mod
            .getattr("PdLocked")?
            .call1((
                leader as usize,
                PyBytes::new(py, &roothash),
                PyBytes::new(py, &share),
            ))?
            .unbind()),
        MessageWire::PdDone { leader, proof } => Ok(mvba_mod
            .getattr("PdDone")?
            .call1((
                leader as usize,
                build_threshold_share_proof_object(py, &mvba_mod, proof)?,
            ))?
            .unbind()),
        MessageWire::MvbaRcPrepare {
            mvba_round,
            leader,
            proof,
        } => Ok(mvba_mod
            .getattr("MvbaRcPrepare")?
            .call1((
                mvba_round as usize,
                leader as usize,
                match proof {
                    Some(proof) => Some(build_threshold_share_proof_object(py, &mvba_mod, proof)?),
                    None => None,
                },
            ))?
            .unbind()),
        MessageWire::MvbaRcLock {
            mvba_round,
            leader,
            proof,
        } => Ok(mvba_mod
            .getattr("MvbaRcLock")?
            .call1((
                mvba_round as usize,
                leader as usize,
                build_threshold_share_proof_object(py, &mvba_mod, proof)?,
            ))?
            .unbind()),
        MessageWire::MvbaRcStore {
            mvba_round,
            leader,
            store,
        } => Ok(mvba_mod
            .getattr("MvbaRcStore")?
            .call1((
                mvba_round as usize,
                leader as usize,
                build_pd_store_record_object(py, &mvba_mod, store)?,
            ))?
            .unbind()),
        MessageWire::MvbaAbaMessage {
            mvba_round,
            payload,
        } => Ok(mvba_mod
            .getattr("MvbaAbaMessage")?
            .call1((
                mvba_round as usize,
                build_aba_payload_object(py, messages_mod, payload)?,
            ))?
            .unbind()),
        MessageWire::MvbaElectionCoinShare {
            coin_round,
            signature,
        } => Ok(mvba_mod
            .getattr("MvbaElectionCoinShare")?
            .call1((coin_round as usize, PyBytes::new(py, &signature)))?
            .unbind()),
        MessageWire::MvbaAbaCoinShare {
            mvba_round,
            coin_round,
            signature,
        } => Ok(mvba_mod
            .getattr("MvbaAbaCoinShare")?
            .call1((
                mvba_round as usize,
                coin_round as usize,
                PyBytes::new(py, &signature),
            ))?
            .unbind()),
        MessageWire::PoolFetchRequest {
            item_id,
            origin_round,
            origin_sender,
            roothash,
        } => Ok(pool_mod
            .getattr("PoolFetchRequest")?
            .call1((
                item_id,
                origin_round as usize,
                origin_sender as usize,
                PyBytes::new(py, &roothash),
            ))?
            .unbind()),
        MessageWire::PoolFetchResponse { item_id, payload } => Ok(pool_mod
            .getattr("PoolFetchResponse")?
            .call1((item_id, PyBytes::new(py, &payload)))?
            .unbind()),
        MessageWire::TpkeShareBundle { shares } => {
            let mut py_items = Vec::with_capacity(shares.len());
            for share in shares {
                match share {
                    Some(bytes) => py_items.push(PyBytes::new(py, &bytes).into_any().unbind()),
                    None => py_items.push(py.None()),
                }
            }
            let shares_tuple = PyTuple::new(py, py_items)?;
            Ok(messages_mod
                .getattr("TpkeShareBundle")?
                .call1((shares_tuple,))?
                .unbind())
        }
        MessageWire::RawPayload { data } => Ok(messages_mod
            .getattr("RawPayload")?
            .call1((PyBytes::new(py, &data),))?
            .unbind()),
    }
}

#[pyfunction]
fn encode_encrypted_batch(
    py: Python<'_>,
    encrypted_key: &[u8],
    ciphertext: &[u8],
) -> PyResult<Vec<u8>> {
    let encrypted_key = encrypted_key.to_vec();
    let ciphertext = ciphertext.to_vec();
    py.detach(move || {
        archive_api::encode(&EncryptedBatchWire {
            encrypted_key,
            ciphertext,
        })
    })
}

#[pyfunction]
fn decode_encrypted_batch(py: Python<'_>, payload: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
    let payload = payload.to_vec();
    py.detach(move || {
        let wire: EncryptedBatchWire = archive_api::decode(&payload)?;
        Ok((wire.encrypted_key, wire.ciphertext))
    })
}

#[pyfunction]
fn encode_encrypted_batch_py(py: Python<'_>, batch: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    let encrypted_key = batch.getattr("encrypted_key")?.extract::<Vec<u8>>()?;
    let ciphertext = batch.getattr("ciphertext")?.extract::<Vec<u8>>()?;
    py.detach(move || {
        archive_api::encode(&EncryptedBatchWire {
            encrypted_key,
            ciphertext,
        })
    })
}

#[pyfunction]
fn decode_encrypted_batch_py(py: Python<'_>, payload: &[u8]) -> PyResult<Py<PyAny>> {
    let payload = payload.to_vec();
    let wire: EncryptedBatchWire = py.detach(move || archive_api::decode(&payload))?;
    let messages_mod = PyModule::import(py, "honey.support.messages")?;
    Ok(messages_mod
        .getattr("EncryptedBatch")?
        .call1((
            PyBytes::new(py, &wire.encrypted_key),
            PyBytes::new(py, &wire.ciphertext),
        ))?
        .unbind())
}

#[pyfunction]
fn encode_tx_batch(py: Python<'_>, items: Vec<Vec<u8>>) -> PyResult<Vec<u8>> {
    py.detach(move || archive_api::encode(&TxBatchWire { items }))
}

#[pyfunction]
fn decode_tx_batch(py: Python<'_>, payload: &[u8]) -> PyResult<Vec<Vec<u8>>> {
    let payload = payload.to_vec();
    py.detach(move || {
        let wire: TxBatchWire = archive_api::decode(&payload)?;
        Ok(wire.items)
    })
}

#[pyfunction]
fn decode_tx_py(py: Python<'_>, payload: &[u8]) -> PyResult<Py<PyAny>> {
    let payload = payload.to_vec();
    let value = py.detach(move || parse_tx_json(&payload))?;
    json_value_to_py(py, value)
}

#[pyfunction]
fn merge_tx_batches_py(py: Python<'_>, blocks: Vec<Vec<u8>>) -> PyResult<Py<PyAny>> {
    let merged = py.detach(move || merge_tx_batches_inner(blocks))?;
    let mut py_items = Vec::with_capacity(merged.len());
    for item in merged {
        py_items.push(json_value_to_py(py, item)?);
    }
    Ok(PyList::new(py, py_items)?.into_any().unbind())
}

#[pyfunction]
fn merge_tx_batches_bytes(py: Python<'_>, blocks: Vec<Vec<u8>>) -> PyResult<Vec<u8>> {
    py.detach(move || {
        let items = merge_tx_batches_bytes_inner(blocks)?;
        archive_api::encode(&TxBatchWire { items })
    })
}

#[pyfunction(signature = (sender, round_id, channel, instance_id, message_type, byte_fields, int_fields))]
fn encode_protocol_envelope(
    py: Python<'_>,
    sender: usize,
    round_id: usize,
    channel: &str,
    instance_id: Option<usize>,
    message_type: &str,
    byte_fields: Vec<Option<Vec<u8>>>,
    int_fields: Vec<usize>,
) -> PyResult<Vec<u8>> {
    let wire = ProtocolEnvelopeWire {
        sender: to_u32(sender, "sender")?,
        round_id: to_u32(round_id, "round_id")?,
        channel: channel_from_str(channel)?,
        instance_id: match instance_id {
            Some(value) => Some(to_u32(value, "instance_id")?),
            None => None,
        },
        message: match message_type {
            "RbcVal" => {
                if byte_fields.len() != 3 || int_fields.len() != 1 {
                    return Err(PyValueError::new_err(
                        "RbcVal requires 3 byte fields and 1 int field",
                    ));
                }
                let [roothash, proof, stripe] = byte_fields.try_into().unwrap();
                MessageWire::RbcVal {
                    roothash: roothash
                        .ok_or_else(|| PyValueError::new_err("RbcVal.roothash is required"))?,
                    proof: proof
                        .ok_or_else(|| PyValueError::new_err("RbcVal.proof is required"))?,
                    stripe: stripe
                        .ok_or_else(|| PyValueError::new_err("RbcVal.stripe is required"))?,
                    stripe_index: to_u32(int_fields[0], "stripe_index")?,
                }
            }
            "RbcEcho" => {
                if byte_fields.len() != 3 || int_fields.len() != 1 {
                    return Err(PyValueError::new_err(
                        "RbcEcho requires 3 byte fields and 1 int field",
                    ));
                }
                let [roothash, proof, stripe] = byte_fields.try_into().unwrap();
                MessageWire::RbcEcho {
                    roothash: roothash
                        .ok_or_else(|| PyValueError::new_err("RbcEcho.roothash is required"))?,
                    proof: proof
                        .ok_or_else(|| PyValueError::new_err("RbcEcho.proof is required"))?,
                    stripe: stripe
                        .ok_or_else(|| PyValueError::new_err("RbcEcho.stripe is required"))?,
                    stripe_index: to_u32(int_fields[0], "stripe_index")?,
                }
            }
            "RbcReady" => MessageWire::RbcReady {
                roothash: byte_fields
                    .into_iter()
                    .next()
                    .flatten()
                    .ok_or_else(|| PyValueError::new_err("RbcReady.roothash is required"))?,
            },
            "BaEst" => MessageWire::BaEst {
                epoch: to_u32(
                    *int_fields
                        .first()
                        .ok_or_else(|| PyValueError::new_err("BaEst.epoch is required"))?,
                    "epoch",
                )?,
                value: to_u32(
                    *int_fields
                        .get(1)
                        .ok_or_else(|| PyValueError::new_err("BaEst.value is required"))?,
                    "value",
                )?,
            },
            "BaAux" => MessageWire::BaAux {
                epoch: to_u32(
                    *int_fields
                        .first()
                        .ok_or_else(|| PyValueError::new_err("BaAux.epoch is required"))?,
                    "epoch",
                )?,
                value: to_u32(
                    *int_fields
                        .get(1)
                        .ok_or_else(|| PyValueError::new_err("BaAux.value is required"))?,
                    "value",
                )?,
            },
            "BaConf" => {
                if int_fields.is_empty() {
                    return Err(PyValueError::new_err("BaConf requires at least epoch"));
                }
                let mut values = Vec::with_capacity(int_fields.len().saturating_sub(1));
                for value in int_fields.iter().skip(1) {
                    values.push(to_u32(*value, "BaConf.value")?);
                }
                MessageWire::BaConf {
                    epoch: to_u32(int_fields[0], "epoch")?,
                    values,
                }
            }
            "CoinShareMessage" => MessageWire::CoinShareMessage {
                round_id: to_u32(
                    *int_fields.first().ok_or_else(|| {
                        PyValueError::new_err("CoinShareMessage.round_id is required")
                    })?,
                    "round_id",
                )?,
                signature: byte_fields.into_iter().next().flatten().ok_or_else(|| {
                    PyValueError::new_err("CoinShareMessage.signature is required")
                })?,
            },
            "TpkeShareBundle" => MessageWire::TpkeShareBundle {
                shares: byte_fields,
            },
            "RawPayload" => MessageWire::RawPayload {
                data: byte_fields
                    .into_iter()
                    .next()
                    .flatten()
                    .ok_or_else(|| PyValueError::new_err("RawPayload.data is required"))?,
            },
            _ => return Err(PyValueError::new_err("invalid message tag")),
        },
    };
    py.detach(move || archive_api::encode(&wire))
}

#[pyfunction]
fn encode_protocol_envelope_py(
    py: Python<'_>,
    sender: usize,
    envelope: &Bound<'_, PyAny>,
) -> PyResult<Vec<u8>> {
    let round_id = envelope.getattr("round_id")?.extract::<usize>()?;
    let channel_value = envelope
        .getattr("channel")?
        .getattr("value")?
        .extract::<String>()?;
    let instance_id = envelope
        .getattr("instance_id")?
        .extract::<Option<usize>>()?;
    let message = envelope.getattr("message")?;
    let wire = ProtocolEnvelopeWire {
        sender: to_u32(sender, "sender")?,
        round_id: to_u32(round_id, "round_id")?,
        channel: channel_from_str(&channel_value)?,
        instance_id: match instance_id {
            Some(value) => Some(to_u32(value, "instance_id")?),
            None => None,
        },
        message: extract_message_wire(py, &message)?,
    };
    py.detach(move || archive_api::encode(&wire))
}

#[pyfunction]
fn decode_protocol_envelope(
    py: Python<'_>,
    payload: &[u8],
) -> PyResult<(
    usize,
    usize,
    String,
    Option<usize>,
    String,
    Vec<Option<Vec<u8>>>,
    Vec<usize>,
)> {
    let payload = payload.to_vec();
    py.detach(move || {
        let wire: ProtocolEnvelopeWire = archive_api::decode(&payload)?;
        let (message_type, byte_fields, int_fields) = match wire.message {
            MessageWire::RbcVal {
                roothash,
                proof,
                stripe,
                stripe_index,
            } => (
                "RbcVal".to_string(),
                vec![Some(roothash), Some(proof), Some(stripe)],
                vec![stripe_index as usize],
            ),
            MessageWire::RbcEcho {
                roothash,
                proof,
                stripe,
                stripe_index,
            } => (
                "RbcEcho".to_string(),
                vec![Some(roothash), Some(proof), Some(stripe)],
                vec![stripe_index as usize],
            ),
            MessageWire::RbcReady { roothash } => {
                ("RbcReady".to_string(), vec![Some(roothash)], vec![])
            }
            MessageWire::BaEst { epoch, value } => (
                "BaEst".to_string(),
                vec![],
                vec![epoch as usize, value as usize],
            ),
            MessageWire::BaAux { epoch, value } => (
                "BaAux".to_string(),
                vec![],
                vec![epoch as usize, value as usize],
            ),
            MessageWire::BaConf { epoch, values } => {
                let mut ints = Vec::with_capacity(values.len() + 1);
                ints.push(epoch as usize);
                ints.extend(values.into_iter().map(|value| value as usize));
                ("BaConf".to_string(), vec![], ints)
            }
            MessageWire::CoinShareMessage {
                round_id,
                signature,
            } => (
                "CoinShareMessage".to_string(),
                vec![Some(signature)],
                vec![round_id as usize],
            ),
            MessageWire::TpkeShareBundle { shares } => {
                ("TpkeShareBundle".to_string(), shares, vec![])
            }
            MessageWire::RawPayload { data } => {
                ("RawPayload".to_string(), vec![Some(data)], vec![])
            }
            _ => {
                return Err(PyValueError::new_err(
                    "message type not supported by decode_protocol_envelope",
                ));
            }
        };
        Ok((
            wire.sender as usize,
            wire.round_id as usize,
            channel_to_str(&wire.channel).to_string(),
            wire.instance_id.map(|value| value as usize),
            message_type,
            byte_fields,
            int_fields,
        ))
    })
}

#[pyfunction]
fn decode_protocol_envelope_py(py: Python<'_>, payload: &[u8]) -> PyResult<(usize, Py<PyAny>)> {
    let payload = payload.to_vec();
    let wire: ProtocolEnvelopeWire = py.detach(move || archive_api::decode(&payload))?;
    let messages_mod = PyModule::import(py, "honey.support.messages")?;
    let message = build_message_object(py, &messages_mod, wire.message)?;
    let channel = messages_mod
        .getattr("Channel")?
        .call1((channel_to_str(&wire.channel),))?;
    let envelope = messages_mod.getattr("ProtocolEnvelope")?.call1((
        wire.round_id as usize,
        channel,
        wire.instance_id.map(|value| value as usize),
        message,
    ))?;
    Ok((wire.sender as usize, envelope.unbind()))
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encode_encrypted_batch, m)?)?;
    m.add_function(wrap_pyfunction!(decode_encrypted_batch, m)?)?;
    m.add_function(wrap_pyfunction!(encode_encrypted_batch_py, m)?)?;
    m.add_function(wrap_pyfunction!(decode_encrypted_batch_py, m)?)?;
    m.add_function(wrap_pyfunction!(encode_tx_batch, m)?)?;
    m.add_function(wrap_pyfunction!(decode_tx_batch, m)?)?;
    m.add_function(wrap_pyfunction!(decode_tx_py, m)?)?;
    m.add_function(wrap_pyfunction!(merge_tx_batches_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(merge_tx_batches_py, m)?)?;
    m.add_function(wrap_pyfunction!(encode_protocol_envelope, m)?)?;
    m.add_function(wrap_pyfunction!(encode_protocol_envelope_py, m)?)?;
    m.add_function(wrap_pyfunction!(decode_protocol_envelope, m)?)?;
    m.add_function(wrap_pyfunction!(decode_protocol_envelope_py, m)?)?;
    Ok(())
}
