use crate::proposal::AvailableProposal;
use crate::protocol::AcsProtocol;
use crate::{AcsBackend, AcsBackendStats, AcsCryptoMaterial, AcsEvent};
use honey_wire::api::{decode_result, encode_result};
use honey_wire::format::{
    AbaPayloadWire, ChannelWire, MessageWire, PdStoreRecordWire, PrbcProofWire,
    ProtocolEnvelopeWire, ThresholdShareProofWire,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyListMethods, PyModule, PyString, PyTuple};
use std::path::PathBuf;

fn prepend_python_paths(py: Python<'_>) -> PyResult<()> {
    let sys = PyModule::import(py, "sys")?;
    let path = sys.getattr("path")?.cast_into::<PyList>()?;
    path.insert(0, "honey-acs/packages/honey-acs/src")?;
    for candidate in venv_site_packages_candidates() {
        path.insert(0, candidate)?;
    }
    path.insert(0, ".")?;
    path.insert(0, "src")?;
    Ok(())
}

fn venv_site_packages_candidates() -> Vec<String> {
    let mut candidates = Vec::new();
    if let Ok(root) = std::env::current_dir() {
        let mut direct = PathBuf::from(&root);
        direct.push(".venv");
        direct.push("lib");
        direct.push("python3.14");
        direct.push("site-packages");
        if direct.exists() {
            candidates.push(direct.to_string_lossy().into_owned());
        }
    }
    candidates
}

// ---------------------------------------------------------------------------
// Wire format helpers for the internal Python backend bridge.
// These are internal Rust functions, not exposed to Python.
// ---------------------------------------------------------------------------

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
                .map(|proof| extract_threshold_share_proof_wire(proof.bind(py)))
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
    let prbc_mod = PyModule::import(py, "honey_acs.subprotocols.provable_reliable_broadcast")?;
    let dumbo_acs_mod = PyModule::import(py, "honey_acs.dumbo.dumbo_acs")?;
    let mvba_mod = PyModule::import(py, "honey_acs.subprotocols.dumbo_mvba")?;
    let pool_mod = PyModule::import(py, "honey_acs.pool_reuse")?;
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
        MessageWire::RawPayload { data } => Ok(messages_mod
            .getattr("RawPayload")?
            .call1((PyBytes::new(py, &data),))?
            .unbind()),
    }
}

// ---------------------------------------------------------------------------
// Wire encode / decode entry points (internal — not exposed to Python)
// ---------------------------------------------------------------------------

/// Decode a wire-format envelope byte slice into a Python 5-tuple
/// `(sender, round_id, channel_str, instance_id, message_obj)`.
/// This is the Rust-side equivalent of Python's `_decode_protocol_wire`.
fn decode_wire_to_py(py: Python<'_>, payload: &[u8]) -> PyResult<Py<PyAny>> {
    let payload_vec = payload.to_vec();
    let wire: ProtocolEnvelopeWire =
        py.detach(move || decode_result(&payload_vec).map_err(PyValueError::new_err))?;
    let messages_mod = PyModule::import(py, "honey_acs.messages")?;
    let message = build_message_object(py, &messages_mod, wire.message)?;
    let channel_str = channel_to_str(&wire.channel);
    let items: Vec<Py<PyAny>> = vec![
        (wire.sender as usize)
            .into_pyobject(py)?
            .into_any()
            .unbind(),
        (wire.round_id as usize)
            .into_pyobject(py)?
            .into_any()
            .unbind(),
        PyString::new(py, channel_str).into_any().unbind(),
        match wire.instance_id {
            Some(v) => (v as usize).into_pyobject(py)?.into_any().unbind(),
            None => py.None(),
        },
        message,
    ];
    Ok(PyTuple::new(py, items)?.into_any().unbind())
}

/// Encode a Python ACS service event (send / broadcast) to wire-format bytes.
/// Extracts `round_id`, `channel`, `instance_id`, and `message` from the dict,
/// prepends `sender = pid`, then rkyv-serialises.
fn encode_event_to_wire(
    py: Python<'_>,
    pid: usize,
    event: &Bound<'_, PyDict>,
) -> PyResult<Vec<u8>> {
    let round_id = dict_item(event, "round_id")?.extract::<usize>()?;
    let channel_str = dict_item(event, "channel")?.extract::<String>()?;
    let instance_id = event
        .get_item("instance_id")?
        .filter(|v| !v.is_none())
        .map(|v| v.extract::<usize>())
        .transpose()?;
    let message_obj = dict_item(event, "message")?;
    let wire = ProtocolEnvelopeWire {
        sender: to_u32(pid, "pid")?,
        round_id: to_u32(round_id, "round_id")?,
        channel: channel_from_str(&channel_str)?,
        instance_id: match instance_id {
            Some(v) => Some(to_u32(v, "instance_id")?),
            None => None,
        },
        message: extract_message_wire(py, &message_obj)?,
    };
    py.detach(move || encode_result(&wire).map_err(PyValueError::new_err))
}

// ---------------------------------------------------------------------------
// Python IPC wire types
// ---------------------------------------------------------------------------

pub struct PyAcsBackend {
    pub pid: usize,
    pub inner: Py<PyAny>,
}

// ---------------------------------------------------------------------------
// Python IPC helpers
// ---------------------------------------------------------------------------

fn dict_item<'py>(dict: &Bound<'py, PyDict>, key: &str) -> PyResult<Bound<'py, PyAny>> {
    dict.get_item(key)?
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err(format!("missing key: {key}")))
}

/// Parse an ACS service event dict that contains Python message objects
/// (i.e. after `finish_pull_outbound_decoded_batch`).  For send / broadcast
/// events the message is encoded to wire bytes on the fly so that the resulting
/// `AcsEvent` carries `payload: Vec<u8>` as the rest of the system expects.
fn parse_acs_decoded_event(
    py: Python<'_>,
    pid: usize,
    dict: Bound<'_, PyDict>,
) -> PyResult<AcsEvent> {
    let kind = dict_item(&dict, "kind")?.extract::<String>()?;
    match kind.as_str() {
        "send" => {
            let round_id = dict_item(&dict, "round_id")?.extract()?;
            let recipient = dict_item(&dict, "recipient")?.extract()?;
            let payload = encode_event_to_wire(py, pid, &dict)?;
            Ok(AcsEvent::Send {
                round_id,
                recipient,
                payload,
            })
        }
        "broadcast" => {
            let round_id = dict_item(&dict, "round_id")?.extract()?;
            let include_self = dict
                .get_item("include_self")?
                .map(|value| value.extract::<bool>())
                .transpose()?
                .unwrap_or(true);
            let payload = encode_event_to_wire(py, pid, &dict)?;
            Ok(AcsEvent::Broadcast {
                round_id,
                payload,
                include_self,
            })
        }
        "proposal_ready" => Ok(AcsEvent::ProposalAvailable {
            round_id: dict_item(&dict, "round_id")?.extract()?,
            proposal: AvailableProposal {
                proposal_id: dict_item(&dict, "proposal_id")?.extract()?,
                proposer: dict_item(&dict, "proposer")?.extract()?,
                payload: dict_item(&dict, "payload")?.extract()?,
                digest: dict_item(&dict, "digest")?.extract()?,
                availability_proof: dict_item(&dict, "certificate")?.extract()?,
            },
        }),
        "decision" => {
            let round_id = dict_item(&dict, "round_id")?.extract()?;
            let selected_proposal_ids = dict_item(&dict, "selected_proposal_ids")?
                .try_iter()?
                .map(|item| item?.extract::<String>())
                .collect::<PyResult<Vec<_>>>()?;
            Ok(AcsEvent::Decided {
                round_id,
                selected_proposal_ids,
            })
        }
        "failure" => Ok(AcsEvent::Failure {
            round_id: dict_item(&dict, "round_id")?.extract()?,
            error: dict_item(&dict, "error")?.extract()?,
            exception_type: dict_item(&dict, "exception_type")?.extract()?,
        }),
        _ => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "unknown ACS wire event kind: {kind}"
        ))),
    }
}

impl PyAcsBackend {
    pub fn new_with_material(
        protocol: AcsProtocol,
        pid: usize,
        nodes: usize,
        faulty: usize,
        crypto: &AcsCryptoMaterial,
        config_json: &str,
    ) -> Result<Self, String> {
        Python::attach(|py| -> PyResult<Self> {
            prepend_python_paths(py)?;
            let module = PyModule::import(py, "honey_acs.host")?;
            let kwargs = PyDict::new(py);
            kwargs.set_item("protocol", protocol.as_str())?;
            kwargs.set_item("pid", pid)?;
            kwargs.set_item("nodes", nodes)?;
            kwargs.set_item("faulty", faulty)?;
            kwargs.set_item("sig_pk", &crypto.sig_pk)?;
            kwargs.set_item("sig_sk", &crypto.sig_sk)?;
            kwargs.set_item("ecdsa_pks", &crypto.ecdsa_pks)?;
            kwargs.set_item("ecdsa_sk", &crypto.ecdsa_sk)?;
            kwargs.set_item("proof_sig_pk", &crypto.proof_sig_pk)?;
            kwargs.set_item("proof_sig_sk", &crypto.proof_sig_sk)?;
            kwargs.set_item("config_json", config_json)?;
            let host = module
                .getattr("build_persistent_acs_host")?
                .call((), Some(&kwargs))?;
            Ok(Self {
                pid,
                inner: host.unbind(),
            })
        })
        .map_err(|err| err.to_string())
    }

    pub fn start_round(
        &self,
        round_id: usize,
        sid: &str,
        proposal_input: &[u8],
    ) -> Result<(), String> {
        Python::attach(|py| -> PyResult<()> {
            let kwargs = PyDict::new(py);
            kwargs.set_item("round_id", round_id)?;
            kwargs.set_item("sid", sid)?;
            kwargs.set_item("proposal_input", proposal_input)?;
            self.inner
                .bind(py)
                .call_method("start_round", (), Some(&kwargs))?;
            Ok(())
        })
        .map_err(|err| err.to_string())
    }

    /// Decode each wire-format payload to a Python typed tuple, then hand the
    /// batch to Python's `push_inbound_decoded_batch`.  The Python ACS host no
    /// longer needs to call `honey_native.decode_protocol_envelope_py`.
    pub fn push_inbound_wire_batch(&self, items: &[Vec<u8>]) -> Result<usize, String> {
        Python::attach(|py| -> PyResult<usize> {
            let batch = PyList::empty(py);
            for payload in items {
                let decoded = decode_wire_to_py(py, payload)?;
                batch.append(decoded)?;
            }
            self.inner
                .bind(py)
                .call_method1("push_inbound_decoded_batch", (batch,))?
                .extract()
        })
        .map_err(|err| err.to_string())
    }

    pub fn outbound_ready(&self) -> Result<bool, String> {
        Python::attach(|py| -> PyResult<bool> {
            self.inner
                .bind(py)
                .call_method0("outbound_ready")?
                .extract()
        })
        .map_err(|err| err.to_string())
    }

    pub fn begin_pull_outbound_wire_batch(&self, limit: usize) -> Result<(), String> {
        Python::attach(|py| -> PyResult<()> {
            self.inner
                .bind(py)
                .call_method1("begin_pull_outbound_wire_batch", (limit,))?;
            Ok(())
        })
        .map_err(|err| err.to_string())
    }

    /// Retrieve decoded service events from Python and encode each send /
    /// broadcast message back to wire bytes.  Python's
    /// `finish_pull_outbound_decoded_batch` returns events with Python message
    /// objects; this method serialises them before handing `AcsEvent`s to the
    /// Rust driver.
    pub fn finish_pull_outbound_wire_batch(&self) -> Result<Vec<AcsEvent>, String> {
        let pid = self.pid;
        Python::attach(|py| -> PyResult<Vec<AcsEvent>> {
            let events = self
                .inner
                .bind(py)
                .call_method0("finish_pull_outbound_decoded_batch")?;
            events
                .try_iter()?
                .map(|item| parse_acs_decoded_event(py, pid, item?.cast_into::<PyDict>()?))
                .collect()
        })
        .map_err(|err| err.to_string())
    }

    pub fn stats(&self) -> Result<AcsBackendStats, String> {
        Python::attach(|py| -> PyResult<AcsBackendStats> {
            let stats = self
                .inner
                .bind(py)
                .call_method0("stats")?
                .cast_into::<PyDict>()?;
            let command_counts = dict_item(&stats, "command_counts")?.cast_into::<PyDict>()?;
            let batch_item_counts =
                dict_item(&stats, "batch_item_counts")?.cast_into::<PyDict>()?;
            Ok(AcsBackendStats {
                worker_ident: dict_item(&stats, "worker_ident")?.extract()?,
                rounds_started: dict_item(&stats, "rounds_started")?.extract()?,
                rounds_finished: dict_item(&stats, "rounds_finished")?.extract()?,
                processed_commands: dict_item(&stats, "processed_commands")?.extract()?,
                bridge_queue_size: dict_item(&stats, "bridge_queue_size")?.extract()?,
                worker_running: dict_item(&stats, "worker_running")?.extract()?,
                worker_error: dict_item(&stats, "worker_error")?.extract()?,
                start_round_calls: dict_item(&command_counts, "start_round")?.extract()?,
                push_inbound_wire_batch_calls: dict_item(
                    &command_counts,
                    "push_inbound_wire_batch",
                )?
                .extract()?,
                push_inbound_wire_batch_items: dict_item(
                    &batch_item_counts,
                    "push_inbound_wire_batch_items",
                )?
                .extract()?,
                pull_outbound_wire_batch_calls: dict_item(
                    &command_counts,
                    "pull_outbound_wire_batch",
                )?
                .extract()?,
                pull_outbound_wire_batch_items: dict_item(
                    &batch_item_counts,
                    "pull_outbound_wire_batch_items",
                )?
                .extract()?,
                stats_calls: dict_item(&command_counts, "stats")?.extract()?,
            })
        })
        .map_err(|err| err.to_string())
    }

    pub fn shutdown(&self) -> Result<(), String> {
        Python::attach(|py| -> PyResult<()> {
            self.inner.bind(py).call_method0("shutdown")?;
            Ok(())
        })
        .map_err(|err| err.to_string())
    }
}

impl AcsBackend for PyAcsBackend {
    fn pid(&self) -> usize {
        self.pid
    }

    fn start_round(&self, round_id: usize, sid: &str, proposal_input: &[u8]) -> Result<(), String> {
        PyAcsBackend::start_round(self, round_id, sid, proposal_input)
    }

    fn push_inbound_wire_batch(&self, items: &[Vec<u8>]) -> Result<usize, String> {
        PyAcsBackend::push_inbound_wire_batch(self, items)
    }

    fn outbound_ready(&self) -> Result<bool, String> {
        PyAcsBackend::outbound_ready(self)
    }

    fn begin_pull_outbound_wire_batch(&self, limit: usize) -> Result<(), String> {
        PyAcsBackend::begin_pull_outbound_wire_batch(self, limit)
    }

    fn finish_pull_outbound_wire_batch(&self) -> Result<Vec<AcsEvent>, String> {
        PyAcsBackend::finish_pull_outbound_wire_batch(self)
    }

    fn stats(&self) -> Result<AcsBackendStats, String> {
        PyAcsBackend::stats(self)
    }

    fn shutdown(&self) -> Result<(), String> {
        PyAcsBackend::shutdown(self)
    }
}
