use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule, PyTuple};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Serialize, Deserialize)]
struct EncryptedBatchWire {
    encrypted_key: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
enum ChannelWire {
    AcsCoin,
    AcsRbc,
    AcsAba,
    DumboPrbc,
    DumboProof,
    DumboMvba,
    DumboPool,
    Tpke,
}

#[derive(Serialize, Deserialize)]
enum MessageWire {
    RbcVal {
        roothash: Vec<u8>,
        proof: Vec<u8>,
        stripe: Vec<u8>,
        stripe_index: u32,
    },
    RbcEcho {
        roothash: Vec<u8>,
        proof: Vec<u8>,
        stripe: Vec<u8>,
        stripe_index: u32,
    },
    RbcReady {
        roothash: Vec<u8>,
    },
    BaEst {
        epoch: u32,
        value: u32,
    },
    BaAux {
        epoch: u32,
        value: u32,
    },
    BaConf {
        epoch: u32,
        values: Vec<u32>,
    },
    CoinShareMessage {
        round_id: u32,
        signature: Vec<u8>,
    },
    TpkeShareBundle {
        shares: Vec<Option<Vec<u8>>>,
    },
    RawPayload {
        data: Vec<u8>,
    },
}

#[derive(Serialize, Deserialize)]
struct ProtocolEnvelopeWire {
    sender: u32,
    round_id: u32,
    channel: ChannelWire,
    instance_id: Option<u32>,
    message: MessageWire,
}

#[derive(Serialize, Deserialize)]
struct TxBatchWire {
    items: Vec<Vec<u8>>,
}

fn to_u32(value: usize, name: &str) -> PyResult<u32> {
    u32::try_from(value)
        .map_err(|_| PyValueError::new_err(format!("{name} does not fit into u32")))
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

fn extract_message_wire(message: &Bound<'_, PyAny>) -> PyResult<MessageWire> {
    let message_type = message.getattr("__class__")?.getattr("__name__")?.extract::<String>()?;
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
        "TpkeShareBundle" => Ok(MessageWire::TpkeShareBundle {
            shares: message.getattr("shares")?.extract()?,
        }),
        "RawPayload" => Ok(MessageWire::RawPayload {
            data: message.getattr("data")?.extract()?,
        }),
        _ => Err(PyValueError::new_err("invalid message tag")),
    }
}

fn build_message_object(py: Python<'_>, messages_mod: &Bound<'_, PyModule>, wire: MessageWire) -> PyResult<PyObject> {
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
            let values = values.into_iter().map(|value| value as usize).collect::<Vec<_>>();
            let values_tuple = PyTuple::new(py, values)?;
            Ok(messages_mod
                .getattr("BaConf")?
                .call1((epoch as usize, values_tuple))?
                .unbind())
        }
        MessageWire::CoinShareMessage { round_id, signature } => Ok(messages_mod
            .getattr("CoinShareMessage")?
            .call1((round_id as usize, PyBytes::new(py, &signature)))?
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
fn encode_encrypted_batch(py: Python<'_>, encrypted_key: &[u8], ciphertext: &[u8]) -> PyResult<Vec<u8>> {
    let encrypted_key = encrypted_key.to_vec();
    let ciphertext = ciphertext.to_vec();
    py.allow_threads(move || {
        bincode::serialize(&EncryptedBatchWire {
            encrypted_key,
            ciphertext,
        })
        .map_err(|e| PyValueError::new_err(e.to_string()))
    })
}

#[pyfunction]
fn decode_encrypted_batch(py: Python<'_>, payload: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
    let payload = payload.to_vec();
    py.allow_threads(move || {
        let wire: EncryptedBatchWire =
            bincode::deserialize(&payload).map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok((wire.encrypted_key, wire.ciphertext))
    })
}

#[pyfunction]
fn encode_encrypted_batch_py(py: Python<'_>, batch: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    let encrypted_key = batch.getattr("encrypted_key")?.extract::<Vec<u8>>()?;
    let ciphertext = batch.getattr("ciphertext")?.extract::<Vec<u8>>()?;
    py.allow_threads(move || {
        bincode::serialize(&EncryptedBatchWire {
            encrypted_key,
            ciphertext,
        })
        .map_err(|e| PyValueError::new_err(e.to_string()))
    })
}

#[pyfunction]
fn decode_encrypted_batch_py(py: Python<'_>, payload: &[u8]) -> PyResult<PyObject> {
    let payload = payload.to_vec();
    let wire: EncryptedBatchWire = py.allow_threads(move || {
        bincode::deserialize(&payload).map_err(|e| PyValueError::new_err(e.to_string()))
    })?;
    let messages_mod = PyModule::import(py, "honey.support.messages")?;
    Ok(messages_mod
        .getattr("EncryptedBatch")?
        .call1((PyBytes::new(py, &wire.encrypted_key), PyBytes::new(py, &wire.ciphertext)))?
        .unbind())
}

#[pyfunction]
fn encode_tx_batch(py: Python<'_>, items: Vec<Vec<u8>>) -> PyResult<Vec<u8>> {
    py.allow_threads(move || {
        bincode::serialize(&TxBatchWire { items }).map_err(|e| PyValueError::new_err(e.to_string()))
    })
}

#[pyfunction]
fn decode_tx_batch(py: Python<'_>, payload: &[u8]) -> PyResult<Vec<Vec<u8>>> {
    let payload = payload.to_vec();
    py.allow_threads(move || {
        let wire: TxBatchWire =
            bincode::deserialize(&payload).map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(wire.items)
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
                    return Err(PyValueError::new_err("RbcVal requires 3 byte fields and 1 int field"));
                }
                let [roothash, proof, stripe] = byte_fields.try_into().unwrap();
                MessageWire::RbcVal {
                    roothash: roothash.ok_or_else(|| PyValueError::new_err("RbcVal.roothash is required"))?,
                    proof: proof.ok_or_else(|| PyValueError::new_err("RbcVal.proof is required"))?,
                    stripe: stripe.ok_or_else(|| PyValueError::new_err("RbcVal.stripe is required"))?,
                    stripe_index: to_u32(int_fields[0], "stripe_index")?,
                }
            }
            "RbcEcho" => {
                if byte_fields.len() != 3 || int_fields.len() != 1 {
                    return Err(PyValueError::new_err("RbcEcho requires 3 byte fields and 1 int field"));
                }
                let [roothash, proof, stripe] = byte_fields.try_into().unwrap();
                MessageWire::RbcEcho {
                    roothash: roothash.ok_or_else(|| PyValueError::new_err("RbcEcho.roothash is required"))?,
                    proof: proof.ok_or_else(|| PyValueError::new_err("RbcEcho.proof is required"))?,
                    stripe: stripe.ok_or_else(|| PyValueError::new_err("RbcEcho.stripe is required"))?,
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
                epoch: to_u32(*int_fields.first().ok_or_else(|| PyValueError::new_err("BaEst.epoch is required"))?, "epoch")?,
                value: to_u32(*int_fields.get(1).ok_or_else(|| PyValueError::new_err("BaEst.value is required"))?, "value")?,
            },
            "BaAux" => MessageWire::BaAux {
                epoch: to_u32(*int_fields.first().ok_or_else(|| PyValueError::new_err("BaAux.epoch is required"))?, "epoch")?,
                value: to_u32(*int_fields.get(1).ok_or_else(|| PyValueError::new_err("BaAux.value is required"))?, "value")?,
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
                round_id: to_u32(*int_fields.first().ok_or_else(|| PyValueError::new_err("CoinShareMessage.round_id is required"))?, "round_id")?,
                signature: byte_fields
                    .into_iter()
                    .next()
                    .flatten()
                    .ok_or_else(|| PyValueError::new_err("CoinShareMessage.signature is required"))?,
            },
            "TpkeShareBundle" => MessageWire::TpkeShareBundle { shares: byte_fields },
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
    py.allow_threads(move || {
        bincode::serialize(&wire).map_err(|e| PyValueError::new_err(e.to_string()))
    })
}

#[pyfunction]
fn encode_protocol_envelope_py(
    py: Python<'_>,
    sender: usize,
    envelope: &Bound<'_, PyAny>,
) -> PyResult<Vec<u8>> {
    let round_id = envelope.getattr("round_id")?.extract::<usize>()?;
    let channel_value = envelope.getattr("channel")?.getattr("value")?.extract::<String>()?;
    let instance_id = envelope.getattr("instance_id")?.extract::<Option<usize>>()?;
    let message = envelope.getattr("message")?;
    let wire = ProtocolEnvelopeWire {
        sender: to_u32(sender, "sender")?,
        round_id: to_u32(round_id, "round_id")?,
        channel: channel_from_str(&channel_value)?,
        instance_id: match instance_id {
            Some(value) => Some(to_u32(value, "instance_id")?),
            None => None,
        },
        message: extract_message_wire(&message)?,
    };
    py.allow_threads(move || {
        bincode::serialize(&wire).map_err(|e| PyValueError::new_err(e.to_string()))
    })
}

#[pyfunction]
fn decode_protocol_envelope(
    py: Python<'_>,
    payload: &[u8],
) -> PyResult<(usize, usize, String, Option<usize>, String, Vec<Option<Vec<u8>>>, Vec<usize>)> {
    let payload = payload.to_vec();
    py.allow_threads(move || {
        let wire: ProtocolEnvelopeWire =
            bincode::deserialize(&payload).map_err(|e| PyValueError::new_err(e.to_string()))?;
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
            MessageWire::RbcReady { roothash } => (
                "RbcReady".to_string(),
                vec![Some(roothash)],
                vec![],
            ),
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
            MessageWire::CoinShareMessage { round_id, signature } => (
                "CoinShareMessage".to_string(),
                vec![Some(signature)],
                vec![round_id as usize],
            ),
            MessageWire::TpkeShareBundle { shares } => (
                "TpkeShareBundle".to_string(),
                shares,
                vec![],
            ),
            MessageWire::RawPayload { data } => (
                "RawPayload".to_string(),
                vec![Some(data)],
                vec![],
            ),
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
fn decode_protocol_envelope_py(py: Python<'_>, payload: &[u8]) -> PyResult<(usize, PyObject)> {
    let payload = payload.to_vec();
    let wire: ProtocolEnvelopeWire = py.allow_threads(move || {
        bincode::deserialize(&payload).map_err(|e| PyValueError::new_err(e.to_string()))
    })?;
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
    m.add_function(wrap_pyfunction!(encode_protocol_envelope, m)?)?;
    m.add_function(wrap_pyfunction!(encode_protocol_envelope_py, m)?)?;
    m.add_function(wrap_pyfunction!(decode_protocol_envelope, m)?)?;
    m.add_function(wrap_pyfunction!(decode_protocol_envelope_py, m)?)?;
    Ok(())
}
