pub mod backends;
#[cfg(test)]
pub mod harness;
pub mod host_crypto;
pub mod proposal;
pub mod protocol;
pub mod threaded;

use self::backends::rust_dumbo::RustDumboAcsBackend;
use self::backends::rust_fin::RustAcsBackend;
use self::backends::rust_hb::RustHbAcsBackend;
use self::threaded::ThreadedAcsBackend;
use crate::proposal::AvailableProposal;
use honey_wire::codec::{decode_hex, json_string_field};
use serde_json::Value;

pub struct AcsCryptoMaterial {
    pub sig_pk: Vec<u8>,
    pub sig_sk: Vec<u8>,
    pub ecdsa_pks: Vec<Vec<u8>>,
    pub ecdsa_sk: Vec<u8>,
    pub proof_sig_pk: Option<Vec<u8>>,
    pub proof_sig_sk: Option<Vec<u8>>,
}

pub struct AcsBackendStats {
    pub worker_ident: u64,
    pub rounds_started: usize,
    pub rounds_finished: usize,
    pub processed_commands: usize,
    pub bridge_queue_size: usize,
    pub worker_running: bool,
    pub worker_error: Option<String>,
    pub start_round_calls: usize,
    pub push_inbound_wire_batch_calls: usize,
    pub push_inbound_wire_batch_items: usize,
    pub pull_outbound_wire_batch_calls: usize,
    pub pull_outbound_wire_batch_items: usize,
    pub stats_calls: usize,
}

pub enum AcsEvent {
    Send {
        round_id: usize,
        recipient: usize,
        payload: Vec<u8>,
    },
    Broadcast {
        round_id: usize,
        payload: Vec<u8>,
        include_self: bool,
    },
    ProposalAvailable {
        round_id: usize,
        proposal: AvailableProposal,
    },
    Decided {
        round_id: usize,
        selected_proposal_ids: Vec<String>,
    },
    Failure {
        round_id: isize,
        error: String,
        exception_type: String,
    },
}

#[cfg(test)]
pub struct AcsRoundOutcome {
    pub selected_proposal_ids: Vec<String>,
    pub selected_pids: Vec<usize>,
}

pub trait AcsBackend {
    fn pid(&self) -> usize;
    fn start_round(&self, round_id: usize, sid: &str, proposal_input: &[u8]) -> Result<(), String>;
    fn push_inbound_wire_batch(&self, items: &[Vec<u8>]) -> Result<usize, String>;
    fn outbound_ready(&self) -> Result<bool, String>;
    fn begin_pull_outbound_wire_batch(&self, limit: usize) -> Result<(), String>;
    fn finish_pull_outbound_wire_batch(&self) -> Result<Vec<AcsEvent>, String>;
    fn finish_round(&self, round_id: usize) -> Result<(), String>;
    fn stats(&self) -> Result<AcsBackendStats, String>;
    fn shutdown(&self) -> Result<(), String>;
}

impl<T> AcsBackend for Box<T>
where
    T: AcsBackend + ?Sized,
{
    fn pid(&self) -> usize {
        (**self).pid()
    }

    fn start_round(&self, round_id: usize, sid: &str, proposal_input: &[u8]) -> Result<(), String> {
        (**self).start_round(round_id, sid, proposal_input)
    }

    fn push_inbound_wire_batch(&self, items: &[Vec<u8>]) -> Result<usize, String> {
        (**self).push_inbound_wire_batch(items)
    }

    fn outbound_ready(&self) -> Result<bool, String> {
        (**self).outbound_ready()
    }

    fn begin_pull_outbound_wire_batch(&self, limit: usize) -> Result<(), String> {
        (**self).begin_pull_outbound_wire_batch(limit)
    }

    fn finish_pull_outbound_wire_batch(&self) -> Result<Vec<AcsEvent>, String> {
        (**self).finish_pull_outbound_wire_batch()
    }

    fn finish_round(&self, round_id: usize) -> Result<(), String> {
        (**self).finish_round(round_id)
    }

    fn stats(&self) -> Result<AcsBackendStats, String> {
        (**self).stats()
    }

    fn shutdown(&self) -> Result<(), String> {
        (**self).shutdown()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AcsBackendKind {
    #[cfg(feature = "python-backend")]
    PythonHb,
    #[cfg(feature = "python-backend")]
    PythonDumbo,
    RustFin,
    RustDumbo,
    RustHb,
}

impl AcsBackendKind {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            #[cfg(feature = "python-backend")]
            "python_hb" => Ok(Self::PythonHb),
            #[cfg(not(feature = "python-backend"))]
            "python_hb" => Err(String::from(
                "acs_backend=python_hb requires the python-backend feature",
            )),
            #[cfg(feature = "python-backend")]
            "python_dumbo" => Ok(Self::PythonDumbo),
            #[cfg(not(feature = "python-backend"))]
            "python_dumbo" => Err(String::from(
                "acs_backend=python_dumbo requires the python-backend feature",
            )),
            "rust" | "rust_fin" => Ok(Self::RustFin),
            "rust_dumbo" => Ok(Self::RustDumbo),
            "rust_hb" => Ok(Self::RustHb),
            other => Err(format!("unsupported acs_backend: {other}")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            #[cfg(feature = "python-backend")]
            Self::PythonHb => "python_hb",
            #[cfg(feature = "python-backend")]
            Self::PythonDumbo => "python_dumbo",
            Self::RustFin => "rust_fin",
            Self::RustDumbo => "rust_dumbo",
            Self::RustHb => "rust_hb",
        }
    }

    pub fn is_dumbo(self) -> bool {
        match self {
            #[cfg(feature = "python-backend")]
            Self::PythonDumbo => true,
            Self::RustFin | Self::RustDumbo => true,
            _ => false,
        }
    }
}

fn json_string_array_field(value: &Value, key: &str) -> Result<Vec<String>, String> {
    let entries = value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing array field: {key}"))?;
    entries
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("non-string entry in array field: {key}"))
        })
        .collect()
}

pub fn parse_acs_crypto_payload(
    backend: AcsBackendKind,
    payload: &str,
) -> Result<AcsCryptoMaterial, String> {
    let decoded = serde_json::from_str::<Value>(payload).map_err(|err| err.to_string())?;
    let ecdsa_pks = json_string_array_field(&decoded, "ecdsa_pks")?
        .into_iter()
        .map(|value| decode_hex(&value))
        .collect::<Result<Vec<_>, _>>()?;
    let (proof_sig_pk, proof_sig_sk) = if backend.is_dumbo() {
        (
            Some(decode_hex(json_string_field(&decoded, "proof_sig_pk")?)?),
            Some(decode_hex(json_string_field(&decoded, "proof_sig_sk")?)?),
        )
    } else {
        (None, None)
    };
    Ok(AcsCryptoMaterial {
        sig_pk: decode_hex(json_string_field(&decoded, "sig_pk")?)?,
        sig_sk: decode_hex(json_string_field(&decoded, "sig_sk")?)?,
        ecdsa_pks,
        ecdsa_sk: decode_hex(json_string_field(&decoded, "ecdsa_sk")?)?,
        proof_sig_pk,
        proof_sig_sk,
    })
}

pub fn build_acs_backend(
    backend: AcsBackendKind,
    pid: usize,
    nodes: usize,
    faulty: usize,
    crypto_json: &str,
    config_json: &str,
) -> Result<Box<dyn AcsBackend>, String> {
    let crypto = parse_acs_crypto_payload(backend, crypto_json)?;
    match backend {
        #[cfg(feature = "python-backend")]
        AcsBackendKind::PythonHb | AcsBackendKind::PythonDumbo => {
            use self::backends::python::PyAcsBackend;
            Ok(Box::new(PyAcsBackend::new_with_material(
                backend,
                pid,
                nodes,
                faulty,
                &crypto,
                config_json,
            )?))
        }
        AcsBackendKind::RustFin => Ok(Box::new(ThreadedAcsBackend::new(RustAcsBackend::new(
            pid,
            nodes,
            faulty,
            crypto,
            config_json,
        )?))),
        AcsBackendKind::RustDumbo => Ok(Box::new(ThreadedAcsBackend::new(
            RustDumboAcsBackend::new(pid, nodes, faulty, crypto, config_json)?,
        ))),
        AcsBackendKind::RustHb => Ok(Box::new(ThreadedAcsBackend::new(RustHbAcsBackend::new(
            pid,
            nodes,
            faulty,
            crypto,
            config_json,
        )?))),
    }
}
