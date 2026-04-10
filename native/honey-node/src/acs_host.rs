use super::*;
use crate::py_host::PyAcsHost;
use crate::rust_acs::RustAcsHost;
use crate::rust_dumbo_acs::RustDumboAcsHost;
use crate::rust_hb_acs::RustHbAcsHost;
use crate::threaded_acs_host::ThreadedAcsHost;

pub(crate) struct AcsCryptoMaterial {
    pub(crate) sig_pk: Vec<u8>,
    pub(crate) sig_sk: Vec<u8>,
    pub(crate) ecdsa_pks: Vec<Vec<u8>>,
    pub(crate) ecdsa_sk: Vec<u8>,
    pub(crate) proof_sig_pk: Option<Vec<u8>>,
    pub(crate) proof_sig_sk: Option<Vec<u8>>,
}

pub(crate) struct AcsHostStats {
    pub(crate) worker_ident: u64,
    pub(crate) rounds_started: usize,
    pub(crate) rounds_finished: usize,
    pub(crate) processed_commands: usize,
    pub(crate) bridge_queue_size: usize,
    pub(crate) worker_running: bool,
    pub(crate) worker_error: Option<String>,
    pub(crate) start_round_calls: usize,
    pub(crate) push_inbound_wire_batch_calls: usize,
    pub(crate) push_inbound_wire_batch_items: usize,
    pub(crate) pull_outbound_wire_batch_calls: usize,
    pub(crate) pull_outbound_wire_batch_items: usize,
    pub(crate) stats_calls: usize,
}

pub(crate) enum AcsWireEvent {
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
    ProposalReady {
        round_id: usize,
        proposal: ProposalArtifact,
    },
    Decision {
        round_id: usize,
        selected_proposal_ids: Vec<String>,
    },
    Failure {
        round_id: isize,
        error: String,
        exception_type: String,
    },
}

pub(crate) struct AcsRoundOutcome {
    pub(crate) selected_proposal_ids: Vec<String>,
    pub(crate) selected_pids: Vec<usize>,
    pub(crate) send_events: usize,
    pub(crate) drive_stats: DriverPhaseStats,
    pub(crate) settle_stats: DriverPhaseStats,
}

pub(crate) trait AcsHost {
    fn pid(&self) -> usize;
    fn start_round(&self, round_id: usize, sid: &str, proposal_input: &[u8]) -> Result<(), String>;
    fn push_inbound_wire_batch(&self, items: &[Vec<u8>]) -> Result<usize, String>;
    fn outbound_ready(&self) -> Result<bool, String>;
    fn begin_pull_outbound_wire_batch(&self, limit: usize) -> Result<(), String>;
    fn finish_pull_outbound_wire_batch(&self) -> Result<Vec<AcsWireEvent>, String>;
    fn stats(&self) -> Result<AcsHostStats, String>;
    fn shutdown(&self) -> Result<(), String>;
}

impl<T> AcsHost for Box<T>
where
    T: AcsHost + ?Sized,
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

    fn finish_pull_outbound_wire_batch(&self) -> Result<Vec<AcsWireEvent>, String> {
        (**self).finish_pull_outbound_wire_batch()
    }

    fn stats(&self) -> Result<AcsHostStats, String> {
        (**self).stats()
    }

    fn shutdown(&self) -> Result<(), String> {
        (**self).shutdown()
    }
}

#[derive(Clone, Copy)]
enum AcsHostBackend {
    Python,
    RustFin,
    RustDumbo,
    RustHb,
}

fn parse_acs_host_backend(config_json: &str) -> Result<AcsHostBackend, String> {
    let value: Value = serde_json::from_str(config_json).map_err(|err| err.to_string())?;
    match value
        .get("acs_host_backend")
        .and_then(Value::as_str)
        .unwrap_or("python")
    {
        "python" => Ok(AcsHostBackend::Python),
        "rust" | "rust_fin" => Ok(AcsHostBackend::RustFin),
        "rust_dumbo" => Ok(AcsHostBackend::RustDumbo),
        "rust_hb" => Ok(AcsHostBackend::RustHb),
        other => Err(format!(
            "unsupported acs_host_backend in config_json: {other}"
        )),
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

pub(crate) fn parse_acs_crypto_payload(
    protocol: Protocol,
    payload: &str,
) -> Result<AcsCryptoMaterial, String> {
    let decoded = serde_json::from_str::<Value>(payload).map_err(|err| err.to_string())?;
    let ecdsa_pks = json_string_array_field(&decoded, "ecdsa_pks")?
        .into_iter()
        .map(|value| decode_hex(&value))
        .collect::<Result<Vec<_>, _>>()?;
    let (proof_sig_pk, proof_sig_sk) = match protocol {
        Protocol::HoneyBadger => (None, None),
        Protocol::Dumbo => (
            Some(decode_hex(json_string_field(&decoded, "proof_sig_pk")?)?),
            Some(decode_hex(json_string_field(&decoded, "proof_sig_sk")?)?),
        ),
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

pub(crate) fn build_acs_host(
    protocol: Protocol,
    pid: usize,
    nodes: usize,
    faulty: usize,
    crypto_json: &str,
    config_json: &str,
) -> Result<Box<dyn AcsHost>, String> {
    let crypto = parse_acs_crypto_payload(protocol, crypto_json)?;
    match parse_acs_host_backend(config_json)? {
        AcsHostBackend::Python => Ok(Box::new(PyAcsHost::new_with_material(
            protocol,
            pid,
            nodes,
            faulty,
            &crypto,
            config_json,
        )?)),
        AcsHostBackend::RustFin => Ok(Box::new(ThreadedAcsHost::new(RustAcsHost::new(
            pid,
            nodes,
            faulty,
            crypto,
            config_json,
        )?))),
        AcsHostBackend::RustDumbo => {
            if !matches!(protocol, Protocol::Dumbo) {
                return Err(String::from(
                    "acs_host_backend=rust_dumbo currently supports only acs_protocol=dumbo",
                ));
            }
            Ok(Box::new(ThreadedAcsHost::new(RustDumboAcsHost::new(
                pid,
                nodes,
                faulty,
                crypto,
                config_json,
            )?)))
        }
        AcsHostBackend::RustHb => {
            if !matches!(protocol, Protocol::HoneyBadger) {
                return Err(String::from(
                    "acs_host_backend=rust_hb currently supports only acs_protocol=hb",
                ));
            }
            Ok(Box::new(ThreadedAcsHost::new(RustHbAcsHost::new(
                pid,
                nodes,
                faulty,
                crypto,
                config_json,
            )?)))
        }
    }
}
