use crate::acs::proposal::AvailableProposal;
use crate::acs::protocol::AcsProtocol;
use crate::acs::{AcsBackend, AcsBackendStats, AcsCryptoMaterial, AcsEvent};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyListMethods, PyModule};
use std::path::PathBuf;

fn prepend_python_paths(py: Python<'_>) -> PyResult<()> {
    let sys = PyModule::import(py, "sys")?;
    let path = sys.getattr("path")?.cast_into::<PyList>()?;
    path.insert(0, "packages/honey-acs/src")?;
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
// Python IPC wire types
// These types define the data exchanged between the Rust driver and the Python
// ACS host over the PyO3 GIL-locked call boundary.
// ---------------------------------------------------------------------------

pub(crate) struct PyAcsBackend {
    pub(crate) pid: usize,
    pub(crate) inner: Py<PyAny>,
}

// ---------------------------------------------------------------------------
// Python IPC helpers
// ---------------------------------------------------------------------------

fn dict_item<'py>(dict: &Bound<'py, PyDict>, key: &str) -> PyResult<Bound<'py, PyAny>> {
    dict.get_item(key)?
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err(format!("missing key: {key}")))
}

fn parse_acs_wire_event(dict: Bound<'_, PyDict>) -> PyResult<AcsEvent> {
    let kind = dict_item(&dict, "kind")?.extract::<String>()?;
    match kind.as_str() {
        "send" => Ok(AcsEvent::Send {
            round_id: dict_item(&dict, "round_id")?.extract()?,
            recipient: dict_item(&dict, "recipient")?.extract()?,
            payload: dict_item(&dict, "payload")?.extract()?,
        }),
        "broadcast" => Ok(AcsEvent::Broadcast {
            round_id: dict_item(&dict, "round_id")?.extract()?,
            payload: dict_item(&dict, "payload")?.extract()?,
            include_self: dict
                .get_item("include_self")?
                .map(|value| value.extract::<bool>())
                .transpose()?
                .unwrap_or(true),
        }),
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
    pub(crate) fn new_with_material(
        protocol: AcsProtocol,
        pid: usize,
        nodes: usize,
        faulty: usize,
        crypto: &AcsCryptoMaterial,
        config_json: &str,
    ) -> Result<Self, String> {
        Python::attach(|py| -> PyResult<Self> {
            prepend_python_paths(py)?;
            let module = PyModule::import(py, "honey_acs.host_bridge")?;
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

    pub(crate) fn start_round(
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

    pub(crate) fn push_inbound_wire_batch(&self, items: &[Vec<u8>]) -> Result<usize, String> {
        Python::attach(|py| -> PyResult<usize> {
            let batch = pyo3::types::PyList::empty(py);
            for payload in items {
                batch.append(payload)?;
            }
            self.inner
                .bind(py)
                .call_method1("push_inbound_wire_batch", (batch,))?
                .extract()
        })
        .map_err(|err| err.to_string())
    }

    pub(crate) fn outbound_ready(&self) -> Result<bool, String> {
        Python::attach(|py| -> PyResult<bool> {
            self.inner
                .bind(py)
                .call_method0("outbound_ready")?
                .extract()
        })
        .map_err(|err| err.to_string())
    }

    pub(crate) fn begin_pull_outbound_wire_batch(&self, limit: usize) -> Result<(), String> {
        Python::attach(|py| -> PyResult<()> {
            self.inner
                .bind(py)
                .call_method1("begin_pull_outbound_wire_batch", (limit,))?;
            Ok(())
        })
        .map_err(|err| err.to_string())
    }

    pub(crate) fn finish_pull_outbound_wire_batch(&self) -> Result<Vec<AcsEvent>, String> {
        Python::attach(|py| -> PyResult<Vec<AcsEvent>> {
            let events = self
                .inner
                .bind(py)
                .call_method0("finish_pull_outbound_wire_batch")?;
            events
                .try_iter()?
                .map(|item| parse_acs_wire_event(item?.cast_into::<PyDict>()?))
                .collect()
        })
        .map_err(|err| err.to_string())
    }

    pub(crate) fn stats(&self) -> Result<AcsBackendStats, String> {
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

    pub(crate) fn shutdown(&self) -> Result<(), String> {
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
