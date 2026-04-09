use super::*;

// ---------------------------------------------------------------------------
// Python IPC wire types
// These types define the data exchanged between the Rust driver and the Python
// ACS host over the PyO3 GIL-locked call boundary.
// ---------------------------------------------------------------------------

/// A single carry-over item from a Dumbo ACS round (PRBC outputs not included
/// in the ACS decision but eligible for reuse in the next round).
pub(crate) struct CarryoverItem {
    pub(crate) leader: u32,
    pub(crate) value: Vec<u8>,
    pub(crate) roothash: Vec<u8>,
    pub(crate) proof_payload: Vec<u8>,
}

pub(crate) struct PyAcsHost {
    pub(crate) pid: usize,
    pub(crate) inner: Py<PyAny>,
}

pub(crate) struct PyAcsHostStats {
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

pub(crate) enum PyAcsWireEvent {
    Send {
        round_id: usize,
        recipient: usize,
        payload: Vec<u8>,
    },
    BroadcastSend {
        round_id: usize,
        payload: Vec<u8>,
        include_self: bool,
    },
    Decision {
        round_id: usize,
        /// Set when `output_mode = "selected_pids"` (HB / bench mode).
        selected_pids: Vec<usize>,
        /// Set when `output_mode = "payloads"` (Dumbo drive mode with pool reuse).
        selected_payloads: Option<Vec<Option<Vec<u8>>>>,
    },
    Failure {
        round_id: isize,
        error: String,
        exception_type: String,
    },
    Carryovers {
        round_id: usize,
        /// Carry-over items from Dumbo with pool reuse enabled.
        items: Vec<CarryoverItem>,
    },
    BroadcastOutput {
        round_id: usize,
        sender: usize,
        payload: Vec<u8>,
        roothash: Vec<u8>,
    },
}

#[allow(dead_code)]
pub(crate) struct AcsRoundOutcome {
    pub(crate) selected_pids: Vec<usize>,
    /// Raw payloads from a Dumbo `"payloads"` output-mode decision event.
    /// Empty when running in `"selected_pids"` mode (HB).
    pub(crate) selected_payloads: Vec<Option<Vec<u8>>>,
    /// Carry-over items from Dumbo with pool reuse enabled.
    /// Empty when pool reuse is disabled or when running HB.
    pub(crate) carryovers: Vec<CarryoverItem>,
    pub(crate) send_events: usize,
    pub(crate) drive_stats: DriverPhaseStats,
    pub(crate) settle_stats: DriverPhaseStats,
}

#[allow(dead_code)]
pub(crate) struct HbBlockOutcome {
    pub(crate) block_payload: Vec<u8>,
    pub(crate) tpke_bundle_events: usize,
    pub(crate) local_share_seconds: f64,
    pub(crate) combine_seconds: f64,
}

// ---------------------------------------------------------------------------
// Python IPC helpers
// ---------------------------------------------------------------------------

fn dict_item<'py>(dict: &Bound<'py, PyDict>, key: &str) -> PyResult<Bound<'py, PyAny>> {
    dict.get_item(key)?
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err(format!("missing key: {key}")))
}

fn parse_acs_wire_event(dict: Bound<'_, PyDict>) -> PyResult<PyAcsWireEvent> {
    let kind = dict_item(&dict, "kind")?.extract::<String>()?;
    match kind.as_str() {
        "send" => Ok(PyAcsWireEvent::Send {
            round_id: dict_item(&dict, "round_id")?.extract()?,
            recipient: dict_item(&dict, "recipient")?.extract()?,
            payload: dict_item(&dict, "payload")?.extract()?,
        }),
        "broadcast_send" => Ok(PyAcsWireEvent::BroadcastSend {
            round_id: dict_item(&dict, "round_id")?.extract()?,
            payload: dict_item(&dict, "payload")?.extract()?,
            include_self: dict
                .get_item("include_self")?
                .map(|value| value.extract::<bool>())
                .transpose()?
                .unwrap_or(true),
        }),
        "decision" => {
            let round_id = dict_item(&dict, "round_id")?.extract()?;
            // `selected_pids` is present in HB / "selected_pids" output mode.
            // In Dumbo "payloads" mode this key may be absent.
            let selected_pids = if let Some(pids_val) = dict.get_item("selected_pids")? {
                pids_val
                    .try_iter()?
                    .map(|item| item?.extract::<usize>())
                    .collect::<PyResult<Vec<_>>>()?
            } else {
                Vec::new()
            };
            // `selected_payloads` is present in Dumbo "payloads" output mode.
            let selected_payloads =
                if let Some(payloads_val) = dict.get_item("selected_payloads")? {
                    Some(
                        payloads_val
                            .try_iter()?
                            .map(|item| item?.extract::<Option<Vec<u8>>>())
                            .collect::<PyResult<Vec<_>>>()?,
                    )
                } else {
                    None
                };
            Ok(PyAcsWireEvent::Decision {
                round_id,
                selected_pids,
                selected_payloads,
            })
        }
        "failure" => Ok(PyAcsWireEvent::Failure {
            round_id: dict_item(&dict, "round_id")?.extract()?,
            error: dict_item(&dict, "error")?.extract()?,
            exception_type: dict_item(&dict, "exception_type")?.extract()?,
        }),
        "carryovers" => {
            let round_id = dict_item(&dict, "round_id")?.extract()?;
            // `items` is present when pool reuse is enabled.
            let items = if let Some(items_val) = dict.get_item("items")? {
                items_val
                    .try_iter()?
                    .map(|item| {
                        let item = item?;
                        let d = item.extract::<Bound<'_, PyDict>>().map_err(|_| {
                            pyo3::exceptions::PyTypeError::new_err("carryover item must be a dict")
                        })?;
                        Ok(CarryoverItem {
                            leader: dict_item(&d, "leader")?.extract()?,
                            value: dict_item(&d, "value")?.extract()?,
                            roothash: dict_item(&d, "roothash")?.extract()?,
                            proof_payload: dict_item(&d, "proof_payload")?.extract()?,
                        })
                    })
                    .collect::<PyResult<Vec<_>>>()?
            } else {
                Vec::new()
            };
            Ok(PyAcsWireEvent::Carryovers { round_id, items })
        }
        "broadcast_output" => Ok(PyAcsWireEvent::BroadcastOutput {
            round_id: dict_item(&dict, "round_id")?.extract()?,
            sender: dict_item(&dict, "sender")?.extract()?,
            payload: dict_item(&dict, "payload")?.extract()?,
            roothash: dict_item(&dict, "roothash")?.extract()?,
        }),
        _ => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "unknown ACS wire event kind: {kind}"
        ))),
    }
}

// ---------------------------------------------------------------------------

#[allow(dead_code)]
pub(crate) trait RustDrivenAcsHost {
    fn pid(&self) -> usize;
    fn start_round(&self, round_id: usize, sid: &str, proposal_input: &[u8]) -> Result<(), String>;
    fn push_inbound_wire_batch(&self, items: &[Vec<u8>]) -> Result<usize, String>;
    fn begin_pull_outbound_wire_batch(&self, limit: usize) -> Result<(), String>;
    fn finish_pull_outbound_wire_batch(&self) -> Result<Vec<PyAcsWireEvent>, String>;
    fn stats(&self) -> Result<PyAcsHostStats, String>;
    fn shutdown(&self) -> Result<(), String>;
}

impl PyAcsHost {
    pub(crate) fn new(
        protocol: Protocol,
        pid: usize,
        nodes: usize,
        faulty: usize,
        crypto_json: &str,
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
            kwargs.set_item("crypto_json", crypto_json)?;
            kwargs.set_item("config_json", config_json)?;
            let host = module
                .getattr("build_persistent_acs_host_from_json")?
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

    pub(crate) fn finish_pull_outbound_wire_batch(&self) -> Result<Vec<PyAcsWireEvent>, String> {
        Python::attach(|py| -> PyResult<Vec<PyAcsWireEvent>> {
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

    pub(crate) fn stats(&self) -> Result<PyAcsHostStats, String> {
        Python::attach(|py| -> PyResult<PyAcsHostStats> {
            let stats = self
                .inner
                .bind(py)
                .call_method0("stats")?
                .cast_into::<PyDict>()?;
            let command_counts = dict_item(&stats, "command_counts")?.cast_into::<PyDict>()?;
            let batch_item_counts =
                dict_item(&stats, "batch_item_counts")?.cast_into::<PyDict>()?;
            Ok(PyAcsHostStats {
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

impl RustDrivenAcsHost for PyAcsHost {
    fn pid(&self) -> usize {
        self.pid
    }

    fn start_round(&self, round_id: usize, sid: &str, proposal_input: &[u8]) -> Result<(), String> {
        PyAcsHost::start_round(self, round_id, sid, proposal_input)
    }

    fn push_inbound_wire_batch(&self, items: &[Vec<u8>]) -> Result<usize, String> {
        PyAcsHost::push_inbound_wire_batch(self, items)
    }

    fn begin_pull_outbound_wire_batch(&self, limit: usize) -> Result<(), String> {
        PyAcsHost::begin_pull_outbound_wire_batch(self, limit)
    }

    fn finish_pull_outbound_wire_batch(&self) -> Result<Vec<PyAcsWireEvent>, String> {
        PyAcsHost::finish_pull_outbound_wire_batch(self)
    }

    fn stats(&self) -> Result<PyAcsHostStats, String> {
        PyAcsHost::stats(self)
    }

    fn shutdown(&self) -> Result<(), String> {
        PyAcsHost::shutdown(self)
    }
}
