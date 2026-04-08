use super::*;

pub(crate) trait RustDrivenAcsHost {
    fn pid(&self) -> usize;
    fn start_round(&self, round_id: usize, sid: &str, proposal_input: &[u8]) -> Result<(), String>;
    fn push_inbound_wire_batch(&self, items: &[Vec<u8>]) -> Result<usize, String>;
    fn begin_pull_outbound_wire_batch(&self, limit: usize) -> Result<(), String>;
    fn finish_pull_outbound_wire_batch(&self) -> Result<Vec<PyAcsWireEvent>, String>;
    fn take_round_broadcast_outputs(&self, round_id: usize) -> Result<Vec<PyAcsWireEvent>, String>;
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

    pub(crate) fn take_round_broadcast_outputs(
        &self,
        round_id: usize,
    ) -> Result<Vec<PyAcsWireEvent>, String> {
        Python::attach(|py| -> PyResult<Vec<PyAcsWireEvent>> {
            let events = self
                .inner
                .bind(py)
                .call_method1("take_round_broadcast_outputs", (round_id,))?;
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

    fn take_round_broadcast_outputs(&self, round_id: usize) -> Result<Vec<PyAcsWireEvent>, String> {
        PyAcsHost::take_round_broadcast_outputs(self, round_id)
    }

    fn stats(&self) -> Result<PyAcsHostStats, String> {
        PyAcsHost::stats(self)
    }

    fn shutdown(&self) -> Result<(), String> {
        PyAcsHost::shutdown(self)
    }
}
