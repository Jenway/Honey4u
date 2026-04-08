use super::*;

type PyAcsInboundItem = (usize, usize, String, Option<usize>, Py<PyAny>);

pub(crate) trait RustDrivenAcsHost {
    fn pid(&self) -> usize;
    fn start_round(&self, round_id: usize, sid: &str, proposal_input: &[u8]) -> Result<(), String>;
    fn push_inbound_batch(&self, items: &[PyAcsInboundItem]) -> Result<usize, String>;
    fn begin_pull_outbound_batch(&self, limit: usize) -> Result<(), String>;
    fn finish_pull_outbound_batch(&self) -> Result<Vec<PyAcsEvent>, String>;
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
            let module = PyModule::import(py, "honey_runtime.drivers.python_acs_bridge")?;
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

    pub(crate) fn push_inbound_batch(&self, items: &[PyAcsInboundItem]) -> Result<usize, String> {
        Python::attach(|py| -> PyResult<usize> {
            let batch = pyo3::types::PyList::empty(py);
            for (sender, round_id, channel, instance_id, message) in items {
                batch.append((
                    *sender,
                    *round_id,
                    channel.as_str(),
                    *instance_id,
                    message.bind(py),
                ))?;
            }
            self.inner
                .bind(py)
                .call_method1("push_inbound_batch", (batch,))?
                .extract()
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

    pub(crate) fn begin_pull_outbound_batch(&self, limit: usize) -> Result<(), String> {
        Python::attach(|py| -> PyResult<()> {
            self.inner
                .bind(py)
                .call_method1("begin_pull_outbound_batch", (limit,))?;
            Ok(())
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

    pub(crate) fn finish_pull_outbound_batch(&self) -> Result<Vec<PyAcsEvent>, String> {
        Python::attach(|py| -> PyResult<Vec<PyAcsEvent>> {
            let events = self
                .inner
                .bind(py)
                .call_method0("finish_pull_outbound_batch")?;
            events
                .try_iter()?
                .map(|item| parse_acs_event(item?.cast_into::<PyDict>()?))
                .collect()
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
            let exchange_timing =
                dict_item(&stats, "exchange_timing_seconds")?.cast_into::<PyDict>()?;
            Ok(PyAcsHostStats {
                worker_ident: dict_item(&stats, "worker_ident")?.extract()?,
                rounds_started: dict_item(&stats, "rounds_started")?.extract()?,
                rounds_finished: dict_item(&stats, "rounds_finished")?.extract()?,
                processed_commands: dict_item(&stats, "processed_commands")?.extract()?,
                bridge_queue_size: dict_item(&stats, "bridge_queue_size")?.extract()?,
                worker_running: dict_item(&stats, "worker_running")?.extract()?,
                worker_error: dict_item(&stats, "worker_error")?.extract()?,
                start_round_calls: dict_item(&command_counts, "start_round")?.extract()?,
                push_inbound_batch_calls: dict_item(&command_counts, "push_inbound_batch")?
                    .extract()?,
                push_inbound_batch_items: dict_item(
                    &batch_item_counts,
                    "push_inbound_batch_items",
                )?
                .extract()?,
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
                exchange_batches_calls: dict_item(&command_counts, "exchange_batches")?
                    .extract()?,
                exchange_inbound_items: dict_item(&batch_item_counts, "exchange_inbound_items")?
                    .extract()?,
                exchange_outbound_items: dict_item(&batch_item_counts, "exchange_outbound_items")?
                    .extract()?,
                pull_outbound_batch_calls: dict_item(&command_counts, "pull_outbound_batch")?
                    .extract()?,
                pull_outbound_batch_items: dict_item(
                    &batch_item_counts,
                    "pull_outbound_batch_items",
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
                exchange_deliver_seconds: dict_item(&exchange_timing, "deliver")?.extract()?,
                exchange_pump_seconds: dict_item(&exchange_timing, "pump")?.extract()?,
                exchange_drain_seconds: dict_item(&exchange_timing, "drain")?.extract()?,
                exchange_total_seconds: dict_item(&exchange_timing, "total")?.extract()?,
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

    fn push_inbound_batch(&self, items: &[PyAcsInboundItem]) -> Result<usize, String> {
        PyAcsHost::push_inbound_batch(self, items)
    }

    fn begin_pull_outbound_batch(&self, limit: usize) -> Result<(), String> {
        PyAcsHost::begin_pull_outbound_batch(self, limit)
    }

    fn finish_pull_outbound_batch(&self) -> Result<Vec<PyAcsEvent>, String> {
        PyAcsHost::finish_pull_outbound_batch(self)
    }

    fn stats(&self) -> Result<PyAcsHostStats, String> {
        PyAcsHost::stats(self)
    }

    fn shutdown(&self) -> Result<(), String> {
        PyAcsHost::shutdown(self)
    }
}
