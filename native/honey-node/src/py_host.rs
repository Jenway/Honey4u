use super::*;

pub(crate) trait RustDrivenAcsHost {
    fn pid(&self) -> usize;
    fn start_round(&self, round_id: usize, sid: &str, local_input: &[u8]) -> Result<(), String>;
    fn deliver_decoded(
        &self,
        sender: usize,
        round_id: usize,
        channel: &str,
        instance_id: Option<usize>,
        message: &Py<PyAny>,
    ) -> Result<(), String>;
    fn drain_events(&self, limit: usize) -> Result<Vec<PyAcsEvent>, String>;
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
            let module = PyModule::import(py, "honey.host.acs_host")?;
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
        local_input: &[u8],
    ) -> Result<(), String> {
        Python::attach(|py| -> PyResult<()> {
            let kwargs = PyDict::new(py);
            kwargs.set_item("round_id", round_id)?;
            kwargs.set_item("sid", sid)?;
            kwargs.set_item("local_input", local_input)?;
            self.inner
                .bind(py)
                .call_method("submit_start_round", (), Some(&kwargs))?;
            Ok(())
        })
        .map_err(|err| err.to_string())
    }

    pub(crate) fn deliver_raw(&self, payload: &[u8]) -> Result<(), String> {
        Python::attach(|py| -> PyResult<()> {
            self.inner
                .bind(py)
                .call_method1("submit_deliver", (payload,))?;
            Ok(())
        })
        .map_err(|err| err.to_string())
    }

    pub(crate) fn deliver_raw_batch(&self, payloads: &[Vec<u8>]) -> Result<(), String> {
        if payloads.is_empty() {
            return Ok(());
        }

        Python::attach(|py| -> PyResult<()> {
            self.inner
                .bind(py)
                .call_method1("submit_deliver_batch", (payloads.to_vec(),))?;
            Ok(())
        })
        .map_err(|err| err.to_string())
    }

    pub(crate) fn deliver_decoded(
        &self,
        sender: usize,
        round_id: usize,
        channel: &str,
        instance_id: Option<usize>,
        message: &Py<PyAny>,
    ) -> Result<(), String> {
        Python::attach(|py| -> PyResult<()> {
            let kwargs = PyDict::new(py);
            kwargs.set_item("sender", sender)?;
            kwargs.set_item("round_id", round_id)?;
            kwargs.set_item("channel", channel)?;
            kwargs.set_item("instance_id", instance_id)?;
            kwargs.set_item("message", message.bind(py))?;
            self.inner
                .bind(py)
                .call_method("submit_deliver_decoded", (), Some(&kwargs))?;
            Ok(())
        })
        .map_err(|err| err.to_string())
    }

    pub(crate) fn drain_events(&self, limit: usize) -> Result<Vec<PyAcsEvent>, String> {
        Python::attach(|py| -> PyResult<Vec<PyAcsEvent>> {
            let events = self.inner.bind(py).call_method1("drain_events", (limit,))?;
            events
                .try_iter()?
                .map(|item| parse_acs_event(item?.cast_into::<PyDict>()?))
                .collect()
        })
        .map_err(|err| err.to_string())
    }

    pub(crate) fn stats(&self) -> Result<PyAcsHostStats, String> {
        Python::attach(|py| -> PyResult<PyAcsHostStats> {
            let stats = self
                .inner
                .bind(py)
                .call_method0("bridge_stats")?
                .cast_into::<PyDict>()?;
            Ok(PyAcsHostStats {
                worker_ident: dict_item(&stats, "worker_ident")?.extract()?,
                rounds_started: dict_item(&stats, "rounds_started")?.extract()?,
                rounds_finished: dict_item(&stats, "rounds_finished")?.extract()?,
                processed_commands: dict_item(&stats, "processed_commands")?.extract()?,
                bridge_queue_size: dict_item(&stats, "bridge_queue_size")?.extract()?,
                worker_running: dict_item(&stats, "worker_running")?.extract()?,
                worker_error: dict_item(&stats, "worker_error")?.extract()?,
            })
        })
        .map_err(|err| err.to_string())
    }

    pub(crate) fn shutdown(&self) -> Result<(), String> {
        Python::attach(|py| -> PyResult<()> {
            self.inner.bind(py).call_method0("close_bridge")?;
            Ok(())
        })
        .map_err(|err| err.to_string())
    }
}

impl RustDrivenAcsHost for PyAcsHost {
    fn pid(&self) -> usize {
        self.pid
    }

    fn start_round(&self, round_id: usize, sid: &str, local_input: &[u8]) -> Result<(), String> {
        PyAcsHost::start_round(self, round_id, sid, local_input)
    }

    fn deliver_decoded(
        &self,
        sender: usize,
        round_id: usize,
        channel: &str,
        instance_id: Option<usize>,
        message: &Py<PyAny>,
    ) -> Result<(), String> {
        PyAcsHost::deliver_decoded(self, sender, round_id, channel, instance_id, message)
    }

    fn drain_events(&self, limit: usize) -> Result<Vec<PyAcsEvent>, String> {
        PyAcsHost::drain_events(self, limit)
    }

    fn stats(&self) -> Result<PyAcsHostStats, String> {
        PyAcsHost::stats(self)
    }

    fn shutdown(&self) -> Result<(), String> {
        PyAcsHost::shutdown(self)
    }
}

impl HbNodeRuntime {
    pub(crate) fn new(acs_host: PyAcsHost, tpke_private_share: HbPkePrivateKeyShare) -> Self {
        Self {
            acs_host,
            tpke_private_share,
        }
    }

    pub(crate) fn tpke_private_share(&self) -> &HbPkePrivateKeyShare {
        &self.tpke_private_share
    }
}
