use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use runtime_core::transport::LocalTcpTransport as CoreLocalTcpTransport;

#[pyclass]
pub struct LocalTcpTransport {
    inner: CoreLocalTcpTransport,
}

#[pymethods]
impl LocalTcpTransport {
    #[new]
    fn new(pid: usize, addresses: Vec<(String, u16)>) -> PyResult<Self> {
        let inner = CoreLocalTcpTransport::new(pid, addresses).map_err(|e| {
            PyValueError::new_err(format!("failed to create local tcp transport: {e}"))
        })?;
        Ok(Self { inner })
    }

    fn send(&self, recipient: usize, payload: &[u8]) -> PyResult<()> {
        self.inner
            .send(recipient, payload)
            .map_err(|e| PyValueError::new_err(format!("transport send failed: {e}")))
    }

    #[pyo3(signature = (max_items))]
    fn recv_batch(&self, max_items: usize) -> PyResult<Vec<Vec<u8>>> {
        self.inner
            .recv_batch(max_items)
            .map_err(|e| PyValueError::new_err(format!("transport recv failed: {e}")))
    }

    fn pending_inbound(&self) -> usize {
        self.inner.pending_inbound()
    }

    fn pending_outbound(&self) -> usize {
        self.inner.pending_outbound()
    }

    fn wakeup_seq(&self) -> u64 {
        runtime_core::transport::TransportHandle::wakeup_seq(&self.inner)
    }

    fn stats(&self) -> PyResult<Py<PyAny>> {
        let stats = self.inner.stats();
        Python::attach(|py| {
            let dict = pyo3::types::PyDict::new(py);
            dict.set_item("sent_frames", stats.sent_frames)?;
            dict.set_item("recv_frames", stats.recv_frames)?;
            dict.set_item("connect_retries", stats.connect_retries)?;
            dict.set_item("send_retries", stats.send_retries)?;
            Ok(dict.into_any().unbind())
        })
    }

    fn close(&mut self) -> PyResult<()> {
        self.inner
            .close()
            .map_err(|e| PyValueError::new_err(format!("transport close failed: {e}")))
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<LocalTcpTransport>()?;
    Ok(())
}
