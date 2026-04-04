use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
use std::collections::{HashMap, HashSet, VecDeque};

use crate::archive::api as archive_api;
use crate::archive::wire::TxBatchWire;

struct TxEntry {
    tx_id: String,
    payload: Vec<u8>,
}

#[pyclass]
pub struct TxPool {
    queued: VecDeque<TxEntry>,
    queued_ids: HashSet<String>,
    inflight: HashMap<String, Vec<u8>>,
}

impl TxPool {
    fn encode_json_string_bytes(value: &str) -> Result<Vec<u8>, String> {
        serde_json::to_vec(value).map_err(|e| e.to_string())
    }

    fn push_inner(&mut self, tx_id: String, payload: Vec<u8>) -> Result<(), &'static str> {
        if self.queued_ids.contains(&tx_id) || self.inflight.contains_key(&tx_id) {
            return Err("duplicate tx_id");
        }
        self.queued_ids.insert(tx_id.clone());
        self.queued.push_back(TxEntry { tx_id, payload });
        Ok(())
    }

    fn pop_batch_inner(
        &mut self,
        max_items: usize,
        max_bytes: usize,
    ) -> Result<(Vec<String>, Vec<u8>), String> {
        if max_items == 0 || self.queued.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }

        let mut selected = Vec::new();
        let mut used_bytes = 0usize;

        while selected.len() < max_items {
            let Some(front) = self.queued.front() else {
                break;
            };
            let next_size = front.payload.len();
            if !selected.is_empty() && max_bytes > 0 && used_bytes + next_size > max_bytes {
                break;
            }

            let entry = self.queued.pop_front().expect("queue front must exist");
            let tx_id = entry.tx_id;
            used_bytes += entry.payload.len();
            self.queued_ids.remove(&tx_id);
            selected.push(tx_id.clone());
            self.inflight.insert(tx_id, entry.payload);
        }

        let items: Vec<Vec<u8>> = selected
            .iter()
            .map(|tx_id| {
                self.inflight
                    .get(tx_id)
                    .expect("selected tx must exist in inflight")
                    .clone()
            })
            .collect();

        let payload = archive_api::encode(&TxBatchWire { items }).map_err(|e| e.to_string())?;

        Ok((selected, payload))
    }

    fn requeue_inner(&mut self, tx_ids: Vec<String>) -> Result<(), &'static str> {
        for tx_id in tx_ids.into_iter().rev() {
            let Some(payload) = self.inflight.remove(&tx_id) else {
                return Err("unknown inflight tx_id");
            };
            self.queued_ids.insert(tx_id.clone());
            self.queued.push_front(TxEntry { tx_id, payload });
        }
        Ok(())
    }

    fn drop_inflight_inner(&mut self, tx_ids: Vec<String>) -> Result<(), &'static str> {
        for tx_id in tx_ids {
            if self.inflight.remove(&tx_id).is_none() {
                return Err("unknown inflight tx_id");
            }
        }
        Ok(())
    }

    fn resolve_delivery_inner(
        &mut self,
        tx_ids: Vec<String>,
        final_block_payload: Vec<u8>,
    ) -> Result<(Vec<String>, Vec<String>), String> {
        let wire: TxBatchWire =
            archive_api::decode(&final_block_payload).map_err(|e| e.to_string())?;
        let mut delivered_counts: HashMap<Vec<u8>, usize> = HashMap::new();
        for payload in wire.items {
            *delivered_counts.entry(payload).or_default() += 1;
        }

        let mut retry_ids = Vec::new();
        let mut delivered_ids = Vec::new();
        for tx_id in tx_ids {
            let payload = self
                .inflight
                .get(&tx_id)
                .ok_or_else(|| format!("unknown inflight tx_id: {tx_id}"))?;
            if let Some(remaining) = delivered_counts.get_mut(payload.as_slice())
                && *remaining > 0
            {
                *remaining -= 1;
                delivered_ids.push(tx_id);
                continue;
            }
            retry_ids.push(tx_id);
        }

        self.drop_inflight_inner(delivered_ids.clone())
            .map_err(|e| e.to_string())?;
        self.requeue_inner(retry_ids.clone())
            .map_err(|e| e.to_string())?;
        Ok((retry_ids, delivered_ids))
    }
}

#[pymethods]
impl TxPool {
    #[new]
    fn new() -> Self {
        Self {
            queued: VecDeque::new(),
            queued_ids: HashSet::new(),
            inflight: HashMap::new(),
        }
    }

    fn len(&self) -> usize {
        self.queued.len()
    }

    fn inflight_len(&self) -> usize {
        self.inflight.len()
    }

    fn push(&mut self, py: Python<'_>, tx_id: String, payload: &[u8]) -> PyResult<()> {
        let payload = payload.to_vec();
        py.detach(move || self.push_inner(tx_id, payload))
            .map_err(PyValueError::new_err)
    }

    fn push_json_str(&mut self, py: Python<'_>, tx_id: String, value: &str) -> PyResult<()> {
        let value = value.to_owned();
        py.detach(move || {
            let payload =
                Self::encode_json_string_bytes(&value).map_err(|_| "invalid tx string")?;
            self.push_inner(tx_id, payload)
        })
        .map_err(PyValueError::new_err)
    }

    fn pop_batch(
        &mut self,
        py: Python<'_>,
        max_items: usize,
        max_bytes: usize,
    ) -> PyResult<(Vec<String>, Vec<u8>)> {
        py.detach(move || self.pop_batch_inner(max_items, max_bytes))
            .map_err(PyValueError::new_err)
    }

    fn requeue(&mut self, py: Python<'_>, tx_ids: Vec<String>) -> PyResult<()> {
        py.detach(move || self.requeue_inner(tx_ids))
            .map_err(PyValueError::new_err)
    }

    fn drop_inflight(&mut self, py: Python<'_>, tx_ids: Vec<String>) -> PyResult<()> {
        py.detach(move || self.drop_inflight_inner(tx_ids))
            .map_err(PyValueError::new_err)
    }

    fn resolve_delivery(
        &mut self,
        py: Python<'_>,
        tx_ids: Vec<String>,
        final_block_payload: &[u8],
    ) -> PyResult<(Vec<String>, Vec<String>)> {
        let final_block_payload = final_block_payload.to_vec();
        py.detach(move || self.resolve_delivery_inner(tx_ids, final_block_payload))
            .map_err(PyValueError::new_err)
    }
}

#[pyfunction]
fn encode_json_string(py: Python<'_>, value: &str) -> PyResult<Vec<u8>> {
    let value = value.to_owned();
    py.detach(move || TxPool::encode_json_string_bytes(&value))
        .map_err(PyValueError::new_err)
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<TxPool>()?;
    m.add_function(wrap_pyfunction!(encode_json_string, m)?)?;
    Ok(())
}
