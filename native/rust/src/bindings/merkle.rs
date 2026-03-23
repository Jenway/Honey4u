use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};

use crate::crypto::merkle;

#[derive(Serialize, Deserialize)]
struct EncodedShardWire {
    index: usize,
    data: Vec<u8>,
    proof: merkle::MerkleProof,
}

#[pyclass]
#[derive(Clone)]
pub struct MerkleProof {
    pub(crate) inner: merkle::MerkleProof,
}

#[pymethods]
impl MerkleProof {
    #[getter]
    fn leaf_index(&self) -> usize {
        self.inner.leaf_index
    }

    #[getter]
    fn siblings(&self) -> Vec<Vec<u8>> {
        self.inner.siblings.iter().map(|s| s.to_vec()).collect()
    }

    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        bincode::serialize(&self.inner).map_err(|e| PyValueError::new_err(e.to_string()))
    }

    #[staticmethod]
    fn from_bytes(b: &[u8]) -> PyResult<Self> {
        let inner: merkle::MerkleProof =
            bincode::deserialize(b).map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self { inner })
    }
}

#[pyclass]
#[derive(Clone)]
pub struct EncodedShard {
    index: usize,
    data: Vec<u8>,
    proof: MerkleProof,
}

#[pymethods]
impl EncodedShard {
    #[new]
    fn new(index: usize, data: Vec<u8>, proof: MerkleProof) -> Self {
        Self { index, data, proof }
    }

    #[getter]
    fn index(&self) -> usize {
        self.index
    }

    #[getter]
    fn data(&self) -> Vec<u8> {
        self.data.clone()
    }

    #[getter]
    fn proof(&self) -> MerkleProof {
        self.proof.clone()
    }

    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        let wire = EncodedShardWire {
            index: self.index,
            data: self.data.clone(),
            proof: self.proof.inner.clone(),
        };
        bincode::serialize(&wire).map_err(|e| PyValueError::new_err(e.to_string()))
    }

    #[staticmethod]
    fn from_bytes(b: &[u8]) -> PyResult<Self> {
        let wire: EncodedShardWire =
            bincode::deserialize(b).map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self {
            index: wire.index,
            data: wire.data,
            proof: MerkleProof { inner: wire.proof },
        })
    }
}

#[pyclass]
pub struct MerkleResult {
    pub(crate) inner: merkle::MerkleResult,
}

#[pymethods]
impl MerkleResult {
    #[getter]
    fn root(&self) -> Vec<u8> {
        self.inner.root.to_vec()
    }

    #[getter]
    fn shards(&self) -> Vec<Vec<u8>> {
        self.inner.shards.clone()
    }

    #[getter]
    fn proofs(&self) -> Vec<MerkleProof> {
        self.inner
            .proofs
            .iter()
            .cloned()
            .map(|p| MerkleProof { inner: p })
            .collect()
    }

    fn shard(&self, i: usize) -> PyResult<Vec<u8>> {
        self.inner
            .shards
            .get(i)
            .cloned()
            .ok_or_else(|| PyValueError::new_err("index out of bounds"))
    }

    fn proof(&self, i: usize) -> PyResult<MerkleProof> {
        self.inner
            .proofs
            .get(i)
            .cloned()
            .map(|p| MerkleProof { inner: p })
            .ok_or_else(|| PyValueError::new_err("index out of bounds"))
    }

    fn encoded_shard(&self, i: usize) -> PyResult<EncodedShard> {
        let data = self
            .inner
            .shards
            .get(i)
            .cloned()
            .ok_or_else(|| PyValueError::new_err("index out of bounds"))?;

        let proof = self
            .inner
            .proofs
            .get(i)
            .cloned()
            .ok_or_else(|| PyValueError::new_err("index out of bounds"))?;

        Ok(EncodedShard {
            index: i,
            data,
            proof: MerkleProof { inner: proof },
        })
    }

    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        bincode::serialize(&self.inner).map_err(|e| PyValueError::new_err(e.to_string()))
    }

    #[staticmethod]
    fn from_bytes(b: &[u8]) -> PyResult<Self> {
        let inner: merkle::MerkleResult =
            bincode::deserialize(b).map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self { inner })
    }
}

#[pyfunction]
fn merkle_encode(data: &[u8], k: usize, n: usize) -> PyResult<MerkleResult> {
    let inner = merkle::encode(data, k, n)?;
    Ok(MerkleResult { inner })
}

#[pyfunction]
fn merkle_verify(shard: &[u8], proof: &MerkleProof, root: &[u8]) -> PyResult<bool> {
    if root.len() != 32 {
        return Err(PyValueError::new_err("Root must be 32 bytes"));
    }

    let mut root_arr = [0u8; 32];
    root_arr.copy_from_slice(root);

    Ok(merkle::verify_shard(shard, &proof.inner, &root_arr))
}

#[pyfunction]
fn merkle_decode(
    available: Vec<EncodedShard>,
    root: &[u8],
    k: usize,
    n: usize,
) -> PyResult<Vec<u8>> {
    if root.len() != 32 {
        return Err(PyValueError::new_err("Root must be 32 bytes"));
    }

    let mut root_arr = [0u8; 32];
    root_arr.copy_from_slice(root);

    let mut inner = Vec::with_capacity(available.len());
    for s in available {
        inner.push((s.index, s.data, s.proof.inner));
    }

    merkle::decode(&inner, &root_arr, k, n).map_err(|e| PyValueError::new_err(e.to_string()))
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<MerkleProof>()?;
    m.add_class::<EncodedShard>()?;
    m.add_class::<MerkleResult>()?;
    m.add_function(wrap_pyfunction!(merkle_encode, m)?)?;
    m.add_function(wrap_pyfunction!(merkle_verify, m)?)?;
    m.add_function(wrap_pyfunction!(merkle_decode, m)?)?;
    Ok(())
}
