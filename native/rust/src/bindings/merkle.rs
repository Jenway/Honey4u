use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::archive::api as archive_api;
use crate::archive::wire::{EncodedShardWire, MerkleProofWire, MerkleResultWire};
use crate::crypto::merkle;

fn merkle_proof_to_wire(proof: &merkle::MerkleProof) -> MerkleProofWire {
    MerkleProofWire {
        leaf_index: proof.leaf_index,
        siblings: proof.siblings.iter().map(|sibling| sibling.to_vec()).collect(),
    }
}

fn merkle_proof_from_wire(wire: MerkleProofWire) -> PyResult<merkle::MerkleProof> {
    let mut siblings = Vec::with_capacity(wire.siblings.len());
    for sibling in wire.siblings {
        if sibling.len() != 32 {
            return Err(PyValueError::new_err(format!(
                "expected 32-byte Merkle sibling, got {}",
                sibling.len()
            )));
        }
        let mut sibling_arr = [0u8; 32];
        sibling_arr.copy_from_slice(&sibling);
        siblings.push(sibling_arr);
    }

    Ok(merkle::MerkleProof {
        leaf_index: wire.leaf_index,
        siblings,
    })
}

fn merkle_result_to_wire(result: &merkle::MerkleResult) -> MerkleResultWire {
    MerkleResultWire {
        root: result.root.to_vec(),
        shards: result.shards.clone(),
        proofs: result.proofs.iter().map(merkle_proof_to_wire).collect(),
    }
}

fn merkle_result_from_wire(wire: MerkleResultWire) -> PyResult<merkle::MerkleResult> {
    if wire.root.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "expected 32-byte Merkle root, got {}",
            wire.root.len()
        )));
    }

    let mut root = [0u8; 32];
    root.copy_from_slice(&wire.root);

    Ok(merkle::MerkleResult {
        root,
        shards: wire.shards,
        proofs: wire
            .proofs
            .into_iter()
            .map(merkle_proof_from_wire)
            .collect::<PyResult<Vec<_>>>()?,
    })
}

#[pyclass(from_py_object)]
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

    fn to_bytes(&self, py: Python<'_>) -> PyResult<Vec<u8>> {
        let wire = merkle_proof_to_wire(&self.inner);
        py.detach(move || archive_api::encode(&wire))
    }

    #[staticmethod]
    fn from_bytes(py: Python<'_>, b: &[u8]) -> PyResult<Self> {
        let payload = b.to_vec();
        let wire: MerkleProofWire = py.detach(move || archive_api::decode(&payload))?;
        let inner = merkle_proof_from_wire(wire)?;
        Ok(Self { inner })
    }
}

#[pyclass(from_py_object)]
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

    fn to_bytes(&self, py: Python<'_>) -> PyResult<Vec<u8>> {
        let wire = EncodedShardWire {
            index: self.index,
            data: self.data.clone(),
            proof: merkle_proof_to_wire(&self.proof.inner),
        };
        py.detach(move || archive_api::encode(&wire))
    }

    #[staticmethod]
    fn from_bytes(py: Python<'_>, b: &[u8]) -> PyResult<Self> {
        let payload = b.to_vec();
        let wire: EncodedShardWire = py.detach(move || archive_api::decode(&payload))?;
        Ok(Self {
            index: wire.index,
            data: wire.data,
            proof: MerkleProof {
                inner: merkle_proof_from_wire(wire.proof)?,
            },
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

    fn to_bytes(&self, py: Python<'_>) -> PyResult<Vec<u8>> {
        let wire = merkle_result_to_wire(&self.inner);
        py.detach(move || archive_api::encode(&wire))
    }

    #[staticmethod]
    fn from_bytes(py: Python<'_>, b: &[u8]) -> PyResult<Self> {
        let payload = b.to_vec();
        let wire: MerkleResultWire = py.detach(move || archive_api::decode(&payload))?;
        let inner = merkle_result_from_wire(wire)?;
        Ok(Self { inner })
    }
}

#[pyfunction]
fn merkle_encode(py: Python<'_>, data: &[u8], k: usize, n: usize) -> PyResult<MerkleResult> {
    let payload = data.to_vec();
    let inner = py.detach(move || merkle::encode(&payload, k, n))?;
    Ok(MerkleResult { inner })
}

#[pyfunction]
fn merkle_verify(py: Python<'_>, shard: &[u8], proof: &MerkleProof, root: &[u8]) -> PyResult<bool> {
    if root.len() != 32 {
        return Err(PyValueError::new_err("Root must be 32 bytes"));
    }

    let mut root_arr = [0u8; 32];
    root_arr.copy_from_slice(root);
    let shard = shard.to_vec();
    let proof = proof.inner.clone();
    py.detach(move || Ok(merkle::verify_shard(&shard, &proof, &root_arr)))
}

#[pyfunction]
fn merkle_decode(
    py: Python<'_>,
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

    py.detach(move || {
        merkle::decode_owned(inner, &root_arr, k, n)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    })
}

#[pyfunction]
fn merkle_decode_dicts(
    py: Python<'_>,
    stripes: &Bound<'_, PyDict>,
    proofs: &Bound<'_, PyDict>,
    root: &[u8],
    k: usize,
    n: usize,
) -> PyResult<Vec<u8>> {
    if root.len() != 32 {
        return Err(PyValueError::new_err("Root must be 32 bytes"));
    }

    let mut root_arr = [0u8; 32];
    root_arr.copy_from_slice(root);

    let mut inner = Vec::with_capacity(stripes.len());
    for (idx_any, shard_any) in stripes.iter() {
        let idx = idx_any.extract::<usize>()?;
        let shard = shard_any.extract::<Vec<u8>>()?;
        let Some(proof_any) = proofs.get_item(idx)? else {
            continue;
        };
        let proof_bytes = proof_any.extract::<Vec<u8>>()?;
        let proof_wire: MerkleProofWire = archive_api::decode(&proof_bytes)?;
        let proof = merkle_proof_from_wire(proof_wire)?;
        inner.push((idx, shard, proof));
    }

    py.detach(move || {
        merkle::decode_trusted_owned(inner, &root_arr, k, n)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    })
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<MerkleProof>()?;
    m.add_class::<EncodedShard>()?;
    m.add_class::<MerkleResult>()?;
    m.add_function(wrap_pyfunction!(merkle_encode, m)?)?;
    m.add_function(wrap_pyfunction!(merkle_verify, m)?)?;
    m.add_function(wrap_pyfunction!(merkle_decode, m)?)?;
    m.add_function(wrap_pyfunction!(merkle_decode_dicts, m)?)?;
    Ok(())
}
