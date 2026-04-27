use super::*;

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct PrbcProof {
    pub(super) roothash: [u8; 32],
    pub(super) sigmas: Vec<(usize, Vec<u8>)>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct ThresholdProof {
    pub(super) roothash: [u8; 32],
    pub(super) signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct PdStoreRecord {
    pub(super) roothash: [u8; 32],
    pub(super) stripe_owner: u32,
    pub(super) stripe: Vec<u8>,
    pub(super) merkle_proof: MerkleProof,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(super) enum DumboCoinScope {
    Election { permutation_round: u32 },
    Aba { mvba_round: u32, epoch: u32 },
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct RustDumboEnvelope {
    pub(super) round_id: u32,
    pub(super) sender: u32,
    pub(super) message: RustDumboMessage,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) enum RustDumboMessage {
    PrbcVal {
        leader: u32,
        roothash: [u8; 32],
        proof: MerkleProof,
        stripe: Vec<u8>,
        stripe_index: u32,
    },
    PrbcEcho {
        leader: u32,
        roothash: [u8; 32],
        proof: MerkleProof,
        stripe: Vec<u8>,
        stripe_index: u32,
    },
    PrbcReady {
        leader: u32,
        roothash: [u8; 32],
        signature: Vec<u8>,
    },
    ProofDiffuse {
        leader: u32,
        proof: PrbcProof,
    },
    PdStore {
        leader: u32,
        roothash: [u8; 32],
        stripe: Vec<u8>,
        merkle_proof: MerkleProof,
    },
    PdStored {
        leader: u32,
        roothash: [u8; 32],
        share: Vec<u8>,
    },
    PdLock {
        leader: u32,
        proof: ThresholdProof,
    },
    PdLocked {
        leader: u32,
        roothash: [u8; 32],
        share: Vec<u8>,
    },
    PdDone {
        leader: u32,
        proof: ThresholdProof,
    },
    RcPrepare {
        mvba_round: u32,
        leader: u32,
        proof: Option<ThresholdProof>,
    },
    RcLock {
        mvba_round: u32,
        leader: u32,
        proof: ThresholdProof,
    },
    RcStore {
        mvba_round: u32,
        leader: u32,
        store: PdStoreRecord,
    },
    AbaEst {
        mvba_round: u32,
        epoch: u32,
        value: bool,
    },
    AbaAux {
        mvba_round: u32,
        epoch: u32,
        value: bool,
    },
    AbaConf {
        mvba_round: u32,
        epoch: u32,
        values: [bool; 2],
    },
    CoinShare {
        scope: DumboCoinScope,
        share: Vec<u8>,
    },
}

impl RustDumboAcsBackend {
    pub(super) fn encode_envelope(
        &self,
        round_id: usize,
        message: RustDumboMessage,
    ) -> Result<Vec<u8>, String> {
        bincode::serialize(&RustDumboEnvelope {
            round_id: round_id as u32,
            sender: self.pid as u32,
            message,
        })
        .map_err(|err| err.to_string())
    }

    pub(super) fn decode_envelope(payload: &[u8]) -> Result<RustDumboEnvelope, String> {
        bincode::deserialize(payload).map_err(|err| err.to_string())
    }

    pub(super) fn build_proposal_id(round_id: usize, proposer: usize, digest: &[u8; 32]) -> String {
        format!("{round_id}:{proposer}:{}", hex_encode(digest))
    }

    pub(super) fn serialize_prbc_proof(proof: &PrbcProof) -> Vec<u8> {
        let mut chunks = Vec::with_capacity(2 + 32 + 2 + proof.sigmas.len() * (2 + 4 + 64));
        chunks.extend_from_slice(&(proof.roothash.len() as u16).to_be_bytes());
        chunks.extend_from_slice(&proof.roothash);
        chunks.extend_from_slice(&(proof.sigmas.len() as u16).to_be_bytes());
        for (sender, signature) in &proof.sigmas {
            chunks.extend_from_slice(&(*sender as u16).to_be_bytes());
            chunks.extend_from_slice(&(signature.len() as u32).to_be_bytes());
            chunks.extend_from_slice(signature);
        }
        chunks
    }

    pub(super) fn serialize_prbc_vector(entries: &[Option<PrbcProof>]) -> Vec<u8> {
        let mut chunks = Vec::new();
        chunks.extend_from_slice(&(entries.len() as u16).to_be_bytes());
        for proof in entries {
            match proof {
                None => chunks.push(0),
                Some(proof) => {
                    chunks.push(1);
                    chunks.extend_from_slice(&(proof.roothash.len() as u16).to_be_bytes());
                    chunks.extend_from_slice(&proof.roothash);
                    chunks.extend_from_slice(&(proof.sigmas.len() as u16).to_be_bytes());
                    for (sender, signature) in &proof.sigmas {
                        chunks.extend_from_slice(&(*sender as u16).to_be_bytes());
                        chunks.extend_from_slice(&(signature.len() as u32).to_be_bytes());
                        chunks.extend_from_slice(signature);
                    }
                }
            }
        }
        chunks
    }

    pub(super) fn deserialize_prbc_vector(
        raw: &[u8],
        expected_nodes: usize,
    ) -> Result<Vec<Option<PrbcProof>>, String> {
        if raw.len() < 2 {
            return Err(String::from("invalid PRBC vector header"));
        }
        let size = u16::from_be_bytes([raw[0], raw[1]]) as usize;
        if size != expected_nodes {
            return Err(format!(
                "PRBC vector size mismatch: expected {expected_nodes}, got {size}"
            ));
        }
        let mut offset = 2usize;
        let mut entries = Vec::with_capacity(size);
        for _ in 0..size {
            let Some(&present) = raw.get(offset) else {
                return Err(String::from("truncated PRBC vector"));
            };
            offset += 1;
            if present == 0 {
                entries.push(None);
                continue;
            }
            if present != 1 {
                return Err(String::from("invalid PRBC vector presence flag"));
            }
            if offset + 2 > raw.len() {
                return Err(String::from("truncated PRBC vector roothash header"));
            }
            let root_len = u16::from_be_bytes([raw[offset], raw[offset + 1]]) as usize;
            offset += 2;
            if offset + root_len > raw.len() {
                return Err(String::from("truncated PRBC vector roothash"));
            }
            let roothash: [u8; 32] = raw[offset..offset + root_len]
                .try_into()
                .map_err(|_| String::from("invalid PRBC vector roothash length"))?;
            offset += root_len;
            if offset + 2 > raw.len() {
                return Err(String::from("truncated PRBC vector signature count"));
            }
            let count = u16::from_be_bytes([raw[offset], raw[offset + 1]]) as usize;
            offset += 2;
            let mut sigmas = Vec::with_capacity(count);
            for _ in 0..count {
                if offset + 6 > raw.len() {
                    return Err(String::from("truncated PRBC vector signature header"));
                }
                let sender = u16::from_be_bytes([raw[offset], raw[offset + 1]]) as usize;
                let sig_len = u32::from_be_bytes([
                    raw[offset + 2],
                    raw[offset + 3],
                    raw[offset + 4],
                    raw[offset + 5],
                ]) as usize;
                offset += 6;
                if offset + sig_len > raw.len() {
                    return Err(String::from("truncated PRBC vector signature"));
                }
                let signature = raw[offset..offset + sig_len].to_vec();
                offset += sig_len;
                sigmas.push((sender, signature));
            }
            entries.push(Some(PrbcProof { roothash, sigmas }));
        }
        if offset != raw.len() {
            return Err(String::from("PRBC vector has trailing bytes"));
        }
        Ok(entries)
    }
}
