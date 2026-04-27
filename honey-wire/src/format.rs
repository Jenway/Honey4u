use honey_crypto::merkle::MerkleProof;
use rkyv::{Archive, Deserialize, Serialize};

#[derive(Clone, Archive, Serialize, Deserialize)]
pub struct EncryptedBatchWire {
    pub encrypted_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Archive, Serialize, Deserialize)]
pub struct TxBatchWire {
    pub items: Vec<Vec<u8>>,
}

#[derive(Clone, Archive, Serialize, Deserialize)]
pub struct MerkleProofWire {
    pub leaf_index: usize,
    pub siblings: Vec<Vec<u8>>,
}

impl MerkleProofWire {
    pub fn from_runtime(value: &MerkleProof) -> Self {
        Self {
            leaf_index: value.leaf_index,
            siblings: value
                .siblings
                .iter()
                .map(|sibling| sibling.to_vec())
                .collect(),
        }
    }

    pub fn into_runtime(self) -> Result<MerkleProof, String> {
        let mut siblings = Vec::with_capacity(self.siblings.len());
        for sibling in self.siblings {
            let sibling: [u8; 32] = sibling.try_into().map_err(|bytes: Vec<u8>| {
                format!("invalid Merkle sibling length: {}", bytes.len())
            })?;
            siblings.push(sibling);
        }
        Ok(MerkleProof {
            leaf_index: self.leaf_index,
            siblings,
        })
    }
}

#[derive(Clone, Archive, Serialize, Deserialize)]
pub struct EncodedShardWire {
    pub index: usize,
    pub data: Vec<u8>,
    pub proof: MerkleProofWire,
}

#[derive(Clone, Archive, Serialize, Deserialize)]
pub struct MerkleResultWire {
    pub root: Vec<u8>,
    pub shards: Vec<Vec<u8>>,
    pub proofs: Vec<MerkleProofWire>,
}

#[derive(Archive, Serialize, Deserialize)]
pub enum ChannelWire {
    AcsCoin,
    AcsRbc,
    AcsAba,
    DumboPrbc,
    DumboProof,
    DumboMvba,
    DumboPool,
}

#[derive(Archive, Serialize, Deserialize)]
pub enum MessageWire {
    RbcVal {
        roothash: Vec<u8>,
        proof: Vec<u8>,
        stripe: Vec<u8>,
        stripe_index: u32,
    },
    RbcEcho {
        roothash: Vec<u8>,
        proof: Vec<u8>,
        stripe: Vec<u8>,
        stripe_index: u32,
    },
    RbcReady {
        roothash: Vec<u8>,
    },
    BaEst {
        epoch: u32,
        value: u32,
    },
    BaAux {
        epoch: u32,
        value: u32,
    },
    BaConf {
        epoch: u32,
        values: Vec<u32>,
    },
    CoinShareMessage {
        round_id: u32,
        signature: Vec<u8>,
    },
    PrbcVal {
        leader: u32,
        roothash: Vec<u8>,
        proof: Vec<u8>,
        stripe: Vec<u8>,
        stripe_index: u32,
    },
    PrbcEcho {
        leader: u32,
        roothash: Vec<u8>,
        proof: Vec<u8>,
        stripe: Vec<u8>,
        stripe_index: u32,
    },
    PrbcReady {
        leader: u32,
        roothash: Vec<u8>,
        signature: Vec<u8>,
    },
    DumboProofDiffuse {
        leader: u32,
        proof: PrbcProofWire,
    },
    PdStore {
        leader: u32,
        roothash: Vec<u8>,
        stripe: Vec<u8>,
        merkle_proof: Vec<u8>,
    },
    PdStored {
        leader: u32,
        roothash: Vec<u8>,
        share: Vec<u8>,
    },
    PdLock {
        leader: u32,
        proof: ThresholdShareProofWire,
    },
    PdLocked {
        leader: u32,
        roothash: Vec<u8>,
        share: Vec<u8>,
    },
    PdDone {
        leader: u32,
        proof: ThresholdShareProofWire,
    },
    MvbaRcPrepare {
        mvba_round: u32,
        leader: u32,
        proof: Option<ThresholdShareProofWire>,
    },
    MvbaRcLock {
        mvba_round: u32,
        leader: u32,
        proof: ThresholdShareProofWire,
    },
    MvbaRcStore {
        mvba_round: u32,
        leader: u32,
        store: PdStoreRecordWire,
    },
    MvbaAbaMessage {
        mvba_round: u32,
        payload: AbaPayloadWire,
    },
    MvbaElectionCoinShare {
        coin_round: u32,
        signature: Vec<u8>,
    },
    MvbaAbaCoinShare {
        mvba_round: u32,
        coin_round: u32,
        signature: Vec<u8>,
    },
    PoolFetchRequest {
        item_id: String,
        origin_round: u32,
        origin_sender: u32,
        roothash: Vec<u8>,
    },
    PoolFetchResponse {
        item_id: String,
        payload: Vec<u8>,
    },
    RawPayload {
        data: Vec<u8>,
    },
}

#[derive(Archive, Serialize, Deserialize)]
pub enum AbaPayloadWire {
    BaEst { epoch: u32, value: u32 },
    BaAux { epoch: u32, value: u32 },
    BaConf { epoch: u32, values: Vec<u32> },
}

#[derive(Archive, Serialize, Deserialize)]
pub struct ProtocolEnvelopeWire {
    pub sender: u32,
    pub round_id: u32,
    pub channel: ChannelWire,
    pub instance_id: Option<u32>,
    pub message: MessageWire,
}

#[derive(Archive, Serialize, Deserialize)]
pub struct PrbcProofWire {
    pub roothash: Vec<u8>,
    pub sigmas: Vec<(u32, Vec<u8>)>,
}

#[derive(Archive, Serialize, Deserialize)]
pub struct ThresholdShareProofWire {
    pub roothash: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Archive, Serialize, Deserialize)]
pub struct PdStoreRecordWire {
    pub roothash: Vec<u8>,
    pub stripe_owner: u32,
    pub stripe: Vec<u8>,
    pub merkle_proof: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_proof_wire_round_trips_runtime_proof() {
        let proof = MerkleProof {
            leaf_index: 2,
            siblings: vec![[7u8; 32], [9u8; 32]],
        };

        let decoded = MerkleProofWire::from_runtime(&proof)
            .into_runtime()
            .expect("valid proof should decode");

        assert_eq!(decoded.leaf_index, proof.leaf_index);
        assert_eq!(decoded.siblings, proof.siblings);
    }

    #[test]
    fn merkle_proof_wire_rejects_invalid_sibling_length() {
        let err = MerkleProofWire {
            leaf_index: 0,
            siblings: vec![vec![1, 2, 3]],
        }
        .into_runtime()
        .expect_err("short sibling should be rejected");

        assert!(err.contains("invalid Merkle sibling length: 3"));
    }
}
