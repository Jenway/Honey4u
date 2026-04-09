use rkyv::{Archive, Deserialize, Serialize};

#[derive(Archive, Serialize, Deserialize)]
pub struct EncryptedBatchWire {
    pub encrypted_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Archive, Serialize, Deserialize)]
pub struct TxBatchWire {
    pub items: Vec<Vec<u8>>,
}

#[derive(Archive, Serialize, Deserialize)]
pub struct MerkleProofWire {
    pub leaf_index: usize,
    pub siblings: Vec<Vec<u8>>,
}

#[derive(Archive, Serialize, Deserialize)]
pub struct EncodedShardWire {
    pub index: usize,
    pub data: Vec<u8>,
    pub proof: MerkleProofWire,
}

#[derive(Archive, Serialize, Deserialize)]
pub struct MerkleResultWire {
    pub root: Vec<u8>,
    pub shards: Vec<Vec<u8>>,
    pub proofs: Vec<MerkleProofWire>,
}
