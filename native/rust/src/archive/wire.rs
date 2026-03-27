use rkyv::{Archive, Deserialize, Serialize};

#[derive(Archive, Serialize, Deserialize)]
pub(crate) struct EncryptedBatchWire {
    pub(crate) encrypted_key: Vec<u8>,
    pub(crate) ciphertext: Vec<u8>,
}

#[derive(Archive, Serialize, Deserialize)]
pub(crate) enum ChannelWire {
    AcsCoin,
    AcsRbc,
    AcsAba,
    DumboPrbc,
    DumboProof,
    DumboMvba,
    DumboPool,
    Tpke,
}

#[derive(Archive, Serialize, Deserialize)]
pub(crate) enum MessageWire {
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
    TpkeShareBundle {
        shares: Vec<Option<Vec<u8>>>,
    },
    RawPayload {
        data: Vec<u8>,
    },
}

#[derive(Archive, Serialize, Deserialize)]
pub(crate) enum AbaPayloadWire {
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
}

#[derive(Archive, Serialize, Deserialize)]
pub(crate) struct ProtocolEnvelopeWire {
    pub(crate) sender: u32,
    pub(crate) round_id: u32,
    pub(crate) channel: ChannelWire,
    pub(crate) instance_id: Option<u32>,
    pub(crate) message: MessageWire,
}

#[derive(Archive, Serialize, Deserialize)]
pub(crate) struct TxBatchWire {
    pub(crate) items: Vec<Vec<u8>>,
}

#[derive(Archive, Serialize, Deserialize)]
pub(crate) struct MerkleProofWire {
    pub(crate) leaf_index: usize,
    pub(crate) siblings: Vec<Vec<u8>>,
}

#[derive(Archive, Serialize, Deserialize)]
pub(crate) struct EncodedShardWire {
    pub(crate) index: usize,
    pub(crate) data: Vec<u8>,
    pub(crate) proof: MerkleProofWire,
}

#[derive(Archive, Serialize, Deserialize)]
pub(crate) struct MerkleResultWire {
    pub(crate) root: Vec<u8>,
    pub(crate) shards: Vec<Vec<u8>>,
    pub(crate) proofs: Vec<MerkleProofWire>,
}

#[derive(Archive, Serialize, Deserialize)]
pub(crate) struct PrbcProofWire {
    pub(crate) roothash: Vec<u8>,
    pub(crate) sigmas: Vec<(u32, Vec<u8>)>,
}

#[derive(Archive, Serialize, Deserialize)]
pub(crate) struct ThresholdShareProofWire {
    pub(crate) roothash: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}

#[derive(Archive, Serialize, Deserialize)]
pub(crate) struct PdStoreRecordWire {
    pub(crate) roothash: Vec<u8>,
    pub(crate) stripe_owner: u32,
    pub(crate) stripe: Vec<u8>,
    pub(crate) merkle_proof: Vec<u8>,
}
