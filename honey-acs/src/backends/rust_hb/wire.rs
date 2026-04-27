use super::*;
use honey_wire::api::{decode_result, encode_result};
use rkyv::{Archive, Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HbBroadcastMode {
    Rbc,
    Prbc,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Archive, Serialize, Deserialize)]
pub(super) enum HbCoinScope {
    Aba { instance: u32, epoch: u32 },
}

#[derive(Clone, Archive, Serialize, Deserialize)]
pub(super) struct RustHbEnvelope {
    pub(super) round_id: u32,
    pub(super) sender: u32,
    pub(super) message: RustHbMessage,
}

#[derive(Clone, Archive, Serialize, Deserialize)]
pub(super) enum RustHbMessage {
    RbcVal {
        leader: u32,
        roothash: [u8; 32],
        proof: MerkleProofWire,
        stripe: Vec<u8>,
        stripe_index: u32,
    },
    RbcEcho {
        leader: u32,
        roothash: [u8; 32],
        proof: MerkleProofWire,
        stripe: Vec<u8>,
        stripe_index: u32,
    },
    RbcReady {
        leader: u32,
        roothash: [u8; 32],
    },
    PrbcVal {
        leader: u32,
        roothash: [u8; 32],
        proof: MerkleProofWire,
        stripe: Vec<u8>,
        stripe_index: u32,
    },
    PrbcEcho {
        leader: u32,
        roothash: [u8; 32],
        proof: MerkleProofWire,
        stripe: Vec<u8>,
        stripe_index: u32,
    },
    PrbcReady {
        leader: u32,
        roothash: [u8; 32],
        signature: Vec<u8>,
    },
    AbaEst {
        instance: u32,
        epoch: u32,
        value: bool,
    },
    AbaAux {
        instance: u32,
        epoch: u32,
        value: bool,
    },
    AbaConf {
        instance: u32,
        epoch: u32,
        values: [bool; 2],
    },
    CoinShare {
        scope: HbCoinScope,
        share: Vec<u8>,
    },
}

#[derive(Clone, Archive, Serialize, Deserialize)]
pub(super) struct PrbcProof {
    pub(super) roothash: [u8; 32],
    pub(super) sigmas: Vec<(usize, Vec<u8>)>,
}

impl RustHbAcsBackend {
    pub(super) fn coin_message(sid: &str, scope: HbCoinScope) -> Vec<u8> {
        match scope {
            HbCoinScope::Aba { instance, epoch } => {
                format!("{sid}COIN{instance}:{epoch}").into_bytes()
            }
        }
    }

    pub(super) fn encode_envelope(
        &self,
        round_id: usize,
        message: RustHbMessage,
    ) -> Result<Vec<u8>, String> {
        encode_result(&RustHbEnvelope {
            round_id: round_id as u32,
            sender: self.pid as u32,
            message,
        })
    }

    pub(super) fn decode_envelope(payload: &[u8]) -> Result<RustHbEnvelope, String> {
        decode_result(payload)
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
}
