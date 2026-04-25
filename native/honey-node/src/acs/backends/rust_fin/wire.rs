use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(super) enum CoinScope {
    Election { iteration: u32 },
    Raba { iteration: u32, loop_index: u32 },
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct RustAcsEnvelope {
    pub(super) round_id: u32,
    pub(super) sender: u32,
    pub(super) message: RustAcsMessage,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) enum RustAcsMessage {
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
    WrbcSend {
        proposer: u32,
        value: Vec<u8>,
    },
    WrbcEcho {
        proposer: u32,
        digest: [u8; 32],
    },
    WrbcReady {
        proposer: u32,
        digest: [u8; 32],
    },
    WrbcValue {
        proposer: u32,
        value: Vec<u8>,
    },
    RabaVal {
        iteration: u32,
        loop_index: u32,
        value: bool,
    },
    RabaAux {
        iteration: u32,
        loop_index: u32,
        value: bool,
    },
    RabaConf {
        iteration: u32,
        loop_index: u32,
        values: [bool; 2],
    },
    RabaFinish {
        iteration: u32,
        value: bool,
    },
    CoinShare {
        scope: CoinScope,
        share: Vec<u8>,
    },
}

#[derive(Clone)]
pub(super) struct PrbcProof {
    pub(super) roothash: [u8; 32],
    pub(super) sigmas: Vec<(usize, [u8; 64])>,
}

impl RustAcsBackend {
    pub(super) fn encode_envelope(
        &self,
        round_id: usize,
        message: RustAcsMessage,
    ) -> Result<Vec<u8>, String> {
        bincode::serialize(&RustAcsEnvelope {
            round_id: round_id as u32,
            sender: self.pid as u32,
            message,
        })
        .map_err(|err| err.to_string())
    }

    pub(super) fn decode_envelope(payload: &[u8]) -> Result<RustAcsEnvelope, String> {
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

    pub(super) fn payload_digest(payload: &[u8]) -> [u8; 32] {
        Sha256::digest(payload).into()
    }

    pub(super) fn encode_completion_vector(bits: &[bool]) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + bits.len());
        out.extend_from_slice(&(bits.len() as u16).to_be_bytes());
        for bit in bits {
            out.push(u8::from(*bit));
        }
        out
    }

    pub(super) fn decode_completion_vector(raw: &[u8], n: usize) -> Result<Vec<bool>, String> {
        if raw.len() < 2 {
            return Err(String::from("invalid completion vector header"));
        }
        let size = u16::from_be_bytes([raw[0], raw[1]]) as usize;
        if size != n {
            return Err(format!(
                "completion vector size mismatch: expected {n}, got {size}"
            ));
        }
        if raw.len() != size + 2 {
            return Err(String::from("completion vector has trailing bytes"));
        }
        let mut bits = Vec::with_capacity(size);
        for &byte in &raw[2..] {
            match byte {
                0 => bits.push(false),
                1 => bits.push(true),
                _ => return Err(String::from("completion vector contains invalid bit")),
            }
        }
        Ok(bits)
    }

    pub(super) fn coin_message(sid: &str, scope: CoinScope) -> Vec<u8> {
        match scope {
            CoinScope::Election { iteration } => {
                format!("{sid}{COIN_DOMAIN}:election:{iteration}").into_bytes()
            }
            CoinScope::Raba {
                iteration,
                loop_index,
            } => format!("{sid}{COIN_DOMAIN}:raba:{iteration}:{loop_index}").into_bytes(),
        }
    }
}
