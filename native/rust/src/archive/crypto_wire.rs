use rkyv::{Archive, Deserialize, Serialize};

use crate::crypto::threshold::keygen::{
    Ciphertext, PartialDecryptionShare, PkePrivateKeyShare, PkePublicParams, SigPrivateKeyShare,
    SigPublicParams,
};
use crate::crypto::threshold::utils::{
    fr_from_bytes, fr_to_bytes, g1_from_bytes, g1_to_bytes, g2_from_bytes, g2_to_bytes,
};

#[derive(Archive, Serialize, Deserialize)]
pub(crate) struct SigPublicParamsWire {
    pub(crate) total_players: usize,
    pub(crate) threshold: usize,
    pub(crate) master_public_key: Vec<u8>,
    pub(crate) verification_vector: Vec<Vec<u8>>,
}

impl SigPublicParamsWire {
    pub(crate) fn from_runtime(value: &SigPublicParams) -> Self {
        Self {
            total_players: value.total_players,
            threshold: value.threshold,
            master_public_key: g2_to_bytes(&value.master_public_key),
            verification_vector: value.verification_vector.iter().map(g2_to_bytes).collect(),
        }
    }

    pub(crate) fn into_runtime(self) -> Result<SigPublicParams, String> {
        Ok(SigPublicParams {
            total_players: self.total_players,
            threshold: self.threshold,
            master_public_key: g2_from_bytes(&self.master_public_key)?,
            verification_vector: self
                .verification_vector
                .into_iter()
                .map(|bytes| g2_from_bytes(&bytes))
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

#[derive(Archive, Serialize, Deserialize)]
pub(crate) struct SigPrivateKeyShareWire {
    pub(crate) player_id: usize,
    pub(crate) secret: Vec<u8>,
}

impl SigPrivateKeyShareWire {
    pub(crate) fn from_runtime(value: &SigPrivateKeyShare) -> Self {
        Self {
            player_id: value.player_id,
            secret: fr_to_bytes(&value.secret),
        }
    }

    pub(crate) fn into_runtime(self) -> Result<SigPrivateKeyShare, String> {
        Ok(SigPrivateKeyShare {
            player_id: self.player_id,
            secret: fr_from_bytes(&self.secret)?,
        })
    }
}

#[derive(Archive, Serialize, Deserialize)]
pub(crate) struct PkePublicParamsWire {
    pub(crate) total_players: usize,
    pub(crate) threshold: usize,
    pub(crate) master_public_key: Vec<u8>,
    pub(crate) verification_vector: Vec<Vec<u8>>,
}

impl PkePublicParamsWire {
    pub(crate) fn from_runtime(value: &PkePublicParams) -> Self {
        Self {
            total_players: value.total_players,
            threshold: value.threshold,
            master_public_key: g1_to_bytes(&value.master_public_key),
            verification_vector: value.verification_vector.iter().map(g2_to_bytes).collect(),
        }
    }

    pub(crate) fn into_runtime(self) -> Result<PkePublicParams, String> {
        Ok(PkePublicParams {
            total_players: self.total_players,
            threshold: self.threshold,
            master_public_key: g1_from_bytes(&self.master_public_key)?,
            verification_vector: self
                .verification_vector
                .into_iter()
                .map(|bytes| g2_from_bytes(&bytes))
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

#[derive(Archive, Serialize, Deserialize)]
pub(crate) struct PkePrivateKeyShareWire {
    pub(crate) player_id: usize,
    pub(crate) secret: Vec<u8>,
}

impl PkePrivateKeyShareWire {
    pub(crate) fn from_runtime(value: &PkePrivateKeyShare) -> Self {
        Self {
            player_id: value.player_id,
            secret: fr_to_bytes(&value.secret),
        }
    }

    pub(crate) fn into_runtime(self) -> Result<PkePrivateKeyShare, String> {
        Ok(PkePrivateKeyShare {
            player_id: self.player_id,
            secret: fr_from_bytes(&self.secret)?,
        })
    }
}

#[derive(Archive, Serialize, Deserialize)]
pub(crate) struct CiphertextWire {
    pub(crate) u: Vec<u8>,
    pub(crate) v: Vec<u8>,
    pub(crate) w: Vec<u8>,
}

impl CiphertextWire {
    pub(crate) fn from_runtime(value: &Ciphertext) -> Self {
        Self {
            u: g1_to_bytes(&value.u),
            v: value.v.to_vec(),
            w: g2_to_bytes(&value.w),
        }
    }

    pub(crate) fn into_runtime(self) -> Result<Ciphertext, String> {
        let mut v = [0u8; 32];
        if self.v.len() != v.len() {
            return Err(format!("expected 32 bytes for ciphertext mask, got {}", self.v.len()));
        }
        v.copy_from_slice(&self.v);

        Ok(Ciphertext {
            u: g1_from_bytes(&self.u)?,
            v,
            w: g2_from_bytes(&self.w)?,
        })
    }
}

#[derive(Archive, Serialize, Deserialize)]
pub(crate) struct PartialDecryptionShareWire {
    pub(crate) player_id: usize,
    pub(crate) value: Vec<u8>,
}

impl PartialDecryptionShareWire {
    pub(crate) fn from_runtime(value: &PartialDecryptionShare) -> Self {
        Self {
            player_id: value.player_id,
            value: g1_to_bytes(&value.value),
        }
    }

    pub(crate) fn into_runtime(self) -> Result<PartialDecryptionShare, String> {
        Ok(PartialDecryptionShare {
            player_id: self.player_id,
            value: g1_from_bytes(&self.value)?,
        })
    }
}
