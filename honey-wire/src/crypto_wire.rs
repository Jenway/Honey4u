use rkyv::{Archive, Deserialize, Serialize};

use honey_crypto::threshold::keygen::{
    Ciphertext, PartialDecryptionShare, PkePrivateKeyShare, PkePublicParams, SigPrivateKeyShare,
    SigPublicParams,
};
use honey_crypto::{bls::fr::Fr, bls::g1::G1, bls::g2::G2};

fn fr_from_bytes(bytes: &[u8]) -> Result<Fr, String> {
    let arr: &[u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("expected 32 bytes for Fr, got {}", bytes.len()))?;
    Fr::from_scalar_bytes(arr).ok_or_else(|| "invalid Fr scalar bytes".into())
}

fn g1_from_bytes(bytes: &[u8]) -> Result<G1, String> {
    let arr: &[u8; 48] = bytes
        .try_into()
        .map_err(|_| format!("expected 48 bytes for G1, got {}", bytes.len()))?;
    G1::from_compressed_bytes(arr)
}

fn g2_from_bytes(bytes: &[u8]) -> Result<G2, String> {
    let arr: &[u8; 96] = bytes
        .try_into()
        .map_err(|_| format!("expected 96 bytes for G2, got {}", bytes.len()))?;
    G2::from_compressed_bytes(arr)
}

#[derive(Archive, Serialize, Deserialize)]
pub struct SigPublicParamsWire {
    pub total_players: usize,
    pub threshold: usize,
    pub master_public_key: Vec<u8>,
    pub verification_vector: Vec<Vec<u8>>,
}

impl SigPublicParamsWire {
    pub fn from_runtime(value: &SigPublicParams) -> Self {
        Self {
            total_players: value.total_players,
            threshold: value.threshold,
            master_public_key: value.master_public_key.to_compressed_bytes().to_vec(),
            verification_vector: value
                .verification_vector
                .iter()
                .map(|point| point.to_compressed_bytes().to_vec())
                .collect(),
        }
    }

    pub fn into_runtime(self) -> Result<SigPublicParams, String> {
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
pub struct SigPrivateKeyShareWire {
    pub player_id: usize,
    pub secret: Vec<u8>,
}

impl SigPrivateKeyShareWire {
    pub fn from_runtime(value: &SigPrivateKeyShare) -> Self {
        Self {
            player_id: value.player_id,
            secret: value.secret.to_scalar_bytes().to_vec(),
        }
    }

    pub fn into_runtime(self) -> Result<SigPrivateKeyShare, String> {
        Ok(SigPrivateKeyShare {
            player_id: self.player_id,
            secret: fr_from_bytes(&self.secret)?,
        })
    }
}

#[derive(Archive, Serialize, Deserialize)]
pub struct PkePublicParamsWire {
    pub total_players: usize,
    pub threshold: usize,
    pub master_public_key: Vec<u8>,
    pub verification_vector: Vec<Vec<u8>>,
}

impl PkePublicParamsWire {
    pub fn from_runtime(value: &PkePublicParams) -> Self {
        Self {
            total_players: value.total_players,
            threshold: value.threshold,
            master_public_key: value.master_public_key.to_compressed_bytes().to_vec(),
            verification_vector: value
                .verification_vector
                .iter()
                .map(|point| point.to_compressed_bytes().to_vec())
                .collect(),
        }
    }

    pub fn into_runtime(self) -> Result<PkePublicParams, String> {
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
pub struct PkePrivateKeyShareWire {
    pub player_id: usize,
    pub secret: Vec<u8>,
}

impl PkePrivateKeyShareWire {
    pub fn from_runtime(value: &PkePrivateKeyShare) -> Self {
        Self {
            player_id: value.player_id,
            secret: value.secret.to_scalar_bytes().to_vec(),
        }
    }

    pub fn into_runtime(self) -> Result<PkePrivateKeyShare, String> {
        Ok(PkePrivateKeyShare {
            player_id: self.player_id,
            secret: fr_from_bytes(&self.secret)?,
        })
    }
}

#[derive(Archive, Serialize, Deserialize)]
pub struct CiphertextWire {
    pub u: Vec<u8>,
    pub v: Vec<u8>,
    pub w: Vec<u8>,
}

impl CiphertextWire {
    pub fn from_runtime(value: &Ciphertext) -> Self {
        Self {
            u: value.u.to_compressed_bytes().to_vec(),
            v: value.v.to_vec(),
            w: value.w.to_compressed_bytes().to_vec(),
        }
    }

    pub fn into_runtime(self) -> Result<Ciphertext, String> {
        let mut v = [0u8; 32];
        if self.v.len() != v.len() {
            return Err(format!(
                "expected 32 bytes for ciphertext mask, got {}",
                self.v.len()
            ));
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
pub struct PartialDecryptionShareWire {
    pub player_id: usize,
    pub value: Vec<u8>,
}

impl PartialDecryptionShareWire {
    pub fn from_runtime(value: &PartialDecryptionShare) -> Self {
        Self {
            player_id: value.player_id,
            value: value.value.to_compressed_bytes().to_vec(),
        }
    }

    pub fn into_runtime(self) -> Result<PartialDecryptionShare, String> {
        Ok(PartialDecryptionShare {
            player_id: self.player_id,
            value: g1_from_bytes(&self.value)?,
        })
    }
}
