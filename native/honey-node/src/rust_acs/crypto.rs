use super::*;

pub(super) struct RustAcsCryptoMaterial {
    pub(super) ecdsa_pks: Vec<[u8; 33]>,
    pub(super) ecdsa_sk: [u8; 32],
    pub(super) coin_pk: SigPublicParams,
    pub(super) coin_sk: SigPrivateKeyShare,
}

impl RustAcsCryptoMaterial {
    fn decode_coin_pk(payload: &[u8]) -> Result<SigPublicParams, String> {
        let wire: SigPublicParamsWire = decode_result(payload)?;
        wire.into_runtime()
    }

    fn decode_coin_sk(payload: &[u8]) -> Result<SigPrivateKeyShare, String> {
        let wire: SigPrivateKeyShareWire = decode_result(payload)?;
        wire.into_runtime()
    }

    pub(super) fn try_from_material(
        material: AcsCryptoMaterial,
        pid: usize,
        nodes: usize,
        faulty: usize,
    ) -> Result<Self, String> {
        let ecdsa_sk: [u8; 32] = material
            .ecdsa_sk
            .try_into()
            .map_err(|_| String::from("Rust ACS requires 32-byte ecdsa_sk"))?;
        let ecdsa_pks = material
            .ecdsa_pks
            .into_iter()
            .map(|value| {
                value
                    .try_into()
                    .map_err(|_| String::from("Rust ACS requires 33-byte ECDSA public keys"))
            })
            .collect::<Result<Vec<[u8; 33]>, _>>()?;
        let coin_pk = Self::decode_coin_pk(&material.sig_pk)?;
        let coin_sk = Self::decode_coin_sk(&material.sig_sk)?;
        if coin_pk.total_players != nodes {
            return Err(format!(
                "Rust ACS coin players mismatch: expected {nodes}, got {}",
                coin_pk.total_players
            ));
        }
        if coin_pk.threshold != faulty + 1 {
            return Err(format!(
                "Rust ACS coin threshold mismatch: expected {}, got {}",
                faulty + 1,
                coin_pk.threshold
            ));
        }
        if coin_sk.player_id != pid + 1 {
            return Err(format!(
                "Rust ACS coin share player mismatch: expected {}, got {}",
                pid + 1,
                coin_sk.player_id
            ));
        }
        Ok(Self {
            ecdsa_pks,
            ecdsa_sk,
            coin_pk,
            coin_sk,
        })
    }
}
