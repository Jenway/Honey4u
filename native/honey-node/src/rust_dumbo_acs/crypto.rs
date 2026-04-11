use super::*;

pub(super) struct RustDumboCryptoMaterial {
    pub(super) ecdsa_pks: Vec<[u8; 33]>,
    pub(super) ecdsa_sk: [u8; 32],
    pub(super) coin_pk: SigPublicParams,
    pub(super) coin_sk: SigPrivateKeyShare,
    pub(super) proof_pk: SigPublicParams,
    pub(super) proof_sk: SigPrivateKeyShare,
}

impl RustDumboCryptoMaterial {
    fn decode_sig_pk(payload: &[u8]) -> Result<SigPublicParams, String> {
        let wire: SigPublicParamsWire = decode_result(payload)?;
        wire.into_runtime()
    }

    fn decode_sig_sk(payload: &[u8]) -> Result<SigPrivateKeyShare, String> {
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
            .map_err(|_| String::from("Rust Dumbo ACS requires 32-byte ecdsa_sk"))?;
        let ecdsa_pks = material
            .ecdsa_pks
            .into_iter()
            .map(|value| {
                value
                    .try_into()
                    .map_err(|_| String::from("Rust Dumbo ACS requires 33-byte ECDSA public keys"))
            })
            .collect::<Result<Vec<[u8; 33]>, _>>()?;
        let Some(proof_sig_pk) = material.proof_sig_pk else {
            return Err(String::from(
                "Rust Dumbo ACS requires proof_sig_pk in ACS crypto payload",
            ));
        };
        let Some(proof_sig_sk) = material.proof_sig_sk else {
            return Err(String::from(
                "Rust Dumbo ACS requires proof_sig_sk in ACS crypto payload",
            ));
        };
        let coin_pk = Self::decode_sig_pk(&material.sig_pk)?;
        let coin_sk = Self::decode_sig_sk(&material.sig_sk)?;
        let proof_pk = Self::decode_sig_pk(&proof_sig_pk)?;
        let proof_sk = Self::decode_sig_sk(&proof_sig_sk)?;
        if coin_pk.total_players != nodes {
            return Err(format!(
                "Rust Dumbo ACS coin players mismatch: expected {nodes}, got {}",
                coin_pk.total_players
            ));
        }
        if coin_pk.threshold != faulty + 1 {
            return Err(format!(
                "Rust Dumbo ACS coin threshold mismatch: expected {}, got {}",
                faulty + 1,
                coin_pk.threshold
            ));
        }
        if proof_pk.total_players != nodes {
            return Err(format!(
                "Rust Dumbo ACS proof players mismatch: expected {nodes}, got {}",
                proof_pk.total_players
            ));
        }
        if proof_pk.threshold != nodes - faulty {
            return Err(format!(
                "Rust Dumbo ACS proof threshold mismatch: expected {}, got {}",
                nodes - faulty,
                proof_pk.threshold
            ));
        }
        if coin_sk.player_id != pid + 1 {
            return Err(format!(
                "Rust Dumbo ACS coin share player mismatch: expected {}, got {}",
                pid + 1,
                coin_sk.player_id
            ));
        }
        if proof_sk.player_id != pid + 1 {
            return Err(format!(
                "Rust Dumbo ACS proof share player mismatch: expected {}, got {}",
                pid + 1,
                proof_sk.player_id
            ));
        }
        Ok(Self {
            ecdsa_pks,
            ecdsa_sk,
            coin_pk,
            coin_sk,
            proof_pk,
            proof_sk,
        })
    }
}

impl RustDumboAcsHost {
    pub(super) fn validate_prbc_proof(
        &self,
        round: &RoundState,
        leader: usize,
        proof: &PrbcProof,
    ) -> bool {
        if leader >= round.nodes() || self.crypto.ecdsa_pks.len() != round.nodes() {
            return false;
        }
        let sid = Self::prbc_sid(&round.sid, leader);
        let digest = Self::ready_digest(&sid, &proof.roothash);
        let signatures = proof
            .sigmas
            .iter()
            .filter_map(|(sender, signature)| {
                let signature: [u8; 64] = signature.as_slice().try_into().ok()?;
                let id = i32::try_from(*sender).ok()?;
                Some((id, signature))
            })
            .collect::<Vec<_>>();
        ecdsa::verify_threshold_sigs(
            &self.crypto.ecdsa_pks,
            &digest,
            &signatures,
            self.threshold(round),
        )
    }

    pub(super) fn validate_proof_vector(&self, round: &RoundState, raw: &[u8]) -> bool {
        let Ok(entries) = Self::deserialize_prbc_vector(raw, round.nodes()) else {
            return false;
        };
        let valid = entries
            .iter()
            .enumerate()
            .filter_map(|(leader, proof)| proof.as_ref().map(|proof| (leader, proof)))
            .filter(|(leader, proof)| self.validate_prbc_proof(round, *leader, proof))
            .count();
        valid >= self.threshold(round)
    }

    pub(super) fn build_threshold_proof(
        params: &SigPublicParams,
        shares: &BTreeMap<usize, Vec<u8>>,
        threshold: usize,
        roothash: [u8; 32],
        msg: &[u8],
    ) -> Result<ThresholdProof, String> {
        let partials = shares
            .iter()
            .take(threshold)
            .map(|(sender, share)| {
                let value = g1_from_bytes(share)?;
                Ok::<_, String>(PartialSignature {
                    player_id: sender + 1,
                    value,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let combined = threshold::sig::combine_trusted(params, msg, &partials)
            .map_err(|err| err.to_string())?;
        Ok(ThresholdProof {
            roothash,
            signature: g1_to_bytes(&combined),
        })
    }

    pub(super) fn verify_threshold_proof(
        params: &SigPublicParams,
        proof: &ThresholdProof,
        msg: &[u8],
    ) -> bool {
        let Ok(signature) = g1_from_bytes(&proof.signature) else {
            return false;
        };
        threshold::sig::verify_combined(params, &signature, msg).is_ok()
    }

    pub(super) fn coin_message(sid: &str, scope: DumboCoinScope) -> Vec<u8> {
        match scope {
            DumboCoinScope::Election { permutation_round } => {
                format!("{sid}mvba:election:{permutation_round}").into_bytes()
            }
            DumboCoinScope::Aba { mvba_round, epoch } => {
                format!("{sid}mvba:{mvba_round}:coin:{epoch}").into_bytes()
            }
        }
    }

    pub(super) fn leader_permutation(seed: u8, nodes: usize) -> Vec<usize> {
        let mut ranked = (0..nodes)
            .map(|leader| {
                let mut payload = Vec::with_capacity(1 + 8);
                payload.push(seed);
                payload.extend_from_slice(&(leader as u64).to_be_bytes());
                (Sha256::digest(&payload).to_vec(), leader)
            })
            .collect::<Vec<_>>();
        ranked.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
        ranked.into_iter().map(|(_, leader)| leader).collect()
    }
}
