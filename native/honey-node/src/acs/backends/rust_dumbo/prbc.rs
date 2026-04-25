use super::*;

impl RustDumboAcsBackend {
    fn output_prbc(
        &self,
        round: &mut RoundState,
        leader: usize,
        roothash: [u8; 32],
    ) -> Result<bool, String> {
        let threshold = self.threshold(round);
        let data_threshold = self.data_threshold(round);
        let nodes = round.nodes();
        let (available, sigmas) = {
            let proposal = &round.proposals[leader];
            if proposal.output.is_some() {
                return Ok(false);
            }
            let Some(stripes) = proposal.stripes.get(&roothash) else {
                return Ok(false);
            };
            if stripes.len() < data_threshold {
                return Ok(false);
            }
            let Some(proofs) = proposal.proofs.get(&roothash) else {
                return Ok(false);
            };
            let Some(signatures) = proposal.ready_signatures.get(&roothash) else {
                return Ok(false);
            };
            if signatures.len() < threshold {
                return Ok(false);
            }
            let available = stripes
                .iter()
                .filter_map(|(index, stripe)| {
                    proofs
                        .get(index)
                        .cloned()
                        .map(|proof| (*index, stripe.clone(), proof))
                })
                .collect::<Vec<_>>();
            if available.len() < data_threshold {
                return Ok(false);
            }
            let sigmas = signatures
                .iter()
                .take(threshold)
                .map(|(sender, signature)| (*sender, signature.to_vec()))
                .collect::<Vec<_>>();
            (available, sigmas)
        };
        let payload = merkle::decode_owned(available, &roothash, data_threshold, nodes)
            .map_err(|err| err.to_string())?;
        let proof = PrbcProof { roothash, sigmas };
        let proposal_id = Self::build_proposal_id(round.round_id, leader, &roothash);
        let artifact = AvailableProposal {
            proposal_id,
            proposer: leader,
            payload: payload.clone(),
            digest: roothash.to_vec(),
            availability_proof: Self::serialize_prbc_proof(&proof),
        };
        let proposal = &mut round.proposals[leader];
        proposal.payload = Some(payload);
        proposal.output = Some(proof);
        proposal.proposal_ready = Some(artifact.clone());
        round.mark_mvba_dirty();
        round.outbound.push_back(AcsEvent::ProposalAvailable {
            round_id: round.round_id,
            proposal: artifact,
        });
        Ok(true)
    }

    fn drive_prbc_leader(&self, round: &mut RoundState, leader: usize) -> Result<bool, String> {
        let mut changed_any = false;
        let threshold = self.threshold(round);
        let data_threshold = self.data_threshold(round);
        loop {
            let mut changed = false;
            let mut send_ready_for = None;
            let mut maybe_output_for = None;
            {
                let proposal = &round.proposals[leader];
                if proposal.output.is_none() {
                    for roothash in proposal.stripes.keys() {
                        let echo_count = proposal
                            .echo_by_sender
                            .values()
                            .filter(|value| **value == *roothash)
                            .count();
                        let ready_count = proposal
                            .ready_by_sender
                            .values()
                            .filter(|value| **value == *roothash)
                            .count();
                        if !proposal.ready_sent
                            && (echo_count >= threshold || ready_count > self.faulty)
                        {
                            send_ready_for = Some(*roothash);
                        }
                        if ready_count >= threshold {
                            let stripe_count = proposal
                                .stripes
                                .get(roothash)
                                .map(BTreeMap::len)
                                .unwrap_or_default();
                            if stripe_count >= data_threshold {
                                maybe_output_for = Some(*roothash);
                                break;
                            }
                        }
                    }
                }
            }
            if let Some(roothash) = send_ready_for {
                let proposal = &mut round.proposals[leader];
                if !proposal.ready_sent {
                    proposal.ready_sent = true;
                    let sid = Self::prbc_sid(&round.sid, leader);
                    let digest = Self::ready_digest(&sid, &roothash);
                    let signature = ecdsa::sign(&self.crypto.ecdsa_sk, &digest)
                        .map_err(|err| err.to_string())?;
                    proposal.local_ready = Some((roothash, signature));
                    proposal.ready_by_sender.insert(self.pid, roothash);
                    proposal
                        .ready_signatures
                        .entry(roothash)
                        .or_default()
                        .insert(self.pid, signature);
                    self.queue_broadcast(
                        round,
                        RustDumboMessage::PrbcReady {
                            leader: leader as u32,
                            roothash,
                            signature: signature.to_vec(),
                        },
                    )?;
                    changed = true;
                }
            }
            if let Some(roothash) = maybe_output_for {
                changed |= self.output_prbc(round, leader, roothash)?;
            }
            if !changed {
                return Ok(changed_any);
            }
            changed_any = true;
        }
    }

    pub(super) fn drive_prbc(&self, round: &mut RoundState) -> Result<bool, String> {
        let mut changed = false;
        let leaders = round.take_dirty_prbc_leaders();
        for leader in leaders {
            changed |= self.drive_prbc_leader(round, leader)?;
            round.clear_dirty_prbc_leader(leader);
        }
        Ok(changed)
    }

    pub(super) fn maybe_diffuse_local_proof(&self, round: &mut RoundState) -> Result<bool, String> {
        let Some(proof) = round.proposals[self.pid].output.clone() else {
            return Ok(false);
        };
        if round.proposals[self.pid].proof_diffused {
            return Ok(false);
        }
        round.proposals[self.pid].proof_diffused = true;
        round.mvba.proof_vector[self.pid] = Some(proof.clone());
        self.queue_broadcast(
            round,
            RustDumboMessage::ProofDiffuse {
                leader: self.pid as u32,
                proof,
            },
        )?;
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn handle_prbc_val(
        &self,
        round: &mut RoundState,
        sender: usize,
        leader: usize,
        roothash: [u8; 32],
        proof: MerkleProof,
        stripe: Vec<u8>,
        stripe_index: usize,
    ) -> Result<bool, String> {
        if leader >= round.nodes() || sender != leader || stripe_index != self.pid {
            return Ok(false);
        }
        if !merkle::verify_shard(&stripe, &proof, &roothash) {
            return Ok(false);
        }
        let proposal = &mut round.proposals[leader];
        if proposal.leader_root.is_some() {
            return Ok(false);
        }
        proposal.leader_root = Some(roothash);
        proposal
            .stripes
            .entry(roothash)
            .or_default()
            .insert(stripe_index, stripe.clone());
        proposal
            .proofs
            .entry(roothash)
            .or_default()
            .insert(stripe_index, proof.clone());
        proposal.echo_by_sender.insert(self.pid, roothash);
        self.queue_broadcast(
            round,
            RustDumboMessage::PrbcEcho {
                leader: leader as u32,
                roothash,
                proof,
                stripe,
                stripe_index: self.pid as u32,
            },
        )?;
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn handle_prbc_echo(
        &self,
        round: &mut RoundState,
        sender: usize,
        leader: usize,
        roothash: [u8; 32],
        proof: MerkleProof,
        stripe: Vec<u8>,
        stripe_index: usize,
    ) -> Result<bool, String> {
        if leader >= round.nodes() || stripe_index != sender {
            return Ok(false);
        }
        if !merkle::verify_shard(&stripe, &proof, &roothash) {
            return Ok(false);
        }
        let proposal = &mut round.proposals[leader];
        if let Some(existing) = proposal.echo_by_sender.get(&sender) {
            if *existing != roothash {
                return Ok(false);
            }
            return Ok(false);
        }
        proposal.echo_by_sender.insert(sender, roothash);
        proposal
            .stripes
            .entry(roothash)
            .or_default()
            .insert(stripe_index, stripe);
        proposal
            .proofs
            .entry(roothash)
            .or_default()
            .insert(stripe_index, proof);
        Ok(true)
    }

    pub(super) fn handle_prbc_ready(
        &self,
        round: &mut RoundState,
        sender: usize,
        leader: usize,
        roothash: [u8; 32],
        signature: Vec<u8>,
    ) -> Result<bool, String> {
        if leader >= round.nodes() || sender >= self.crypto.ecdsa_pks.len() {
            return Ok(false);
        }
        let signature: [u8; 64] = match signature.as_slice().try_into() {
            Ok(signature) => signature,
            Err(_) => return Ok(false),
        };
        let proposal = &mut round.proposals[leader];
        if let Some(existing) = proposal.ready_by_sender.get(&sender) {
            if *existing != roothash {
                return Ok(false);
            }
            return Ok(false);
        }
        let sid = Self::prbc_sid(&round.sid, leader);
        let digest = Self::ready_digest(&sid, &roothash);
        if sender == self.pid {
            match proposal.local_ready {
                Some((local_root, local_signature))
                    if local_root == roothash && local_signature == signature => {}
                _ => return Ok(false),
            }
        } else if !ecdsa::verify(&self.crypto.ecdsa_pks[sender], &digest, &signature) {
            return Ok(false);
        }
        proposal.ready_by_sender.insert(sender, roothash);
        proposal
            .ready_signatures
            .entry(roothash)
            .or_default()
            .insert(sender, signature);
        Ok(true)
    }

    pub(super) fn handle_proof_diffuse(
        &self,
        round: &mut RoundState,
        sender: usize,
        leader: usize,
        proof: PrbcProof,
    ) -> Result<bool, String> {
        if leader != sender || leader >= round.nodes() || round.mvba.proof_vector[leader].is_some()
        {
            return Ok(false);
        }
        let accepted = match round.proposals[leader].output.as_ref() {
            Some(local) if local.roothash == proof.roothash => Some(local.clone()),
            _ if self.validate_prbc_proof(round, leader, &proof) => Some(proof),
            _ => None,
        };
        let Some(proof) = accepted else {
            return Ok(false);
        };
        round.mvba.proof_vector[leader] = Some(proof);
        Ok(true)
    }
}
