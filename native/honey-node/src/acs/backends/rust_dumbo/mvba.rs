use super::*;

impl RustDumboAcsBackend {
    pub(super) fn maybe_start_mvba_input(&self, round: &mut RoundState) -> Result<bool, String> {
        if round.mvba.local_input.is_some() || round.valid_diffuse_count() < self.threshold(round) {
            return Ok(false);
        }
        let raw = Self::serialize_prbc_vector(&round.mvba.proof_vector);
        if !self.validate_proof_vector(round, &raw) {
            return Err(String::from("local Dumbo proof vector failed validation"));
        }
        round.mvba.local_input = Some(raw);
        Ok(true)
    }

    fn ensure_pd_local_input(&self, round: &mut RoundState) -> Result<bool, String> {
        let Some(local_input) = round.mvba.local_input.clone() else {
            return Ok(false);
        };
        let leader = self.pid;
        if round.mvba.pd[leader].input_sent {
            return Ok(false);
        }
        let data_threshold = self.data_threshold(round);
        let nodes = round.nodes();
        let encoded =
            merkle::encode(&local_input, data_threshold, nodes).map_err(|err| err.to_string())?;
        {
            let pd = &mut round.mvba.pd[leader];
            pd.input_sent = true;
            pd.input_root = Some(encoded.root);
        }
        let mut changed = false;
        for recipient in 0..nodes {
            if recipient == self.pid {
                changed |= self.process_pd_store(
                    round,
                    self.pid,
                    leader,
                    encoded.root,
                    encoded.proofs[recipient].clone(),
                    encoded.shards[recipient].clone(),
                )?;
                continue;
            }
            self.queue_send(
                round,
                recipient,
                RustDumboMessage::PdStore {
                    leader: leader as u32,
                    roothash: encoded.root,
                    stripe: encoded.shards[recipient].clone(),
                    merkle_proof: encoded.proofs[recipient].clone(),
                },
            )?;
            changed = true;
        }
        Ok(changed)
    }

    pub(super) fn process_pd_store(
        &self,
        round: &mut RoundState,
        sender: usize,
        leader: usize,
        roothash: [u8; 32],
        merkle_proof: MerkleProof,
        stripe: Vec<u8>,
    ) -> Result<bool, String> {
        if leader >= round.nodes()
            || sender != leader
            || !merkle::verify_shard(&stripe, &merkle_proof, &roothash)
        {
            return Ok(false);
        }
        let pd = &mut round.mvba.pd[leader];
        if pd.local_store.is_some() {
            return Ok(false);
        }
        let store = PdStoreRecord {
            roothash,
            stripe_owner: self.pid as u32,
            stripe,
            merkle_proof,
        };
        pd.local_store = Some(store.clone());
        round.mvba.stores.entry(leader).or_insert(store.clone());
        let share_message = Self::pd_digest(
            PD_STORED_DOMAIN,
            &Self::pd_sid(&round.sid, leader),
            &roothash,
        );
        let share = threshold::sig::sign(&self.crypto.proof_sk, &share_message)
            .value
            .to_compressed_bytes()
            .to_vec();
        if self.pid == leader {
            pd.stored_shares.insert(self.pid, share);
        } else {
            self.queue_send(
                round,
                leader,
                RustDumboMessage::PdStored {
                    leader: leader as u32,
                    roothash,
                    share,
                },
            )?;
        }
        Ok(true)
    }

    pub(super) fn process_pd_stored(
        &self,
        round: &mut RoundState,
        sender: usize,
        leader: usize,
        roothash: [u8; 32],
        share: Vec<u8>,
    ) -> Result<bool, String> {
        if leader >= round.nodes() || self.pid != leader {
            return Ok(false);
        }
        let threshold = self.threshold(round);
        let pd_sid = Self::pd_sid(&round.sid, leader);
        let digest = Self::pd_digest(PD_STORED_DOMAIN, &pd_sid, &roothash);
        let pd = &mut round.mvba.pd[leader];
        if pd.input_root != Some(roothash) || pd.stored_shares.contains_key(&sender) {
            return Ok(false);
        }
        if sender != self.pid {
            let Ok(value) = parse_g1_compressed(&share) else {
                return Ok(false);
            };
            let partial = PartialSignature {
                player_id: sender + 1,
                value,
            };
            if threshold::sig::verify_share(&self.crypto.proof_pk, &partial, &digest).is_err() {
                return Ok(false);
            }
        }
        pd.stored_shares.insert(sender, share);
        if pd.lock_sent || pd.stored_shares.len() < threshold {
            return Ok(true);
        }
        pd.lock_sent = true;
        let proof = Self::build_threshold_proof(
            &self.crypto.proof_pk,
            &pd.stored_shares,
            threshold,
            roothash,
            &digest,
        )?;
        pd.local_lock_proof = Some(proof.clone());
        let _ = pd;
        let _ = self.process_pd_lock(round, self.pid, leader, proof.clone())?;
        self.queue_broadcast(
            round,
            RustDumboMessage::PdLock {
                leader: leader as u32,
                proof,
            },
        )?;
        Ok(true)
    }

    pub(super) fn process_pd_lock(
        &self,
        round: &mut RoundState,
        sender: usize,
        leader: usize,
        proof: ThresholdProof,
    ) -> Result<bool, String> {
        if leader >= round.nodes() || sender != leader {
            return Ok(false);
        }
        let pd = &mut round.mvba.pd[leader];
        if pd.local_lock.is_some() {
            return Ok(false);
        }
        let pd_sid = Self::pd_sid(&round.sid, leader);
        let digest = Self::pd_digest(PD_STORED_DOMAIN, &pd_sid, &proof.roothash);
        if sender == self.pid {
            if pd
                .local_lock_proof
                .as_ref()
                .map(|local| local.signature.as_slice())
                != Some(proof.signature.as_slice())
            {
                return Ok(false);
            }
        } else if !Self::verify_threshold_proof(&self.crypto.proof_pk, &proof, &digest) {
            return Ok(false);
        }
        pd.local_lock = Some(proof.clone());
        round.mvba.locks.entry(leader).or_insert(proof.clone());
        let locked_digest = Self::pd_digest(PD_LOCKED_DOMAIN, &pd_sid, &proof.roothash);
        let share = threshold::sig::sign(&self.crypto.proof_sk, &locked_digest)
            .value
            .to_compressed_bytes()
            .to_vec();
        if self.pid == leader {
            pd.locked_shares.insert(self.pid, share);
        } else {
            self.queue_send(
                round,
                leader,
                RustDumboMessage::PdLocked {
                    leader: leader as u32,
                    roothash: proof.roothash,
                    share,
                },
            )?;
        }
        Ok(true)
    }

    pub(super) fn process_pd_locked(
        &self,
        round: &mut RoundState,
        sender: usize,
        leader: usize,
        roothash: [u8; 32],
        share: Vec<u8>,
    ) -> Result<bool, String> {
        if leader >= round.nodes() || self.pid != leader {
            return Ok(false);
        }
        let threshold = self.threshold(round);
        let pd = &mut round.mvba.pd[leader];
        if pd.input_root != Some(roothash) || pd.locked_shares.contains_key(&sender) {
            return Ok(false);
        }
        let pd_sid = Self::pd_sid(&round.sid, leader);
        let digest = Self::pd_digest(PD_LOCKED_DOMAIN, &pd_sid, &roothash);
        if sender != self.pid {
            let Ok(value) = parse_g1_compressed(&share) else {
                return Ok(false);
            };
            let partial = PartialSignature {
                player_id: sender + 1,
                value,
            };
            if threshold::sig::verify_share(&self.crypto.proof_pk, &partial, &digest).is_err() {
                return Ok(false);
            }
        }
        pd.locked_shares.insert(sender, share);
        if pd.done_sent || pd.locked_shares.len() < threshold {
            return Ok(true);
        }
        pd.done_sent = true;
        let proof = Self::build_threshold_proof(
            &self.crypto.proof_pk,
            &pd.locked_shares,
            threshold,
            roothash,
            &digest,
        )?;
        pd.local_done_proof = Some(proof.clone());
        let _ = pd;
        let _ = self.process_pd_done(round, self.pid, leader, proof.clone())?;
        self.queue_broadcast(
            round,
            RustDumboMessage::PdDone {
                leader: leader as u32,
                proof,
            },
        )?;
        Ok(true)
    }

    pub(super) fn process_pd_done(
        &self,
        round: &mut RoundState,
        sender: usize,
        leader: usize,
        proof: ThresholdProof,
    ) -> Result<bool, String> {
        if leader >= round.nodes() || sender != leader {
            return Ok(false);
        }
        let pd = &mut round.mvba.pd[leader];
        if pd.local_done.is_some() {
            return Ok(false);
        }
        let pd_sid = Self::pd_sid(&round.sid, leader);
        let digest = Self::pd_digest(PD_LOCKED_DOMAIN, &pd_sid, &proof.roothash);
        if sender == self.pid {
            if pd
                .local_done_proof
                .as_ref()
                .map(|local| local.signature.as_slice())
                != Some(proof.signature.as_slice())
            {
                return Ok(false);
            }
        } else if !Self::verify_threshold_proof(&self.crypto.proof_pk, &proof, &digest) {
            return Ok(false);
        }
        pd.local_done = Some(proof.clone());
        round.mvba.dones.entry(leader).or_insert(proof);
        Ok(true)
    }

    pub(super) fn drive_pd(&self, round: &mut RoundState) -> Result<bool, String> {
        self.ensure_pd_local_input(round)
    }

    fn drive_coin(&self, round: &mut RoundState, scope: DumboCoinScope) -> Result<bool, String> {
        let mut changed = false;
        let mut outbound_share = None;
        {
            let state = round.mvba.coin_states.entry(scope).or_default();
            if !state.local_sent {
                state.local_sent = true;
                let message = Self::coin_message(&round.sid, scope);
                let partial = threshold::sig::sign(&self.crypto.coin_sk, &message);
                let share = partial.value.to_compressed_bytes().to_vec();
                state.shares.insert(self.pid, share.clone());
                outbound_share = Some(share);
                changed = true;
            }
        }
        if let Some(share) = outbound_share {
            self.queue_broadcast(round, RustDumboMessage::CoinShare { scope, share })?;
        }
        let should_combine = round
            .mvba
            .coin_states
            .get(&scope)
            .map(|state| state.output.is_none() && state.shares.len() >= self.coin_threshold())
            .unwrap_or(false);
        if should_combine {
            let message = Self::coin_message(&round.sid, scope);
            let partials = round
                .mvba
                .coin_states
                .get(&scope)
                .into_iter()
                .flat_map(|state| state.shares.iter().take(self.coin_threshold()))
                .map(|(sender, share)| {
                    let value = parse_g1_compressed(share)?;
                    Ok::<_, String>(PartialSignature {
                        player_id: sender + 1,
                        value,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let combined =
                threshold::sig::combine_trusted(&self.crypto.coin_pk, &message, &partials)
                    .map_err(|err| err.to_string())?;
            let digest = Sha256::digest(combined.to_compressed_bytes());
            if let Some(state) = round.mvba.coin_states.get_mut(&scope)
                && state.output.is_none()
            {
                state.output = Some(digest[0]);
            }
            changed = true;
        }
        Ok(changed)
    }

    pub(super) fn current_prepare_inbox(
        mvba: &mut DumboMvbaState,
        round_id: usize,
    ) -> &mut RcPrepareInbox {
        mvba.rc_prepare_inboxes.entry(round_id).or_default()
    }

    pub(super) fn current_aba_inbox(
        mvba: &mut DumboMvbaState,
        round_id: usize,
        epoch: usize,
    ) -> &mut AbaEpochInbox {
        mvba.aba_inboxes
            .entry(round_id)
            .or_default()
            .entry(epoch)
            .or_default()
    }

    pub(super) fn current_recast_inbox(
        mvba: &mut DumboMvbaState,
        round_id: usize,
    ) -> &mut RcRecastInbox {
        mvba.rc_recast_inboxes.entry(round_id).or_default()
    }

    pub(super) fn aba_conf_index(values: [bool; 2]) -> Option<usize> {
        match values {
            [true, false] => Some(0),
            [false, true] => Some(1),
            [true, true] => Some(2),
            _ => None,
        }
    }

    fn record_bool_message(
        map: &mut BTreeMap<usize, [bool; 2]>,
        sender: usize,
        value: bool,
    ) -> bool {
        let entry = map.entry(sender).or_insert([false, false]);
        let idx = usize::from(value);
        if entry[idx] {
            return false;
        }
        entry[idx] = true;
        true
    }

    fn count_bool_messages(map: &BTreeMap<usize, [bool; 2]>, value: bool) -> usize {
        let idx = usize::from(value);
        map.values().filter(|flags| flags[idx]).count()
    }

    fn aba_aux_result(&self, threshold: usize, inbox: &AbaEpochInbox) -> Option<[bool; 2]> {
        if inbox.bin_values[1] && Self::count_bool_messages(&inbox.aux_by_sender, true) >= threshold
        {
            return Some([false, true]);
        }
        if inbox.bin_values[0]
            && Self::count_bool_messages(&inbox.aux_by_sender, false) >= threshold
        {
            return Some([true, false]);
        }
        let mut total = 0usize;
        if inbox.bin_values[0] {
            total += Self::count_bool_messages(&inbox.aux_by_sender, false);
        }
        if inbox.bin_values[1] {
            total += Self::count_bool_messages(&inbox.aux_by_sender, true);
        }
        if total >= threshold {
            return Some(inbox.bin_values);
        }
        None
    }

    fn aba_conf_result(&self, threshold: usize, inbox: &AbaEpochInbox) -> Option<[bool; 2]> {
        let conf0 = inbox
            .conf_by_sender
            .values()
            .filter(|values| **values == [true, false])
            .count();
        let conf1 = inbox
            .conf_by_sender
            .values()
            .filter(|values| **values == [false, true])
            .count();
        let subset = inbox
            .conf_by_sender
            .values()
            .filter(|values| {
                (!values[0] || inbox.bin_values[0])
                    && (!values[1] || inbox.bin_values[1])
                    && (values[0] || values[1])
            })
            .count();
        if inbox.bin_values[1] && conf1 >= threshold {
            return Some([false, true]);
        }
        if inbox.bin_values[0] && conf0 >= threshold {
            return Some([true, false]);
        }
        if subset >= threshold {
            return Some(inbox.bin_values);
        }
        None
    }

    fn single_conf_value(values: [bool; 2]) -> Option<bool> {
        match values {
            [true, false] => Some(false),
            [false, true] => Some(true),
            _ => None,
        }
    }

    fn ensure_active_mvba_round(&self, round: &mut RoundState) -> Result<bool, String> {
        if round.mvba.output_value.is_some()
            || round.mvba.active_round.is_some()
            || round.mvba.local_input.is_none()
            || round.mvba.dones.len() < self.threshold(round)
        {
            return Ok(false);
        }
        let round_id = round.mvba.next_mvba_round;
        let permutation_round = round_id / round.nodes();
        let permutation_index = round_id % round.nodes();
        let scope = DumboCoinScope::Election {
            permutation_round: permutation_round as u32,
        };
        let mut changed = self.drive_coin(round, scope)?;
        let Some(seed) = round
            .mvba
            .coin_states
            .get(&scope)
            .and_then(|state| state.output)
        else {
            return Ok(changed);
        };
        let nodes = round.nodes();
        round
            .mvba
            .permutations
            .entry(permutation_round)
            .or_insert_with(|| Self::leader_permutation(seed, nodes));
        let leader = round.mvba.permutations[&permutation_round][permutation_index];
        round.mvba.active_round = Some(ActiveMvbaRound::new(round_id, leader));
        changed = true;
        Ok(changed)
    }

    fn drive_rc_prepare(
        &self,
        round: &mut RoundState,
        active: &mut ActiveMvbaRound,
    ) -> Result<bool, String> {
        let mut changed = false;
        if !active.prepare_sent {
            let local_lock = round.mvba.locks.get(&active.leader).cloned();
            active.prepare_sent = true;
            let inbox = Self::current_prepare_inbox(&mut round.mvba, active.round_id);
            match local_lock.clone() {
                Some(proof) => {
                    inbox.proofs.insert(self.pid, proof.clone());
                    active.selected_lock = Some(proof.clone());
                    active.ballot = Some(true);
                    self.queue_broadcast(
                        round,
                        RustDumboMessage::RcPrepare {
                            mvba_round: active.round_id as u32,
                            leader: active.leader as u32,
                            proof: Some(proof),
                        },
                    )?;
                }
                None => {
                    inbox.none_senders.insert(self.pid);
                    self.queue_broadcast(
                        round,
                        RustDumboMessage::RcPrepare {
                            mvba_round: active.round_id as u32,
                            leader: active.leader as u32,
                            proof: None,
                        },
                    )?;
                }
            }
            changed = true;
        }
        if active.ballot.is_none() {
            let inbox = Self::current_prepare_inbox(&mut round.mvba, active.round_id);
            if let Some(proof) = inbox.proofs.values().next().cloned() {
                active.ballot = Some(true);
                active.selected_lock = Some(proof);
                changed = true;
            } else if inbox.none_senders.len() > 2 * self.faulty {
                active.ballot = Some(false);
                changed = true;
            }
        }
        Ok(changed)
    }

    fn drive_aba(
        &self,
        round: &mut RoundState,
        mvba_round: usize,
        aba: &mut AbaState,
    ) -> Result<bool, String> {
        if aba.output.is_some() {
            return Ok(false);
        }
        let mut changed = false;
        let epoch = aba.current_epoch;
        let threshold = self.threshold(round);
        let est_value = aba.est;

        let mut broadcast_est = None;
        {
            let inbox = Self::current_aba_inbox(&mut round.mvba, mvba_round, epoch);
            let progress = aba.epochs.entry(epoch).or_default();
            if !progress.est_sent[usize::from(est_value)] {
                progress.est_sent[usize::from(est_value)] = true;
                Self::record_bool_message(&mut inbox.est_by_sender, self.pid, est_value);
                if Self::count_bool_messages(&inbox.est_by_sender, est_value) > 2 * self.faulty {
                    inbox.bin_values[usize::from(est_value)] = true;
                }
                broadcast_est = Some(est_value);
                changed = true;
            }
        }
        if let Some(value) = broadcast_est {
            self.queue_broadcast(
                round,
                RustDumboMessage::AbaEst {
                    mvba_round: mvba_round as u32,
                    epoch: epoch as u32,
                    value,
                },
            )?;
        }

        let mut broadcast_aux = None;
        {
            let bin_values = {
                let inbox = Self::current_aba_inbox(&mut round.mvba, mvba_round, epoch);
                inbox.bin_values
            };
            let progress = aba.epochs.entry(epoch).or_default();
            if progress.aux_sent.is_none() && (bin_values[0] || bin_values[1]) {
                let value = !bin_values[0];
                progress.aux_sent = Some(value);
                let inbox = Self::current_aba_inbox(&mut round.mvba, mvba_round, epoch);
                Self::record_bool_message(&mut inbox.aux_by_sender, self.pid, value);
                broadcast_aux = Some(value);
                changed = true;
            }
        }
        if let Some(value) = broadcast_aux {
            self.queue_broadcast(
                round,
                RustDumboMessage::AbaAux {
                    mvba_round: mvba_round as u32,
                    epoch: epoch as u32,
                    value,
                },
            )?;
        }

        let mut broadcast_conf = None;
        {
            let aux_result = {
                let inbox = Self::current_aba_inbox(&mut round.mvba, mvba_round, epoch);
                self.aba_aux_result(threshold, inbox)
            };
            if let Some(values) = aux_result
                && let Some(index) = Self::aba_conf_index(values)
            {
                let progress = aba.epochs.entry(epoch).or_default();
                if !progress.conf_sent[index] {
                    progress.conf_sent[index] = true;
                    let inbox = Self::current_aba_inbox(&mut round.mvba, mvba_round, epoch);
                    inbox.conf_by_sender.insert(self.pid, values);
                    broadcast_conf = Some(values);
                    changed = true;
                }
            }
        }
        if let Some(values) = broadcast_conf {
            self.queue_broadcast(
                round,
                RustDumboMessage::AbaConf {
                    mvba_round: mvba_round as u32,
                    epoch: epoch as u32,
                    values,
                },
            )?;
        }

        {
            let conf_result = {
                let inbox = Self::current_aba_inbox(&mut round.mvba, mvba_round, epoch);
                self.aba_conf_result(threshold, inbox)
            };
            let progress = aba.epochs.entry(epoch).or_default();
            if progress.conf_result.is_none() {
                progress.conf_result = conf_result;
            }
        }
        let Some(values) = aba
            .epochs
            .get(&epoch)
            .and_then(|progress| progress.conf_result)
        else {
            return Ok(changed);
        };

        let scope = DumboCoinScope::Aba {
            mvba_round: mvba_round as u32,
            epoch: epoch as u32,
        };
        changed |= self.drive_coin(round, scope)?;
        let coin_value = round
            .mvba
            .coin_states
            .get(&scope)
            .and_then(|state| state.output)
            .map(|value| value % 2 == 0);
        let progress = aba.epochs.entry(epoch).or_default();
        progress.coin_value = coin_value;
        let Some(coin_value) = progress.coin_value else {
            return Ok(changed);
        };

        if let Some(single) = Self::single_conf_value(values) {
            if single == coin_value {
                aba.output = Some(single);
                return Ok(true);
            }
            aba.current_epoch += 1;
            aba.est = single;
            aba.epochs
                .retain(|existing, _| *existing + 2 >= aba.current_epoch);
            return Ok(true);
        }

        aba.current_epoch += 1;
        aba.est = coin_value;
        aba.epochs
            .retain(|existing, _| *existing + 2 >= aba.current_epoch);
        Ok(true)
    }

    fn drive_recast(
        &self,
        round: &mut RoundState,
        leader: usize,
        mvba_round: usize,
        recast: &mut RecastState,
    ) -> Result<bool, String> {
        let mut changed = false;
        if !recast.lock_sent {
            recast.lock_sent = true;
            self.queue_broadcast(
                round,
                RustDumboMessage::RcLock {
                    mvba_round: mvba_round as u32,
                    leader: leader as u32,
                    proof: recast.selected_lock.clone(),
                },
            )?;
            changed = true;
        }
        if !recast.store_sent
            && let Some(store) = round.mvba.stores.get(&leader).cloned()
        {
            recast.store_sent = true;
            recast
                .stripes_by_root
                .entry(store.roothash)
                .or_default()
                .insert(
                    store.stripe_owner as usize,
                    (store.stripe.clone(), store.merkle_proof.clone()),
                );
            self.queue_broadcast(
                round,
                RustDumboMessage::RcStore {
                    mvba_round: mvba_round as u32,
                    leader: leader as u32,
                    store,
                },
            )?;
            changed = true;
        }
        if let Some(inbox) = round.mvba.rc_recast_inboxes.get(&mvba_round) {
            for proof in inbox.locks.values() {
                recast.selected_lock = proof.clone();
            }
            for store in inbox.stores.values() {
                recast
                    .stripes_by_root
                    .entry(store.roothash)
                    .or_default()
                    .insert(
                        store.stripe_owner as usize,
                        (store.stripe.clone(), store.merkle_proof.clone()),
                    );
            }
        }
        let Some(stripes) = recast.stripes_by_root.get(&recast.selected_lock.roothash) else {
            return Ok(changed);
        };
        if stripes.len() < self.data_threshold(round) {
            return Ok(changed);
        }
        let available = stripes
            .iter()
            .map(|(owner, (stripe, proof))| (*owner, stripe.clone(), proof.clone()))
            .collect::<Vec<_>>();
        let value = merkle::decode_owned(
            available,
            &recast.selected_lock.roothash,
            self.data_threshold(round),
            round.nodes(),
        )
        .map_err(|err| err.to_string())?;
        let check = merkle::encode(&value, self.data_threshold(round), round.nodes())
            .map_err(|err| err.to_string())?;
        if check.root != recast.selected_lock.roothash {
            return Ok(changed);
        }
        if recast.output_value.is_none() {
            recast.output_value = Some(value);
            changed = true;
        }
        Ok(changed)
    }

    pub(super) fn drive_mvba(&self, round: &mut RoundState) -> Result<bool, String> {
        let mut changed = false;
        changed |= self.ensure_active_mvba_round(round)?;

        let Some(mut active) = round.mvba.active_round.take() else {
            return Ok(changed);
        };
        changed |= self.drive_rc_prepare(round, &mut active)?;

        if active.aba.is_none()
            && let Some(ballot) = active.ballot
        {
            active.aba = Some(AbaState::new(ballot));
            changed = true;
        }

        if let Some(aba) = active.aba.as_mut() {
            changed |= self.drive_aba(round, active.round_id, aba)?;
            if let Some(output) = aba.output {
                if !output {
                    round.mvba.next_mvba_round = active.round_id + 1;
                    changed = true;
                    return Ok(changed);
                }
                if active.recast.is_none() {
                    let lock = active
                        .selected_lock
                        .clone()
                        .or_else(|| round.mvba.locks.get(&active.leader).cloned())
                        .ok_or_else(|| {
                            String::from("Dumbo ABA selected a leader without a lock proof")
                        })?;
                    active.recast = Some(RecastState::new(lock));
                    changed = true;
                }
            }
        }

        if let Some(recast) = active.recast.as_mut() {
            changed |= self.drive_recast(round, active.leader, active.round_id, recast)?;
            if let Some(value) = recast.output_value.clone() {
                round.mvba.output_value = Some(value);
                changed = true;
                return Ok(changed);
            }
        }

        round.mvba.active_round = Some(active);
        Ok(changed)
    }

    pub(super) fn maybe_finalize_decision(&self, round: &mut RoundState) -> Result<bool, String> {
        if round.decision_emitted {
            return Ok(false);
        }
        if round.selected_proofs.is_none() {
            let Some(raw_value) = round.mvba.output_value.as_ref() else {
                return Ok(false);
            };
            let proofs = Self::deserialize_prbc_vector(raw_value, round.nodes())?;
            if proofs.iter().filter(|proof| proof.is_some()).count() < self.threshold(round) {
                return Err(String::from(
                    "Dumbo MVBA decided fewer than N-f PRBC proofs",
                ));
            }
            round.selected_proofs = Some(proofs);
        }
        let selected = round
            .selected_proofs
            .as_ref()
            .ok_or_else(|| String::from("missing Dumbo selected proof vector"))?;
        let mut selected_ids = Vec::new();
        for (leader, selected_proof) in selected.iter().enumerate() {
            let Some(selected_proof) = selected_proof.as_ref() else {
                continue;
            };
            let Some(local_proof) = round.proposals[leader].output.as_ref() else {
                return Ok(false);
            };
            if local_proof.roothash != selected_proof.roothash {
                return Err(format!(
                    "selected PRBC proof for leader {leader} mismatched local PRBC output"
                ));
            }
            let Some(artifact) = round.proposals[leader].proposal_ready.as_ref() else {
                return Ok(false);
            };
            selected_ids.push(artifact.proposal_id.clone());
        }
        round.decision_emitted = true;
        round.outbound.push_back(AcsEvent::Decided {
            round_id: round.round_id,
            selected_proposal_ids: selected_ids,
        });
        Ok(true)
    }

    pub(super) fn handle_rc_prepare(
        &self,
        round: &mut RoundState,
        sender: usize,
        mvba_round: usize,
        leader: usize,
        proof: Option<ThresholdProof>,
    ) -> Result<bool, String> {
        if leader >= round.nodes() {
            return Ok(false);
        }
        let inbox = Self::current_prepare_inbox(&mut round.mvba, mvba_round);
        match proof {
            None => Ok(inbox.none_senders.insert(sender)),
            Some(proof) => {
                if inbox.proofs.contains_key(&sender) {
                    return Ok(false);
                }
                let digest = Self::pd_digest(
                    PD_STORED_DOMAIN,
                    &Self::pd_sid(&round.sid, leader),
                    &proof.roothash,
                );
                if !Self::verify_threshold_proof(&self.crypto.proof_pk, &proof, &digest) {
                    return Ok(false);
                }
                inbox.proofs.insert(sender, proof);
                Ok(true)
            }
        }
    }

    pub(super) fn handle_rc_lock(
        &self,
        round: &mut RoundState,
        sender: usize,
        mvba_round: usize,
        leader: usize,
        proof: ThresholdProof,
    ) -> Result<bool, String> {
        if leader >= round.nodes() {
            return Ok(false);
        }
        let digest = Self::pd_digest(
            PD_STORED_DOMAIN,
            &Self::pd_sid(&round.sid, leader),
            &proof.roothash,
        );
        if !Self::verify_threshold_proof(&self.crypto.proof_pk, &proof, &digest) {
            return Ok(false);
        }
        let inbox = Self::current_recast_inbox(&mut round.mvba, mvba_round);
        Ok(inbox.locks.insert(sender, proof).is_none())
    }

    pub(super) fn handle_rc_store(
        &self,
        round: &mut RoundState,
        _sender: usize,
        mvba_round: usize,
        leader: usize,
        store: PdStoreRecord,
    ) -> Result<bool, String> {
        if leader >= round.nodes()
            || store.stripe_owner as usize >= round.nodes()
            || !merkle::verify_shard(&store.stripe, &store.merkle_proof, &store.roothash)
        {
            return Ok(false);
        }
        let key = (store.roothash, store.stripe_owner);
        let inbox = Self::current_recast_inbox(&mut round.mvba, mvba_round);
        Ok(inbox.stores.insert(key, store).is_none())
    }

    pub(super) fn handle_aba_est(
        &self,
        round: &mut RoundState,
        sender: usize,
        mvba_round: usize,
        epoch: usize,
        value: bool,
    ) -> Result<bool, String> {
        let inbox = Self::current_aba_inbox(&mut round.mvba, mvba_round, epoch);
        let changed = Self::record_bool_message(&mut inbox.est_by_sender, sender, value);
        if changed && Self::count_bool_messages(&inbox.est_by_sender, value) > 2 * self.faulty {
            inbox.bin_values[usize::from(value)] = true;
        }
        Ok(changed)
    }

    pub(super) fn handle_aba_aux(
        &self,
        round: &mut RoundState,
        sender: usize,
        mvba_round: usize,
        epoch: usize,
        value: bool,
    ) -> Result<bool, String> {
        let inbox = Self::current_aba_inbox(&mut round.mvba, mvba_round, epoch);
        Ok(Self::record_bool_message(
            &mut inbox.aux_by_sender,
            sender,
            value,
        ))
    }

    pub(super) fn handle_aba_conf(
        &self,
        round: &mut RoundState,
        sender: usize,
        mvba_round: usize,
        epoch: usize,
        values: [bool; 2],
    ) -> Result<bool, String> {
        if Self::aba_conf_index(values).is_none() {
            return Ok(false);
        }
        let inbox = Self::current_aba_inbox(&mut round.mvba, mvba_round, epoch);
        Ok(inbox.conf_by_sender.insert(sender, values).is_none())
    }

    pub(super) fn handle_coin_share(
        &self,
        round: &mut RoundState,
        sender: usize,
        scope: DumboCoinScope,
        share: Vec<u8>,
    ) -> Result<bool, String> {
        if sender >= round.nodes() {
            return Ok(false);
        }
        let state = round.mvba.coin_states.entry(scope).or_default();
        if state.shares.contains_key(&sender) {
            return Ok(false);
        }
        let message = Self::coin_message(&round.sid, scope);
        let value = match parse_g1_compressed(&share) {
            Ok(value) => value,
            Err(_) => return Ok(false),
        };
        let partial = PartialSignature {
            player_id: sender + 1,
            value,
        };
        if sender != self.pid
            && threshold::sig::verify_share(&self.crypto.coin_pk, &partial, &message).is_err()
        {
            return Ok(false);
        }
        state.shares.insert(sender, share);
        Ok(true)
    }
}
