use super::*;

impl RustHbAcsHost {
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

    pub(super) fn provide_aba_input(
        &self,
        round: &mut RoundState,
        index: usize,
        value: bool,
    ) -> Result<bool, String> {
        if round.bkr.aba_input_sent[index] {
            return Ok(false);
        }
        round.bkr.aba_input_sent[index] = true;
        round.aba_states[index] = Some(AbaState::new(value));
        Ok(true)
    }

    pub(super) fn on_broadcast_output(
        &self,
        round: &mut RoundState,
        leader: usize,
    ) -> Result<bool, String> {
        self.provide_aba_input(round, leader, true)
    }

    pub(super) fn on_aba_decided(
        &self,
        round: &mut RoundState,
        index: usize,
        value: bool,
    ) -> Result<bool, String> {
        if round.bkr.aba_outputs[index].is_some() {
            return Ok(false);
        }
        round.bkr.aba_outputs[index] = Some(value);
        let mut changed = true;
        if round.bkr.count_ones() >= self.threshold(round) {
            for other in 0..round.nodes() {
                changed |= self.provide_aba_input(round, other, false)?;
            }
        }
        Ok(changed)
    }

    pub(super) fn current_aba_inbox(
        inboxes: &mut BTreeMap<usize, BTreeMap<usize, AbaEpochInbox>>,
        instance: usize,
        epoch: usize,
    ) -> &mut AbaEpochInbox {
        inboxes
            .entry(instance)
            .or_default()
            .entry(epoch)
            .or_default()
    }

    pub(super) fn aba_conf_index(values: [bool; 2]) -> Option<usize> {
        match values {
            [true, false] => Some(0),
            [false, true] => Some(1),
            [true, true] => Some(2),
            _ => None,
        }
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

    fn drive_coin(&self, round: &mut RoundState, scope: HbCoinScope) -> Result<bool, String> {
        let mut changed = false;
        let mut outbound_share = None;
        {
            let state = round.coin_states.entry(scope).or_default();
            if !state.local_sent {
                state.local_sent = true;
                let message = Self::coin_message(&round.sid, scope);
                let partial = threshold::sig::sign(&self.crypto.coin_sk, &message);
                let share = g1_to_bytes(&partial.value);
                state.shares.insert(self.pid, share.clone());
                outbound_share = Some(share);
                changed = true;
            }
        }
        if let Some(share) = outbound_share {
            self.queue_broadcast(round, RustHbMessage::CoinShare { scope, share })?;
        }
        let should_combine = round
            .coin_states
            .get(&scope)
            .map(|state| state.output.is_none() && state.shares.len() >= self.coin_threshold())
            .unwrap_or(false);
        if should_combine {
            let message = Self::coin_message(&round.sid, scope);
            let partials = round
                .coin_states
                .get(&scope)
                .into_iter()
                .flat_map(|state| state.shares.iter().take(self.coin_threshold()))
                .map(|(sender, share)| {
                    let value = g1_from_bytes(share)?;
                    Ok::<_, String>(PartialSignature {
                        player_id: sender + 1,
                        value,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let combined =
                threshold::sig::combine_trusted(&self.crypto.coin_pk, &message, &partials)
                    .map_err(|err| err.to_string())?;
            let digest = Sha256::digest(g1_to_bytes(&combined));
            if let Some(state) = round.coin_states.get_mut(&scope)
                && state.output.is_none()
            {
                state.output = Some(digest[0]);
            }
            changed = true;
        }
        Ok(changed)
    }

    fn drive_aba(
        &self,
        round: &mut RoundState,
        instance: usize,
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
            let inbox = Self::current_aba_inbox(&mut round.aba_inboxes, instance, epoch);
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
                RustHbMessage::AbaEst {
                    instance: instance as u32,
                    epoch: epoch as u32,
                    value,
                },
            )?;
        }

        let mut broadcast_aux = None;
        {
            let bin_values = {
                let inbox = Self::current_aba_inbox(&mut round.aba_inboxes, instance, epoch);
                inbox.bin_values
            };
            let progress = aba.epochs.entry(epoch).or_default();
            if progress.aux_sent.is_none() && (bin_values[0] || bin_values[1]) {
                let value = !bin_values[0];
                progress.aux_sent = Some(value);
                let inbox = Self::current_aba_inbox(&mut round.aba_inboxes, instance, epoch);
                Self::record_bool_message(&mut inbox.aux_by_sender, self.pid, value);
                broadcast_aux = Some(value);
                changed = true;
            }
        }
        if let Some(value) = broadcast_aux {
            self.queue_broadcast(
                round,
                RustHbMessage::AbaAux {
                    instance: instance as u32,
                    epoch: epoch as u32,
                    value,
                },
            )?;
        }

        let mut broadcast_conf = None;
        {
            let aux_result = {
                let inbox = Self::current_aba_inbox(&mut round.aba_inboxes, instance, epoch);
                self.aba_aux_result(threshold, inbox)
            };
            if let Some(values) = aux_result
                && let Some(index) = Self::aba_conf_index(values)
            {
                let progress = aba.epochs.entry(epoch).or_default();
                if !progress.conf_sent[index] {
                    progress.conf_sent[index] = true;
                    let inbox = Self::current_aba_inbox(&mut round.aba_inboxes, instance, epoch);
                    inbox.conf_by_sender.insert(self.pid, values);
                    broadcast_conf = Some(values);
                    changed = true;
                }
            }
        }
        if let Some(values) = broadcast_conf {
            self.queue_broadcast(
                round,
                RustHbMessage::AbaConf {
                    instance: instance as u32,
                    epoch: epoch as u32,
                    values,
                },
            )?;
        }

        {
            let conf_result = {
                let inbox = Self::current_aba_inbox(&mut round.aba_inboxes, instance, epoch);
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

        let scope = HbCoinScope::Aba {
            instance: instance as u32,
            epoch: epoch as u32,
        };
        changed |= self.drive_coin(round, scope)?;
        let coin_value = round
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

    pub(super) fn drive_aba_instances(&self, round: &mut RoundState) -> Result<bool, String> {
        let mut changed = false;
        for instance in 0..round.nodes() {
            let Some(mut aba) = round.aba_states[instance].take() else {
                continue;
            };
            changed |= self.drive_aba(round, instance, &mut aba)?;
            let decided = aba.output;
            round.aba_states[instance] = Some(aba);
            if let Some(value) = decided {
                changed |= self.on_aba_decided(round, instance, value)?;
            }
        }
        Ok(changed)
    }

    pub(super) fn maybe_finalize_decision(&self, round: &mut RoundState) -> Result<bool, String> {
        if round.decision_emitted {
            return Ok(false);
        }
        if !round.bkr.aba_complete() || round.bkr.count_ones() < self.threshold(round) {
            return Ok(false);
        }
        let mut selected_ids = Vec::new();
        for leader in 0..round.nodes() {
            if !matches!(round.bkr.aba_outputs[leader], Some(true)) {
                continue;
            }
            let Some(artifact) = round.proposal_ready(leader) else {
                return Ok(false);
            };
            selected_ids.push(artifact.proposal_id.clone());
        }
        round.decision_emitted = true;
        round.outbound.push_back(AcsWireEvent::Decision {
            round_id: round.round_id,
            selected_proposal_ids: selected_ids,
        });
        Ok(true)
    }

    pub(super) fn handle_aba_est(
        &self,
        round: &mut RoundState,
        sender: usize,
        instance: usize,
        epoch: usize,
        value: bool,
    ) -> Result<bool, String> {
        if instance >= round.nodes() {
            return Ok(false);
        }
        let inbox = Self::current_aba_inbox(&mut round.aba_inboxes, instance, epoch);
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
        instance: usize,
        epoch: usize,
        value: bool,
    ) -> Result<bool, String> {
        if instance >= round.nodes() {
            return Ok(false);
        }
        let inbox = Self::current_aba_inbox(&mut round.aba_inboxes, instance, epoch);
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
        instance: usize,
        epoch: usize,
        values: [bool; 2],
    ) -> Result<bool, String> {
        if instance >= round.nodes() || Self::aba_conf_index(values).is_none() {
            return Ok(false);
        }
        let inbox = Self::current_aba_inbox(&mut round.aba_inboxes, instance, epoch);
        Ok(inbox.conf_by_sender.insert(sender, values).is_none())
    }

    pub(super) fn handle_coin_share(
        &self,
        round: &mut RoundState,
        sender: usize,
        scope: HbCoinScope,
        share: Vec<u8>,
    ) -> Result<bool, String> {
        if sender >= round.nodes() {
            return Ok(false);
        }
        let state = round.coin_states.entry(scope).or_default();
        if state.shares.contains_key(&sender) {
            return Ok(false);
        }
        let message = Self::coin_message(&round.sid, scope);
        let value = match g1_from_bytes(&share) {
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
