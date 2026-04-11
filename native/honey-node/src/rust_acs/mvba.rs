use super::*;

impl RustAcsHost {
    fn validate_wrbc_value(&self, round: &RoundState, value: &[u8]) -> bool {
        let bits = match Self::decode_completion_vector(value, round.nodes()) {
            Ok(bits) => bits,
            Err(_) => return false,
        };
        let mut count = 0usize;
        for (index, present) in bits.iter().enumerate() {
            if !present {
                continue;
            }
            if round.proposals[index].proposal_ready.is_none() {
                return false;
            }
            count += 1;
        }
        count >= self.threshold(round)
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

    fn count_total_bool_messages(map: &BTreeMap<usize, [bool; 2]>) -> usize {
        map.values()
            .map(|flags| usize::from(flags[0]) + usize::from(flags[1]))
            .sum()
    }

    fn activate_wrbc_send_if_valid(
        &self,
        round: &mut RoundState,
        proposer: usize,
    ) -> Result<bool, String> {
        let (value, digest) = {
            let instance = &round.mvba.wrbc[proposer];
            if instance.echo_sent {
                return Ok(false);
            }
            let Some(value) = instance.send_value.clone() else {
                return Ok(false);
            };
            let digest = instance
                .send_digest
                .unwrap_or_else(|| Self::payload_digest(&value));
            (value, digest)
        };
        if !self.validate_wrbc_value(round, &value) {
            return Ok(false);
        }
        let instance = &mut round.mvba.wrbc[proposer];
        if instance.echo_sent {
            return Ok(false);
        }
        instance.echo_sent = true;
        instance.echo_by_sender.insert(self.pid, digest);
        instance.known_values.entry(digest).or_insert(value);
        self.queue_broadcast(
            round,
            RustAcsMessage::WrbcEcho {
                proposer: proposer as u32,
                digest,
            },
        )?;
        Ok(true)
    }

    pub(super) fn drive_wrbc(&self, round: &mut RoundState) -> Result<bool, String> {
        let mut changed = false;
        let threshold = self.threshold(round);
        for proposer in 0..round.nodes() {
            changed |= self.activate_wrbc_send_if_valid(round, proposer)?;
            let mut send_ready_for = None;
            let mut deliver_for = None;
            {
                let instance = &round.mvba.wrbc[proposer];
                if instance.delivered_digest.is_none() {
                    let digests = instance
                        .echo_by_sender
                        .values()
                        .copied()
                        .chain(instance.ready_by_sender.values().copied())
                        .collect::<Vec<_>>();
                    for digest in digests {
                        let echo_count =
                            Self::count_matching_sender_map(&instance.echo_by_sender, &digest);
                        let ready_count =
                            Self::count_matching_sender_map(&instance.ready_by_sender, &digest);
                        if !instance.ready_sent
                            && (echo_count >= threshold || ready_count > self.faulty)
                        {
                            send_ready_for = Some(digest);
                        }
                        if ready_count >= threshold {
                            deliver_for = Some(digest);
                            break;
                        }
                    }
                }
            }
            if let Some(digest) = send_ready_for {
                let instance = &mut round.mvba.wrbc[proposer];
                if !instance.ready_sent {
                    instance.ready_sent = true;
                    instance.ready_by_sender.insert(self.pid, digest);
                    self.queue_broadcast(
                        round,
                        RustAcsMessage::WrbcReady {
                            proposer: proposer as u32,
                            digest,
                        },
                    )?;
                    changed = true;
                }
            }
            if let Some(digest) = deliver_for {
                let instance = &mut round.mvba.wrbc[proposer];
                if instance.delivered_digest.is_none() {
                    instance.delivered_digest = Some(digest);
                    if let Some(value) = instance.known_values.get(&digest) {
                        instance.delivered_value = Some(value.clone());
                    }
                    changed = true;
                }
            }
        }
        Ok(changed)
    }

    fn drive_coin(&self, round: &mut RoundState, scope: CoinScope) -> Result<bool, String> {
        let mut changed = false;
        let mut outbound_share = None;
        {
            let state = round.mvba.coin_states.entry(scope).or_default();
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
            self.queue_broadcast(round, RustAcsMessage::CoinShare { scope, share })?;
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
            if let Some(state) = round.mvba.coin_states.get_mut(&scope)
                && state.output.is_none()
            {
                state.output = Some(digest[0]);
            }
            changed = true;
        }
        Ok(changed)
    }

    fn send_wrbc_local_input(&self, round: &mut RoundState) -> Result<bool, String> {
        if round.mvba.started {
            return Ok(false);
        }
        if round.prbc_completion_count() < self.threshold(round) {
            return Ok(false);
        }
        round.mvba.started = true;
        let local_input = Self::encode_completion_vector(&round.completion_vector());
        round.mvba.local_input = Some(local_input.clone());
        let instance = &mut round.mvba.wrbc[self.pid];
        instance.send_digest = Some(Self::payload_digest(&local_input));
        instance.send_value = Some(local_input.clone());
        instance
            .known_values
            .entry(instance.send_digest.expect("local digest must exist"))
            .or_insert(local_input.clone());
        self.queue_broadcast(
            round,
            RustAcsMessage::WrbcSend {
                proposer: self.pid as u32,
                value: local_input,
            },
        )?;
        Ok(true)
    }

    fn start_iteration_if_ready(&self, round: &mut RoundState) -> Result<bool, String> {
        if !round.mvba.started || round.mvba.output_value.is_some() {
            return Ok(false);
        }
        if round.mvba.current_iteration.is_some() {
            return Ok(false);
        }
        if round.wrbc_completion_count() < self.threshold(round) {
            return Ok(false);
        }
        round.mvba.current_iteration = Some(MvbaIterationState {
            index: 0,
            leader: None,
            raba: None,
        });
        Ok(true)
    }

    fn current_iteration_index(round: &RoundState) -> Option<usize> {
        round
            .mvba
            .current_iteration
            .as_ref()
            .map(|state| state.index)
    }

    fn start_raba_messages(
        &self,
        round: &mut RoundState,
        iteration: usize,
        loop_state: &mut RabaLoopState,
    ) -> Result<bool, String> {
        let mut changed = false;
        let initial_value = loop_state.input;
        let value_idx = usize::from(initial_value);
        if !loop_state.val_sent[value_idx] {
            loop_state.val_sent[value_idx] = true;
            Self::record_bool_message(&mut loop_state.val_by_sender, self.pid, initial_value);
            self.queue_broadcast(
                round,
                RustAcsMessage::RabaVal {
                    iteration: iteration as u32,
                    loop_index: loop_state.index as u32,
                    value: initial_value,
                },
            )?;
            changed = true;
        }
        if loop_state.index == 0 && initial_value && !loop_state.aux_sent[1] {
            loop_state.values[1] = true;
            loop_state.aux_sent[1] = true;
            Self::record_bool_message(&mut loop_state.aux_by_sender, self.pid, true);
            self.queue_broadcast(
                round,
                RustAcsMessage::RabaAux {
                    iteration: iteration as u32,
                    loop_index: loop_state.index as u32,
                    value: true,
                },
            )?;
            changed = true;
        }
        Ok(changed)
    }

    fn maybe_repropose_raba_true(
        &self,
        round: &mut RoundState,
        raba: &mut RabaState,
    ) -> Result<bool, String> {
        if raba.current_loop.index != 0 || raba.current_loop.reproposed_true {
            return Ok(false);
        }
        if raba.current_loop.input {
            return Ok(false);
        }
        if round.mvba.wrbc[raba.leader].delivered_digest.is_none() {
            return Ok(false);
        }
        raba.current_loop.reproposed_true = true;
        let mut changed = false;
        if !raba.current_loop.val_sent[1] {
            raba.current_loop.val_sent[1] = true;
            Self::record_bool_message(&mut raba.current_loop.val_by_sender, self.pid, true);
            self.queue_broadcast(
                round,
                RustAcsMessage::RabaVal {
                    iteration: raba.iteration as u32,
                    loop_index: 0,
                    value: true,
                },
            )?;
            changed = true;
        }
        if !raba.current_loop.aux_sent[1] {
            raba.current_loop.values[1] = true;
            raba.current_loop.aux_sent[1] = true;
            Self::record_bool_message(&mut raba.current_loop.aux_by_sender, self.pid, true);
            self.queue_broadcast(
                round,
                RustAcsMessage::RabaAux {
                    iteration: raba.iteration as u32,
                    loop_index: 0,
                    value: true,
                },
            )?;
            changed = true;
        }
        Ok(changed)
    }

    fn insert_raba_future(raba: &mut RabaState, loop_index: usize, message: BufferedRabaMessage) {
        raba.future_messages
            .entry(loop_index)
            .or_default()
            .push(message);
    }

    fn handle_raba_buffered_message(raba: &mut RabaState, message: BufferedRabaMessage) -> bool {
        match message {
            BufferedRabaMessage::Val {
                sender,
                loop_index,
                value,
            } => {
                if loop_index < raba.current_loop.index {
                    return false;
                }
                if loop_index > raba.current_loop.index {
                    Self::insert_raba_future(
                        raba,
                        loop_index,
                        BufferedRabaMessage::Val {
                            sender,
                            loop_index,
                            value,
                        },
                    );
                    return false;
                }
                Self::record_bool_message(&mut raba.current_loop.val_by_sender, sender, value)
            }
            BufferedRabaMessage::Aux {
                sender,
                loop_index,
                value,
            } => {
                if loop_index < raba.current_loop.index {
                    return false;
                }
                if loop_index > raba.current_loop.index {
                    Self::insert_raba_future(
                        raba,
                        loop_index,
                        BufferedRabaMessage::Aux {
                            sender,
                            loop_index,
                            value,
                        },
                    );
                    return false;
                }
                Self::record_bool_message(&mut raba.current_loop.aux_by_sender, sender, value)
            }
            BufferedRabaMessage::Conf {
                sender,
                loop_index,
                values,
            } => {
                if loop_index < raba.current_loop.index {
                    return false;
                }
                if loop_index > raba.current_loop.index {
                    Self::insert_raba_future(
                        raba,
                        loop_index,
                        BufferedRabaMessage::Conf {
                            sender,
                            loop_index,
                            values,
                        },
                    );
                    return false;
                }
                if raba.current_loop.conf_by_sender.contains_key(&sender) {
                    return false;
                }
                raba.current_loop.conf_by_sender.insert(sender, values);
                true
            }
            BufferedRabaMessage::Finish { sender, value } => {
                if raba.finish_by_sender.contains_key(&sender) {
                    return false;
                }
                raba.finish_by_sender.insert(sender, value);
                true
            }
        }
    }

    fn drain_raba_current_loop_messages(raba: &mut RabaState) -> bool {
        let Some(buffered) = raba.future_messages.remove(&raba.current_loop.index) else {
            return false;
        };
        let mut changed = false;
        for message in buffered {
            changed |= Self::handle_raba_buffered_message(raba, message);
        }
        changed
    }

    fn maybe_send_raba_aux(
        &self,
        round: &mut RoundState,
        raba: &mut RabaState,
        value: bool,
    ) -> Result<bool, String> {
        let idx = usize::from(value);
        if raba.current_loop.aux_sent[idx] {
            return Ok(false);
        }
        raba.current_loop.aux_sent[idx] = true;
        Self::record_bool_message(&mut raba.current_loop.aux_by_sender, self.pid, value);
        self.queue_broadcast(
            round,
            RustAcsMessage::RabaAux {
                iteration: raba.iteration as u32,
                loop_index: raba.current_loop.index as u32,
                value,
            },
        )?;
        Ok(true)
    }

    fn maybe_send_raba_val(
        &self,
        round: &mut RoundState,
        raba: &mut RabaState,
        value: bool,
    ) -> Result<bool, String> {
        let idx = usize::from(value);
        if raba.current_loop.val_sent[idx] {
            return Ok(false);
        }
        raba.current_loop.val_sent[idx] = true;
        Self::record_bool_message(&mut raba.current_loop.val_by_sender, self.pid, value);
        self.queue_broadcast(
            round,
            RustAcsMessage::RabaVal {
                iteration: raba.iteration as u32,
                loop_index: raba.current_loop.index as u32,
                value,
            },
        )?;
        Ok(true)
    }

    fn maybe_send_raba_conf(
        &self,
        round: &mut RoundState,
        raba: &mut RabaState,
    ) -> Result<bool, String> {
        if raba.current_loop.conf_sent {
            return Ok(false);
        }
        let loop_state = &raba.current_loop;
        let aux0ready =
            Self::count_bool_messages(&loop_state.aux_by_sender, false) >= self.threshold(round);
        let aux1ready =
            Self::count_bool_messages(&loop_state.aux_by_sender, true) >= self.threshold(round);
        let auxmixready =
            Self::count_total_bool_messages(&loop_state.aux_by_sender) >= self.threshold(round);
        let conf_ready = (loop_state.values[0] && aux0ready)
            || (loop_state.values[1] && aux1ready)
            || (loop_state.values[0] && loop_state.values[1] && auxmixready);
        if !conf_ready {
            return Ok(false);
        }
        raba.current_loop.conf_sent = true;
        raba.current_loop
            .conf_by_sender
            .insert(self.pid, raba.current_loop.values);
        self.queue_broadcast(
            round,
            RustAcsMessage::RabaConf {
                iteration: raba.iteration as u32,
                loop_index: raba.current_loop.index as u32,
                values: raba.current_loop.values,
            },
        )?;
        Ok(true)
    }

    fn maybe_send_raba_finish(
        &self,
        round: &mut RoundState,
        raba: &mut RabaState,
        value: bool,
    ) -> Result<bool, String> {
        if raba.finish_sent.is_some() {
            return Ok(false);
        }
        raba.finish_sent = Some(value);
        raba.finish_by_sender.insert(self.pid, value);
        self.queue_broadcast(
            round,
            RustAcsMessage::RabaFinish {
                iteration: raba.iteration as u32,
                value,
            },
        )?;
        Ok(true)
    }

    fn start_next_raba_loop(
        &self,
        round: &mut RoundState,
        raba: &mut RabaState,
        input: bool,
    ) -> Result<bool, String> {
        let next_index = raba.current_loop.index + 1;
        raba.current_loop = RabaLoopState::new(next_index, input);
        let mut changed =
            self.start_raba_messages(round, raba.iteration, &mut raba.current_loop)?;
        changed |= Self::drain_raba_current_loop_messages(raba);
        Ok(changed)
    }

    fn drive_raba(&self, round: &mut RoundState, raba: &mut RabaState) -> Result<bool, String> {
        let mut changed = false;
        changed |= Self::drain_raba_current_loop_messages(raba);
        changed |= self.maybe_repropose_raba_true(round, raba)?;

        let val0 = Self::count_bool_messages(&raba.current_loop.val_by_sender, false);
        let val1 = Self::count_bool_messages(&raba.current_loop.val_by_sender, true);
        if val0 > self.faulty {
            changed |= self.maybe_send_raba_val(round, raba, false)?;
        }
        if val1 > self.faulty {
            changed |= self.maybe_send_raba_val(round, raba, true)?;
        }
        if val0 >= self.threshold(round) {
            raba.current_loop.values[0] = true;
            if !raba.current_loop.aux_sent[0] && !raba.current_loop.aux_sent[1] {
                changed |= self.maybe_send_raba_aux(round, raba, false)?;
            }
        }
        if val1 >= self.threshold(round) {
            raba.current_loop.values[1] = true;
            if !raba.current_loop.aux_sent[0] && !raba.current_loop.aux_sent[1] {
                changed |= self.maybe_send_raba_aux(round, raba, true)?;
            }
        }

        changed |= self.maybe_send_raba_conf(round, raba)?;

        let finish_false = raba
            .finish_by_sender
            .values()
            .filter(|value| !**value)
            .count();
        let finish_true = raba
            .finish_by_sender
            .values()
            .filter(|value| **value)
            .count();
        if finish_false > self.faulty {
            changed |= self.maybe_send_raba_finish(round, raba, false)?;
        }
        if finish_true > self.faulty {
            changed |= self.maybe_send_raba_finish(round, raba, true)?;
        }
        if finish_false >= self.threshold(round) && raba.output.is_none() {
            raba.output = Some(false);
            return Ok(true);
        }
        if finish_true >= self.threshold(round) && raba.output.is_none() {
            raba.output = Some(true);
            return Ok(true);
        }

        let mut conf0 = 0usize;
        let mut conf1 = 0usize;
        let mut confmix = 0usize;
        for values in raba.current_loop.conf_by_sender.values() {
            if values[0] && values[1] {
                confmix += 1;
            } else if values[0] {
                conf0 += 1;
                confmix += 1;
            } else if values[1] {
                conf1 += 1;
                confmix += 1;
            }
        }
        let coin_ready = (raba.current_loop.values[0] && conf0 >= self.threshold(round))
            || (raba.current_loop.values[1] && conf1 >= self.threshold(round))
            || (raba.current_loop.values[0]
                && raba.current_loop.values[1]
                && confmix >= self.threshold(round));
        if !coin_ready || raba.current_loop.resolved {
            return Ok(changed);
        }

        if raba.current_loop.index == 0 {
            raba.current_loop.coin_value = Some(true);
        } else {
            let scope = CoinScope::Raba {
                iteration: raba.iteration as u32,
                loop_index: raba.current_loop.index as u32,
            };
            changed |= self.drive_coin(round, scope)?;
            if let Some(output) = round
                .mvba
                .coin_states
                .get(&scope)
                .and_then(|state| state.output)
            {
                raba.current_loop.coin_requested = true;
                raba.current_loop.coin_value = Some(output % 2 == 0);
            }
        }
        let Some(coin) = raba.current_loop.coin_value else {
            return Ok(changed);
        };
        raba.current_loop.resolved = true;

        if raba.current_loop.values[0] && raba.current_loop.values[1] {
            changed |= self.start_next_raba_loop(round, raba, coin)?;
            return Ok(changed);
        }
        if raba.current_loop.values[0] && !coin {
            changed |= self.maybe_send_raba_finish(round, raba, false)?;
            return Ok(changed);
        }
        if raba.current_loop.values[1] && coin {
            changed |= self.maybe_send_raba_finish(round, raba, true)?;
            return Ok(changed);
        }
        let next_input = raba.current_loop.values[1];
        changed |= self.start_next_raba_loop(round, raba, next_input)?;
        Ok(changed)
    }

    pub(super) fn drive_mvba(&self, round: &mut RoundState) -> Result<bool, String> {
        let mut changed = false;
        changed |= self.send_wrbc_local_input(round)?;
        changed |= self.start_iteration_if_ready(round)?;

        let Some(iteration_index) = Self::current_iteration_index(round) else {
            return Ok(changed);
        };

        let election_scope = CoinScope::Election {
            iteration: iteration_index as u32,
        };
        changed |= self.drive_coin(round, election_scope)?;
        let leader = round
            .mvba
            .coin_states
            .get(&election_scope)
            .and_then(|state| state.output)
            .map(|value| (value as usize) % round.nodes());

        let Some(mut iteration) = round.mvba.current_iteration.take() else {
            return Ok(changed);
        };
        if iteration.leader.is_none()
            && let Some(leader) = leader
        {
            iteration.leader = Some(leader);
            changed = true;
        }

        if iteration.raba.is_none()
            && let Some(leader) = iteration.leader
        {
            let input = round.mvba.wrbc[leader].delivered_digest.is_some();
            let mut raba = RabaState::new(iteration.index, leader, input);
            changed |= self.start_raba_messages(round, raba.iteration, &mut raba.current_loop)?;
            if let Some(buffered) = round.mvba.future_raba_messages.remove(&iteration.index) {
                for message in buffered {
                    changed |= Self::handle_raba_buffered_message(&mut raba, message);
                }
            }
            iteration.raba = Some(raba);
        }

        let mut advance_iteration = None;
        let mut decide_mvba = None;
        if let Some(raba) = iteration.raba.as_mut() {
            changed |= self.drive_raba(round, raba)?;
            if let Some(output) = raba.output {
                if output {
                    let leader = raba.leader;
                    let (outbound_value, delivered_value) = {
                        let wrbc = &mut round.mvba.wrbc[leader];
                        if let Some(digest) = wrbc.delivered_digest {
                            if wrbc.delivered_value.is_none()
                                && let Some(value) = wrbc.known_values.get(&digest)
                            {
                                wrbc.delivered_value = Some(value.clone());
                                changed = true;
                            }
                            let outbound_value = if !wrbc.value_broadcasted {
                                wrbc.known_values.get(&digest).cloned()
                            } else {
                                None
                            };
                            if outbound_value.is_some() {
                                wrbc.value_broadcasted = true;
                            }
                            (outbound_value, wrbc.delivered_value.clone())
                        } else {
                            (None, None)
                        }
                    };
                    if let Some(value) = outbound_value {
                        self.queue_broadcast(
                            round,
                            RustAcsMessage::WrbcValue {
                                proposer: leader as u32,
                                value,
                            },
                        )?;
                        changed = true;
                    }
                    if let Some(value) = delivered_value {
                        decide_mvba = Some(value);
                    }
                } else {
                    advance_iteration = Some(iteration.index + 1);
                }
            }
        }

        if let Some(value) = decide_mvba {
            round.mvba.output_value = Some(value);
            changed = true;
        } else if let Some(next_iteration) = advance_iteration {
            round.mvba.current_iteration = Some(MvbaIterationState {
                index: next_iteration,
                leader: None,
                raba: None,
            });
            changed = true;
        } else {
            round.mvba.current_iteration = Some(iteration);
        }

        Ok(changed)
    }

    pub(super) fn maybe_finalize_decision(&self, round: &mut RoundState) -> Result<bool, String> {
        if round.decision_emitted {
            return Ok(false);
        }
        if round.decision_vector.is_none() {
            let Some(raw_value) = round.mvba.output_value.as_ref() else {
                return Ok(false);
            };
            let bits = Self::decode_completion_vector(raw_value, round.nodes())?;
            let selected = bits.iter().filter(|bit| **bit).count();
            if selected < self.threshold(round) {
                return Err(String::from(
                    "MVBA decided an invalid completion vector for ACS",
                ));
            }
            round.decision_vector = Some(bits);
        }
        let bits = round
            .decision_vector
            .as_ref()
            .ok_or_else(|| String::from("missing ACS decision vector"))?;
        let mut selected_ids = Vec::new();
        for (proposer, selected) in bits.iter().enumerate() {
            if !selected {
                continue;
            }
            let Some(artifact) = round.proposals[proposer].proposal_ready.as_ref() else {
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

    pub(super) fn handle_wrbc_send(
        &self,
        round: &mut RoundState,
        sender: usize,
        proposer: usize,
        value: Vec<u8>,
    ) -> Result<(), String> {
        if proposer >= round.nodes() || sender != proposer {
            return Ok(());
        }
        if Self::decode_completion_vector(&value, round.nodes()).is_err() {
            return Ok(());
        }
        let digest = Self::payload_digest(&value);
        let instance = &mut round.mvba.wrbc[proposer];
        if let Some(existing) = instance.send_digest {
            if existing != digest {
                return Ok(());
            }
            return Ok(());
        }
        instance.send_digest = Some(digest);
        instance.send_value = Some(value.clone());
        instance.known_values.entry(digest).or_insert(value);
        self.drive_round(round)
    }

    pub(super) fn handle_wrbc_echo(
        &self,
        round: &mut RoundState,
        sender: usize,
        proposer: usize,
        digest: [u8; 32],
    ) -> Result<(), String> {
        if proposer >= round.nodes() {
            return Ok(());
        }
        let instance = &mut round.mvba.wrbc[proposer];
        if let Some(existing) = instance.echo_by_sender.get(&sender) {
            if *existing != digest {
                return Ok(());
            }
            return Ok(());
        }
        instance.echo_by_sender.insert(sender, digest);
        self.drive_round(round)
    }

    pub(super) fn handle_wrbc_ready(
        &self,
        round: &mut RoundState,
        sender: usize,
        proposer: usize,
        digest: [u8; 32],
    ) -> Result<(), String> {
        if proposer >= round.nodes() {
            return Ok(());
        }
        let instance = &mut round.mvba.wrbc[proposer];
        if let Some(existing) = instance.ready_by_sender.get(&sender) {
            if *existing != digest {
                return Ok(());
            }
            return Ok(());
        }
        instance.ready_by_sender.insert(sender, digest);
        self.drive_round(round)
    }

    pub(super) fn handle_wrbc_value(
        &self,
        round: &mut RoundState,
        _sender: usize,
        proposer: usize,
        value: Vec<u8>,
    ) -> Result<(), String> {
        if proposer >= round.nodes() {
            return Ok(());
        }
        let digest = Self::payload_digest(&value);
        let instance = &mut round.mvba.wrbc[proposer];
        instance.known_values.entry(digest).or_insert(value.clone());
        if instance.delivered_digest == Some(digest) && instance.delivered_value.is_none() {
            instance.delivered_value = Some(value);
        }
        self.drive_round(round)
    }

    pub(super) fn buffer_or_handle_raba_message(
        &self,
        round: &mut RoundState,
        iteration: usize,
        message: BufferedRabaMessage,
    ) -> Result<(), String> {
        let current = round
            .mvba
            .current_iteration
            .as_ref()
            .map(|state| state.index);
        if current.is_none_or(|current_iteration| iteration > current_iteration) {
            round
                .mvba
                .future_raba_messages
                .entry(iteration)
                .or_default()
                .push(message);
            return Ok(());
        }
        let Some(active) = round.mvba.current_iteration.as_mut() else {
            return Ok(());
        };
        if iteration < active.index {
            return Ok(());
        }
        let Some(raba) = active.raba.as_mut() else {
            round
                .mvba
                .future_raba_messages
                .entry(iteration)
                .or_default()
                .push(message);
            return Ok(());
        };
        let _ = Self::handle_raba_buffered_message(raba, message);
        self.drive_round(round)
    }

    pub(super) fn handle_coin_share(
        &self,
        round: &mut RoundState,
        sender: usize,
        scope: CoinScope,
        share: Vec<u8>,
    ) -> Result<(), String> {
        if sender >= round.nodes() {
            return Ok(());
        }
        let state = round.mvba.coin_states.entry(scope).or_default();
        if state.shares.contains_key(&sender) {
            return Ok(());
        }
        let message = Self::coin_message(&round.sid, scope);
        let value = match g1_from_bytes(&share) {
            Ok(value) => value,
            Err(_) => return Ok(()),
        };
        let partial = PartialSignature {
            player_id: sender + 1,
            value,
        };
        if sender != self.pid
            && threshold::sig::verify_share(&self.crypto.coin_pk, &partial, &message).is_err()
        {
            return Ok(());
        }
        state.shares.insert(sender, share);
        self.drive_round(round)
    }
}
