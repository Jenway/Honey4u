//! Rust-native Dumbo ACS host implementing PRBC + Dumbo-MVBA.

use crate::acs::{AcsBackend, AcsBackendStats, AcsCryptoMaterial, AcsEvent};
use crate::*;
use honey_crypto::bls::g1::G1;
use honey_crypto::ecdsa;
use honey_crypto::merkle::{self, MerkleProof};
use honey_crypto::threshold;
use honey_crypto::threshold::keygen::{PartialSignature, SigPrivateKeyShare, SigPublicParams};
use honey_node::wire::api::decode_result;
use honey_node::wire::crypto_wire::{SigPrivateKeyShareWire, SigPublicParamsWire};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Mutex;

mod crypto;
mod mvba;
mod prbc;
mod state;
mod wire;

use crypto::RustDumboCryptoMaterial;
use state::*;
use wire::*;

#[cfg(test)]
mod tests;

fn parse_g1_compressed(bytes: &[u8]) -> Result<G1, String> {
    let arr: &[u8; 48] = bytes
        .try_into()
        .map_err(|_| format!("expected 48 bytes for G1, got {}", bytes.len()))?;
    G1::from_compressed_bytes(arr)
}

const PRBC_READY_DOMAIN: &[u8] = b"prbc-ready|";
const PD_STORED_DOMAIN: &[u8] = b"stored|";
const PD_LOCKED_DOMAIN: &[u8] = b"locked|";

pub(crate) struct RustDumboAcsBackend {
    pid: usize,
    faulty: usize,
    crypto: RustDumboCryptoMaterial,
    state: Mutex<RustDumboState>,
}

impl RustDumboAcsBackend {
    pub(crate) fn new(
        pid: usize,
        nodes: usize,
        faulty: usize,
        crypto: AcsCryptoMaterial,
        _config_json: &str,
    ) -> Result<Self, String> {
        let crypto = RustDumboCryptoMaterial::try_from_material(crypto, pid, nodes, faulty)?;
        if crypto.ecdsa_pks.len() != nodes {
            return Err(format!(
                "Rust Dumbo ACS expected {nodes} ECDSA public keys, got {}",
                crypto.ecdsa_pks.len()
            ));
        }
        Ok(Self {
            pid,
            faulty,
            crypto,
            state: Mutex::new(RustDumboState::default()),
        })
    }

    fn threshold(&self, round: &RoundState) -> usize {
        round.nodes() - self.faulty
    }

    fn data_threshold(&self, round: &RoundState) -> usize {
        round.nodes() - 2 * self.faulty
    }

    fn coin_threshold(&self) -> usize {
        self.faulty + 1
    }

    fn prbc_sid(sid: &str, leader: usize) -> String {
        format!("{sid}prbc:{leader}")
    }

    fn pd_sid(sid: &str, leader: usize) -> String {
        format!("{sid}pd:{leader}")
    }

    fn ready_digest(sid: &str, roothash: &[u8; 32]) -> Vec<u8> {
        let mut message = Vec::with_capacity(PRBC_READY_DOMAIN.len() + sid.len() + 1 + 32);
        message.extend_from_slice(PRBC_READY_DOMAIN);
        message.extend_from_slice(sid.as_bytes());
        message.push(b'|');
        message.extend_from_slice(roothash);
        message
    }

    fn pd_digest(domain: &[u8], pd_sid: &str, roothash: &[u8; 32]) -> Vec<u8> {
        let mut message = Vec::with_capacity(domain.len() + pd_sid.len() + 1 + 32);
        message.extend_from_slice(domain);
        message.extend_from_slice(pd_sid.as_bytes());
        message.push(b'|');
        message.extend_from_slice(roothash);
        message
    }

    fn queue_send(
        &self,
        round: &mut RoundState,
        recipient: usize,
        message: RustDumboMessage,
    ) -> Result<(), String> {
        let payload = self.encode_envelope(round.round_id, message)?;
        round.outbound.push_back(AcsEvent::Send {
            round_id: round.round_id,
            recipient,
            payload,
        });
        Ok(())
    }

    fn queue_broadcast(
        &self,
        round: &mut RoundState,
        message: RustDumboMessage,
    ) -> Result<(), String> {
        let payload = self.encode_envelope(round.round_id, message)?;
        round.outbound.push_back(AcsEvent::Broadcast {
            round_id: round.round_id,
            payload,
            include_self: false,
        });
        Ok(())
    }

    fn drive_round(&self, round: &mut RoundState) -> Result<(), String> {
        loop {
            let mut progressed = false;
            if !round.dirty_prbc_leaders.is_empty() {
                progressed |= self.drive_prbc(round)?;
            }
            if round.mvba_dirty {
                round.mvba_dirty = false;
                let mut mvba_progress = false;
                loop {
                    let mut changed = false;
                    changed |= self.maybe_diffuse_local_proof(round)?;
                    changed |= self.maybe_start_mvba_input(round)?;
                    changed |= self.drive_pd(round)?;
                    changed |= self.drive_mvba(round)?;
                    changed |= self.maybe_finalize_decision(round)?;
                    if !changed {
                        break;
                    }
                    mvba_progress = true;
                }
                progressed |= mvba_progress;
            }
            if !progressed {
                break;
            }
        }
        Ok(())
    }

    fn handle_message(
        &self,
        round: &mut RoundState,
        sender: usize,
        message: RustDumboMessage,
    ) -> Result<bool, String> {
        if round.decision_emitted {
            return Ok(false);
        }
        match message {
            RustDumboMessage::PrbcVal {
                leader,
                roothash,
                proof,
                stripe,
                stripe_index,
            } => {
                let leader = leader as usize;
                let changed = self.handle_prbc_val(
                    round,
                    sender,
                    leader,
                    roothash,
                    proof,
                    stripe,
                    stripe_index as usize,
                )?;
                if changed {
                    round.mark_prbc_dirty(leader);
                }
                Ok(changed)
            }
            RustDumboMessage::PrbcEcho {
                leader,
                roothash,
                proof,
                stripe,
                stripe_index,
            } => {
                let leader = leader as usize;
                let changed = self.handle_prbc_echo(
                    round,
                    sender,
                    leader,
                    roothash,
                    proof,
                    stripe,
                    stripe_index as usize,
                )?;
                if changed {
                    round.mark_prbc_dirty(leader);
                }
                Ok(changed)
            }
            RustDumboMessage::PrbcReady {
                leader,
                roothash,
                signature,
            } => {
                let leader = leader as usize;
                let changed = self.handle_prbc_ready(round, sender, leader, roothash, signature)?;
                if changed {
                    round.mark_prbc_dirty(leader);
                }
                Ok(changed)
            }
            RustDumboMessage::ProofDiffuse { leader, proof } => {
                let changed = self.handle_proof_diffuse(round, sender, leader as usize, proof)?;
                if changed {
                    round.mark_mvba_dirty();
                }
                Ok(changed)
            }
            RustDumboMessage::PdStore {
                leader,
                roothash,
                stripe,
                merkle_proof,
            } => {
                let changed = self.process_pd_store(
                    round,
                    sender,
                    leader as usize,
                    roothash,
                    merkle_proof,
                    stripe,
                )?;
                if changed {
                    round.mark_mvba_dirty();
                }
                Ok(changed)
            }
            RustDumboMessage::PdStored {
                leader,
                roothash,
                share,
            } => {
                let changed =
                    self.process_pd_stored(round, sender, leader as usize, roothash, share)?;
                if changed {
                    round.mark_mvba_dirty();
                }
                Ok(changed)
            }
            RustDumboMessage::PdLock { leader, proof } => {
                let changed = self.process_pd_lock(round, sender, leader as usize, proof)?;
                if changed {
                    round.mark_mvba_dirty();
                }
                Ok(changed)
            }
            RustDumboMessage::PdLocked {
                leader,
                roothash,
                share,
            } => {
                let changed =
                    self.process_pd_locked(round, sender, leader as usize, roothash, share)?;
                if changed {
                    round.mark_mvba_dirty();
                }
                Ok(changed)
            }
            RustDumboMessage::PdDone { leader, proof } => {
                let changed = self.process_pd_done(round, sender, leader as usize, proof)?;
                if changed {
                    round.mark_mvba_dirty();
                }
                Ok(changed)
            }
            RustDumboMessage::RcPrepare {
                mvba_round,
                leader,
                proof,
            } => {
                let changed = self.handle_rc_prepare(
                    round,
                    sender,
                    mvba_round as usize,
                    leader as usize,
                    proof,
                )?;
                if changed {
                    round.mark_mvba_dirty();
                }
                Ok(changed)
            }
            RustDumboMessage::RcLock {
                mvba_round,
                leader,
                proof,
            } => {
                let changed = self.handle_rc_lock(
                    round,
                    sender,
                    mvba_round as usize,
                    leader as usize,
                    proof,
                )?;
                if changed {
                    round.mark_mvba_dirty();
                }
                Ok(changed)
            }
            RustDumboMessage::RcStore {
                mvba_round,
                leader,
                store,
            } => {
                let changed = self.handle_rc_store(
                    round,
                    sender,
                    mvba_round as usize,
                    leader as usize,
                    store,
                )?;
                if changed {
                    round.mark_mvba_dirty();
                }
                Ok(changed)
            }
            RustDumboMessage::AbaEst {
                mvba_round,
                epoch,
                value,
            } => {
                let changed =
                    self.handle_aba_est(round, sender, mvba_round as usize, epoch as usize, value)?;
                if changed {
                    round.mark_mvba_dirty();
                }
                Ok(changed)
            }
            RustDumboMessage::AbaAux {
                mvba_round,
                epoch,
                value,
            } => {
                let changed =
                    self.handle_aba_aux(round, sender, mvba_round as usize, epoch as usize, value)?;
                if changed {
                    round.mark_mvba_dirty();
                }
                Ok(changed)
            }
            RustDumboMessage::AbaConf {
                mvba_round,
                epoch,
                values,
            } => {
                let changed = self.handle_aba_conf(
                    round,
                    sender,
                    mvba_round as usize,
                    epoch as usize,
                    values,
                )?;
                if changed {
                    round.mark_mvba_dirty();
                }
                Ok(changed)
            }
            RustDumboMessage::CoinShare { scope, share } => {
                let changed = self.handle_coin_share(round, sender, scope, share)?;
                if changed {
                    round.mark_mvba_dirty();
                }
                Ok(changed)
            }
        }
    }
}

impl AcsBackend for RustDumboAcsBackend {
    fn pid(&self) -> usize {
        self.pid
    }

    fn start_round(&self, round_id: usize, sid: &str, proposal_input: &[u8]) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| String::from("Rust Dumbo ACS state poisoned"))?;
        if let Some(round) = state.current_round.as_ref()
            && !round.decision_emitted
        {
            return Err(format!(
                "Rust Dumbo ACS host pid={} cannot start round {round_id} before finishing round {}",
                self.pid, round.round_id
            ));
        }
        state.processed_commands += 1;
        state.command_counts.start_round += 1;
        state.rounds_started += 1;
        state.pending_pull_limit = None;
        state.current_round = Some(RoundState::new(
            round_id,
            sid.to_owned(),
            self.crypto.ecdsa_pks.len(),
        ));
        let round = state
            .current_round
            .as_mut()
            .ok_or_else(|| String::from("Rust Dumbo ACS failed to initialize round"))?;

        let merkle_result =
            merkle::encode(proposal_input, self.data_threshold(round), round.nodes())
                .map_err(|err| err.to_string())?;
        for recipient in 0..round.nodes() {
            let message = RustDumboMessage::PrbcVal {
                leader: self.pid as u32,
                roothash: merkle_result.root,
                proof: merkle_result.proofs[recipient].clone(),
                stripe: merkle_result.shards[recipient].clone(),
                stripe_index: recipient as u32,
            };
            if recipient == self.pid {
                let _ = self.handle_message(round, self.pid, message)?;
            } else {
                self.queue_send(round, recipient, message)?;
            }
        }
        self.drive_round(round)?;
        Ok(())
    }

    fn push_inbound_wire_batch(&self, items: &[Vec<u8>]) -> Result<usize, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| String::from("Rust Dumbo ACS state poisoned"))?;
        state.processed_commands += 1;
        state.command_counts.push_inbound_wire_batch += 1;
        state.batch_item_counts.push_inbound_wire_batch_items += items.len();
        let Some(round) = state.current_round.as_mut() else {
            return Ok(0);
        };
        let mut changed = false;
        for item in items {
            let envelope = Self::decode_envelope(item)?;
            if envelope.round_id as usize != round.round_id {
                continue;
            }
            changed |= self.handle_message(round, envelope.sender as usize, envelope.message)?;
        }
        if changed {
            self.drive_round(round)?;
        }
        if round.decision_emitted {
            state.rounds_finished = state.rounds_finished.max(state.rounds_started);
        }
        Ok(items.len())
    }

    fn outbound_ready(&self) -> Result<bool, String> {
        let state = self
            .state
            .lock()
            .map_err(|_| String::from("Rust Dumbo ACS state poisoned"))?;
        Ok(state
            .current_round
            .as_ref()
            .map(|round| !round.outbound.is_empty())
            .unwrap_or(false))
    }

    fn begin_pull_outbound_wire_batch(&self, limit: usize) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| String::from("Rust Dumbo ACS state poisoned"))?;
        if state.pending_pull_limit.is_some() {
            return Err(String::from(
                "Rust Dumbo ACS pull_outbound_wire_batch is already pending",
            ));
        }
        state.processed_commands += 1;
        state.command_counts.pull_outbound_wire_batch += 1;
        state.pending_pull_limit = Some(limit);
        Ok(())
    }

    fn finish_pull_outbound_wire_batch(&self) -> Result<Vec<AcsEvent>, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| String::from("Rust Dumbo ACS state poisoned"))?;
        let limit = state.pending_pull_limit.take().ok_or_else(|| {
            String::from("Rust Dumbo ACS pull_outbound_wire_batch was not started")
        })?;
        let rounds_started = state.rounds_started;
        let Some(round) = state.current_round.as_mut() else {
            return Ok(Vec::new());
        };
        let mut drained = Vec::with_capacity(limit);
        for _ in 0..limit {
            let Some(event) = round.outbound.pop_front() else {
                break;
            };
            drained.push(event);
        }
        let finished = round.decision_emitted && round.outbound.is_empty();
        let drained_len = drained.len();
        let _ = round;
        state.batch_item_counts.pull_outbound_wire_batch_items += drained_len;
        if finished {
            state.rounds_finished = state.rounds_finished.max(rounds_started);
        }
        Ok(drained)
    }

    fn stats(&self) -> Result<AcsBackendStats, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| String::from("Rust Dumbo ACS state poisoned"))?;
        state.processed_commands += 1;
        state.command_counts.stats += 1;
        Ok(AcsBackendStats {
            worker_ident: 0,
            rounds_started: state.rounds_started,
            rounds_finished: state.rounds_finished,
            processed_commands: state.processed_commands,
            bridge_queue_size: state
                .current_round
                .as_ref()
                .map(|round| round.outbound.len())
                .unwrap_or(0),
            worker_running: true,
            worker_error: None,
            start_round_calls: state.command_counts.start_round,
            push_inbound_wire_batch_calls: state.command_counts.push_inbound_wire_batch,
            push_inbound_wire_batch_items: state.batch_item_counts.push_inbound_wire_batch_items,
            pull_outbound_wire_batch_calls: state.command_counts.pull_outbound_wire_batch,
            pull_outbound_wire_batch_items: state.batch_item_counts.pull_outbound_wire_batch_items,
            stats_calls: state.command_counts.stats,
        })
    }

    fn shutdown(&self) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| String::from("Rust Dumbo ACS state poisoned"))?;
        state.current_round = None;
        state.pending_pull_limit = None;
        Ok(())
    }
}
