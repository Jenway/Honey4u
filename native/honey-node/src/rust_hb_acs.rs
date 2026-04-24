//! Rust-native HoneyBadger ACS host implementing BKR93 with RBC/PRBC + ABA.

use super::*;
use crate::acs_host::{AcsCryptoMaterial, AcsHost, AcsHostStats, AcsWireEvent};
use honey_crypto::bls::g1::G1;
use honey_crypto::ecdsa;
use honey_crypto::merkle::{self, MerkleProof};
use honey_crypto::threshold;
use honey_crypto::threshold::keygen::{PartialSignature, SigPrivateKeyShare, SigPublicParams};
use honey_node::wire::api::decode_result;
use honey_node::wire::crypto_wire::{SigPrivateKeyShareWire, SigPublicParamsWire};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

#[path = "rust_hb_acs/aba.rs"]
mod aba;
#[path = "rust_hb_acs/broadcast.rs"]
mod broadcast;
#[path = "rust_hb_acs/crypto.rs"]
mod crypto;
#[path = "rust_hb_acs/state.rs"]
mod state;
#[path = "rust_hb_acs/wire.rs"]
mod wire;

use crypto::RustHbCryptoMaterial;
use state::*;
use wire::*;

#[cfg(test)]
#[path = "rust_hb_acs/tests.rs"]
mod tests;

fn parse_g1_compressed(bytes: &[u8]) -> Result<G1, String> {
    let arr: &[u8; 48] = bytes
        .try_into()
        .map_err(|_| format!("expected 48 bytes for G1, got {}", bytes.len()))?;
    G1::from_compressed_bytes(arr)
}

const PRBC_READY_DOMAIN: &[u8] = b"prbc-ready|";

pub(crate) struct RustHbAcsHost {
    pid: usize,
    faulty: usize,
    mode: HbBroadcastMode,
    crypto: RustHbCryptoMaterial,
    state: Mutex<RustHbState>,
}

impl RustHbAcsHost {
    pub(crate) fn new(
        pid: usize,
        nodes: usize,
        faulty: usize,
        crypto: AcsCryptoMaterial,
        config_json: &str,
    ) -> Result<Self, String> {
        let mode = Self::parse_broadcast_mode(config_json)?;
        let crypto = RustHbCryptoMaterial::try_from_material(crypto, pid, nodes, faulty)?;
        if crypto.ecdsa_pks.len() != nodes {
            return Err(format!(
                "Rust HB ACS expected {nodes} ECDSA public keys, got {}",
                crypto.ecdsa_pks.len()
            ));
        }
        Ok(Self {
            pid,
            faulty,
            mode,
            crypto,
            state: Mutex::new(RustHbState::default()),
        })
    }

    fn parse_broadcast_mode(config_json: &str) -> Result<HbBroadcastMode, String> {
        let value: Value = serde_json::from_str(config_json).map_err(|err| err.to_string())?;
        match value
            .get("hb_broadcast_protocol")
            .and_then(Value::as_str)
            .unwrap_or("rbc")
        {
            "rbc" => Ok(HbBroadcastMode::Rbc),
            "prbc" => Ok(HbBroadcastMode::Prbc),
            other => Err(format!(
                "Rust HB ACS unsupported hb_broadcast_protocol in config_json: {other}"
            )),
        }
    }

    fn threshold(&self, round: &RoundState) -> usize {
        round.nodes() - self.faulty
    }

    fn data_threshold(&self, round: &RoundState) -> usize {
        round.nodes() - 2 * self.faulty
    }

    fn output_threshold(&self) -> usize {
        2 * self.faulty + 1
    }

    fn coin_threshold(&self) -> usize {
        self.faulty + 1
    }

    fn prbc_sid(sid: &str, leader: usize) -> String {
        format!("{sid}prbc:{leader}")
    }

    fn ready_digest(sid: &str, roothash: &[u8; 32]) -> Vec<u8> {
        let mut message = Vec::with_capacity(PRBC_READY_DOMAIN.len() + sid.len() + 1 + 32);
        message.extend_from_slice(PRBC_READY_DOMAIN);
        message.extend_from_slice(sid.as_bytes());
        message.push(b'|');
        message.extend_from_slice(roothash);
        message
    }

    fn queue_send(
        &self,
        round: &mut RoundState,
        recipient: usize,
        message: RustHbMessage,
    ) -> Result<(), String> {
        let payload = self.encode_envelope(round.round_id, message)?;
        round.outbound.push_back(AcsWireEvent::Send {
            round_id: round.round_id,
            recipient,
            payload,
        });
        Ok(())
    }

    fn queue_broadcast(
        &self,
        round: &mut RoundState,
        message: RustHbMessage,
    ) -> Result<(), String> {
        let payload = self.encode_envelope(round.round_id, message)?;
        round.outbound.push_back(AcsWireEvent::Broadcast {
            round_id: round.round_id,
            payload,
            include_self: false,
        });
        Ok(())
    }

    fn drive_round(&self, round: &mut RoundState) -> Result<(), String> {
        loop {
            let mut changed = false;
            changed |= match round.mode {
                HbBroadcastMode::Rbc => self.drive_rbc(round)?,
                HbBroadcastMode::Prbc => self.drive_prbc(round)?,
            };
            changed |= self.drive_aba_instances(round)?;
            changed |= self.maybe_finalize_decision(round)?;
            if !changed {
                break;
            }
        }
        Ok(())
    }

    fn handle_message(
        &self,
        round: &mut RoundState,
        sender: usize,
        message: RustHbMessage,
    ) -> Result<bool, String> {
        if round.decision_emitted {
            return Ok(false);
        }
        match message {
            RustHbMessage::RbcVal {
                leader,
                roothash,
                proof,
                stripe,
                stripe_index,
            } => self.handle_rbc_val(
                round,
                sender,
                leader as usize,
                roothash,
                proof,
                stripe,
                stripe_index as usize,
            ),
            RustHbMessage::RbcEcho {
                leader,
                roothash,
                proof,
                stripe,
                stripe_index,
            } => self.handle_rbc_echo(
                round,
                sender,
                leader as usize,
                roothash,
                proof,
                stripe,
                stripe_index as usize,
            ),
            RustHbMessage::RbcReady { leader, roothash } => {
                self.handle_rbc_ready(round, sender, leader as usize, roothash)
            }
            RustHbMessage::PrbcVal {
                leader,
                roothash,
                proof,
                stripe,
                stripe_index,
            } => self.handle_prbc_val(
                round,
                sender,
                leader as usize,
                roothash,
                proof,
                stripe,
                stripe_index as usize,
            ),
            RustHbMessage::PrbcEcho {
                leader,
                roothash,
                proof,
                stripe,
                stripe_index,
            } => self.handle_prbc_echo(
                round,
                sender,
                leader as usize,
                roothash,
                proof,
                stripe,
                stripe_index as usize,
            ),
            RustHbMessage::PrbcReady {
                leader,
                roothash,
                signature,
            } => self.handle_prbc_ready(round, sender, leader as usize, roothash, signature),
            RustHbMessage::AbaEst {
                instance,
                epoch,
                value,
            } => self.handle_aba_est(round, sender, instance as usize, epoch as usize, value),
            RustHbMessage::AbaAux {
                instance,
                epoch,
                value,
            } => self.handle_aba_aux(round, sender, instance as usize, epoch as usize, value),
            RustHbMessage::AbaConf {
                instance,
                epoch,
                values,
            } => self.handle_aba_conf(round, sender, instance as usize, epoch as usize, values),
            RustHbMessage::CoinShare { scope, share } => {
                self.handle_coin_share(round, sender, scope, share)
            }
        }
    }
}

impl AcsHost for RustHbAcsHost {
    fn pid(&self) -> usize {
        self.pid
    }

    fn start_round(&self, round_id: usize, sid: &str, proposal_input: &[u8]) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| String::from("Rust HB ACS state poisoned"))?;
        if let Some(round) = state.current_round.as_ref()
            && !round.decision_emitted
        {
            return Err(format!(
                "Rust HB ACS host pid={} cannot start round {round_id} before finishing round {}",
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
            self.mode,
        ));
        let round = state
            .current_round
            .as_mut()
            .ok_or_else(|| String::from("Rust HB ACS failed to initialize round"))?;

        let merkle_result =
            merkle::encode(proposal_input, self.data_threshold(round), round.nodes())
                .map_err(|err| err.to_string())?;
        for recipient in 0..round.nodes() {
            let message = match self.mode {
                HbBroadcastMode::Rbc => RustHbMessage::RbcVal {
                    leader: self.pid as u32,
                    roothash: merkle_result.root,
                    proof: merkle_result.proofs[recipient].clone(),
                    stripe: merkle_result.shards[recipient].clone(),
                    stripe_index: recipient as u32,
                },
                HbBroadcastMode::Prbc => RustHbMessage::PrbcVal {
                    leader: self.pid as u32,
                    roothash: merkle_result.root,
                    proof: merkle_result.proofs[recipient].clone(),
                    stripe: merkle_result.shards[recipient].clone(),
                    stripe_index: recipient as u32,
                },
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
            .map_err(|_| String::from("Rust HB ACS state poisoned"))?;
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
            .map_err(|_| String::from("Rust HB ACS state poisoned"))?;
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
            .map_err(|_| String::from("Rust HB ACS state poisoned"))?;
        if state.pending_pull_limit.is_some() {
            return Err(String::from(
                "Rust HB ACS pull_outbound_wire_batch is already pending",
            ));
        }
        state.processed_commands += 1;
        state.command_counts.pull_outbound_wire_batch += 1;
        state.pending_pull_limit = Some(limit);
        Ok(())
    }

    fn finish_pull_outbound_wire_batch(&self) -> Result<Vec<AcsWireEvent>, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| String::from("Rust HB ACS state poisoned"))?;
        let limit = state
            .pending_pull_limit
            .take()
            .ok_or_else(|| String::from("Rust HB ACS pull_outbound_wire_batch was not started"))?;
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

    fn stats(&self) -> Result<AcsHostStats, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| String::from("Rust HB ACS state poisoned"))?;
        state.processed_commands += 1;
        state.command_counts.stats += 1;
        Ok(AcsHostStats {
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
            .map_err(|_| String::from("Rust HB ACS state poisoned"))?;
        state.current_round = None;
        state.pending_pull_limit = None;
        Ok(())
    }
}
