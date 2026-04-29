//! Rust-native ACS host implementing a FIN-style ACS core.
//!
//! This backend keeps the repository's existing proposal-reuse boundary by
//! using PRBC for proposal availability and artifact emission, then runs a
//! FIN-style MVBA over completion vectors to decide the ACS subset.

use crate::proposal::AvailableProposal;
use crate::{AcsBackend, AcsBackendStats, AcsCryptoMaterial, AcsEvent};
use honey_crypto::bls::g1::G1;
use honey_crypto::ecdsa;
use honey_crypto::merkle::{self, MerkleProof};
use honey_crypto::threshold;
use honey_crypto::threshold::keygen::{PartialSignature, SigPrivateKeyShare, SigPublicParams};
use honey_wire::api::decode_result;
use honey_wire::codec::hex_encode;
use honey_wire::crypto_wire::{SigPrivateKeyShareWire, SigPublicParamsWire};
use honey_wire::format::MerkleProofWire;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

mod crypto;
mod mvba;
mod prbc;
mod state;
mod wire;

use crypto::RustAcsCryptoMaterial;
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
const COIN_DOMAIN: &str = "rust-fin-acs";

pub struct RustAcsBackend {
    pid: usize,
    faulty: usize,
    crypto: RustAcsCryptoMaterial,
    state: Mutex<RustAcsState>,
}

impl RustAcsBackend {
    pub fn new(
        pid: usize,
        nodes: usize,
        faulty: usize,
        crypto: AcsCryptoMaterial,
        _config_json: &str,
    ) -> Result<Self, String> {
        let crypto = RustAcsCryptoMaterial::try_from_material(crypto, pid, nodes, faulty)?;
        if crypto.ecdsa_pks.len() != nodes {
            return Err(format!(
                "Rust ACS expected {nodes} ECDSA public keys, got {}",
                crypto.ecdsa_pks.len()
            ));
        }
        Ok(Self {
            pid,
            faulty,
            crypto,
            state: Mutex::new(RustAcsState::default()),
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

    fn ready_digest(sid: &str, roothash: &[u8; 32]) -> Vec<u8> {
        let mut message = Vec::with_capacity(PRBC_READY_DOMAIN.len() + sid.len() + 1 + 32);
        message.extend_from_slice(PRBC_READY_DOMAIN);
        message.extend_from_slice(sid.as_bytes());
        message.push(b'|');
        message.extend_from_slice(roothash);
        message
    }

    fn prbc_sid(sid: &str, leader: usize) -> String {
        format!("{sid}prbc:{leader}")
    }

    fn queue_send(
        &self,
        round: &mut RoundState,
        recipient: usize,
        message: RustAcsMessage,
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
        message: RustAcsMessage,
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
            let mut changed = false;
            changed |= self.drive_prbc(round)?;
            changed |= self.drive_wrbc(round)?;
            changed |= self.drive_mvba(round)?;
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
        message: RustAcsMessage,
    ) -> Result<(), String> {
        match message {
            RustAcsMessage::PrbcVal {
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
                proof.into_runtime()?,
                stripe,
                stripe_index as usize,
            ),
            RustAcsMessage::PrbcEcho {
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
                proof.into_runtime()?,
                stripe,
                stripe_index as usize,
            ),
            RustAcsMessage::PrbcReady {
                leader,
                roothash,
                signature,
            } => self.handle_prbc_ready(round, sender, leader as usize, roothash, signature),
            RustAcsMessage::WrbcSend { proposer, value } => {
                if round.decision_emitted {
                    return Ok(());
                }
                self.handle_wrbc_send(round, sender, proposer as usize, value)
            }
            RustAcsMessage::WrbcEcho { proposer, digest } => {
                if round.decision_emitted {
                    return Ok(());
                }
                self.handle_wrbc_echo(round, sender, proposer as usize, digest)
            }
            RustAcsMessage::WrbcReady { proposer, digest } => {
                if round.decision_emitted {
                    return Ok(());
                }
                self.handle_wrbc_ready(round, sender, proposer as usize, digest)
            }
            RustAcsMessage::WrbcValue { proposer, value } => {
                if round.decision_emitted {
                    return Ok(());
                }
                self.handle_wrbc_value(round, sender, proposer as usize, value)
            }
            RustAcsMessage::RabaVal {
                iteration,
                loop_index,
                value,
            } => {
                if round.decision_emitted {
                    return Ok(());
                }
                self.buffer_or_handle_raba_message(
                    round,
                    iteration as usize,
                    BufferedRabaMessage::Val {
                        sender,
                        loop_index: loop_index as usize,
                        value,
                    },
                )
            }
            RustAcsMessage::RabaAux {
                iteration,
                loop_index,
                value,
            } => {
                if round.decision_emitted {
                    return Ok(());
                }
                self.buffer_or_handle_raba_message(
                    round,
                    iteration as usize,
                    BufferedRabaMessage::Aux {
                        sender,
                        loop_index: loop_index as usize,
                        value,
                    },
                )
            }
            RustAcsMessage::RabaConf {
                iteration,
                loop_index,
                values,
            } => {
                if round.decision_emitted {
                    return Ok(());
                }
                self.buffer_or_handle_raba_message(
                    round,
                    iteration as usize,
                    BufferedRabaMessage::Conf {
                        sender,
                        loop_index: loop_index as usize,
                        values,
                    },
                )
            }
            RustAcsMessage::RabaFinish { iteration, value } => {
                if round.decision_emitted {
                    return Ok(());
                }
                self.buffer_or_handle_raba_message(
                    round,
                    iteration as usize,
                    BufferedRabaMessage::Finish { sender, value },
                )
            }
            RustAcsMessage::CoinShare { scope, share } => {
                if round.decision_emitted {
                    return Ok(());
                }
                self.handle_coin_share(round, sender, scope, share)
            }
        }
    }
}

impl AcsBackend for RustAcsBackend {
    fn pid(&self) -> usize {
        self.pid
    }

    fn start_round(&self, round_id: usize, sid: &str, proposal_input: &[u8]) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| String::from("Rust ACS state poisoned"))?;
        if let Some(round) = state.current_round.as_ref()
            && !round.decision_emitted
        {
            return Err(format!(
                "Rust ACS host pid={} cannot start round {round_id} before finishing round {}",
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
            .ok_or_else(|| String::from("Rust ACS failed to initialize round"))?;

        let merkle_result =
            merkle::encode(proposal_input, self.data_threshold(round), round.nodes())
                .map_err(|err| err.to_string())?;
        for recipient in 0..round.nodes() {
            let message = RustAcsMessage::PrbcVal {
                leader: self.pid as u32,
                roothash: merkle_result.root,
                proof: MerkleProofWire::from_runtime(&merkle_result.proofs[recipient]),
                stripe: merkle_result.shards[recipient].clone(),
                stripe_index: recipient as u32,
            };
            if recipient == self.pid {
                self.handle_message(round, self.pid, message)?;
            } else {
                self.queue_send(round, recipient, message)?;
            }
        }
        Ok(())
    }

    fn push_inbound_wire_batch(&self, items: &[Vec<u8>]) -> Result<usize, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| String::from("Rust ACS state poisoned"))?;
        state.processed_commands += 1;
        state.command_counts.push_inbound_wire_batch += 1;
        state.batch_item_counts.push_inbound_wire_batch_items += items.len();
        let Some(round) = state.current_round.as_mut() else {
            return Ok(0);
        };
        for item in items {
            let envelope = Self::decode_envelope(item)?;
            if envelope.round_id as usize != round.round_id {
                continue;
            }
            self.handle_message(round, envelope.sender as usize, envelope.message)?;
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
            .map_err(|_| String::from("Rust ACS state poisoned"))?;
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
            .map_err(|_| String::from("Rust ACS state poisoned"))?;
        if state.pending_pull_limit.is_some() {
            return Err(String::from(
                "Rust ACS pull_outbound_wire_batch is already pending",
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
            .map_err(|_| String::from("Rust ACS state poisoned"))?;
        let limit = state
            .pending_pull_limit
            .take()
            .ok_or_else(|| String::from("Rust ACS pull_outbound_wire_batch was not started"))?;
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
        state.batch_item_counts.pull_outbound_wire_batch_items += drained_len;
        if finished {
            state.rounds_finished = state.rounds_finished.max(rounds_started);
        }
        Ok(drained)
    }

    fn finish_round(&self, round_id: usize) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| String::from("Rust ACS state poisoned"))?;
        if state
            .current_round
            .as_ref()
            .is_some_and(|round| round.round_id == round_id)
        {
            state.current_round = None;
            state.pending_pull_limit = None;
            state.rounds_finished = state.rounds_finished.max(state.rounds_started);
        }
        Ok(())
    }

    fn stats(&self) -> Result<AcsBackendStats, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| String::from("Rust ACS state poisoned"))?;
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
            .map_err(|_| String::from("Rust ACS state poisoned"))?;
        state.current_round = None;
        state.pending_pull_limit = None;
        Ok(())
    }
}
