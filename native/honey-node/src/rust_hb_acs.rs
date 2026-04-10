//! Rust-native HoneyBadger ACS host implementing BKR93 with RBC/PRBC + ABA.

use super::*;
use crate::acs_host::{AcsCryptoMaterial, AcsHost, AcsHostStats, AcsWireEvent};
use honey_crypto::ecdsa;
use honey_crypto::merkle::{self, MerkleProof};
use honey_crypto::threshold;
use honey_crypto::threshold::keygen::{PartialSignature, SigPrivateKeyShare, SigPublicParams};
use honey_crypto::threshold::utils::{g1_from_bytes, g1_to_bytes};
use honey_crypto::wire::api::decode_result;
use honey_crypto::wire::crypto_wire::{SigPrivateKeyShareWire, SigPublicParamsWire};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

const PRBC_READY_DOMAIN: &[u8] = b"prbc-ready|";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HbBroadcastMode {
    Rbc,
    Prbc,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
enum HbCoinScope {
    Aba { instance: u32, epoch: u32 },
}

#[derive(Clone, Serialize, Deserialize)]
struct RustHbEnvelope {
    round_id: u32,
    sender: u32,
    message: RustHbMessage,
}

#[derive(Clone, Serialize, Deserialize)]
enum RustHbMessage {
    RbcVal {
        leader: u32,
        roothash: [u8; 32],
        proof: MerkleProof,
        stripe: Vec<u8>,
        stripe_index: u32,
    },
    RbcEcho {
        leader: u32,
        roothash: [u8; 32],
        proof: MerkleProof,
        stripe: Vec<u8>,
        stripe_index: u32,
    },
    RbcReady {
        leader: u32,
        roothash: [u8; 32],
    },
    PrbcVal {
        leader: u32,
        roothash: [u8; 32],
        proof: MerkleProof,
        stripe: Vec<u8>,
        stripe_index: u32,
    },
    PrbcEcho {
        leader: u32,
        roothash: [u8; 32],
        proof: MerkleProof,
        stripe: Vec<u8>,
        stripe_index: u32,
    },
    PrbcReady {
        leader: u32,
        roothash: [u8; 32],
        signature: Vec<u8>,
    },
    AbaEst {
        instance: u32,
        epoch: u32,
        value: bool,
    },
    AbaAux {
        instance: u32,
        epoch: u32,
        value: bool,
    },
    AbaConf {
        instance: u32,
        epoch: u32,
        values: [bool; 2],
    },
    CoinShare {
        scope: HbCoinScope,
        share: Vec<u8>,
    },
}

#[derive(Clone, Serialize, Deserialize)]
struct PrbcProof {
    roothash: [u8; 32],
    sigmas: Vec<(usize, Vec<u8>)>,
}

#[derive(Default)]
struct CommandCounts {
    start_round: usize,
    push_inbound_wire_batch: usize,
    pull_outbound_wire_batch: usize,
    stats: usize,
}

#[derive(Default)]
struct BatchItemCounts {
    push_inbound_wire_batch_items: usize,
    pull_outbound_wire_batch_items: usize,
}

#[derive(Default)]
struct RbcState {
    leader_root: Option<[u8; 32]>,
    payload: Option<Vec<u8>>,
    proposal_ready: Option<ProposalArtifact>,
    ready_sent: bool,
    stripes: BTreeMap<[u8; 32], BTreeMap<usize, Vec<u8>>>,
    proofs: BTreeMap<[u8; 32], BTreeMap<usize, MerkleProof>>,
    echo_by_sender: BTreeMap<usize, [u8; 32]>,
    ready_by_sender: BTreeMap<usize, [u8; 32]>,
}

#[derive(Default)]
struct PrbcState {
    leader_root: Option<[u8; 32]>,
    payload: Option<Vec<u8>>,
    output: Option<PrbcProof>,
    proposal_ready: Option<ProposalArtifact>,
    ready_sent: bool,
    local_ready: Option<([u8; 32], [u8; 64])>,
    stripes: BTreeMap<[u8; 32], BTreeMap<usize, Vec<u8>>>,
    proofs: BTreeMap<[u8; 32], BTreeMap<usize, MerkleProof>>,
    echo_by_sender: BTreeMap<usize, [u8; 32]>,
    ready_by_sender: BTreeMap<usize, [u8; 32]>,
    ready_signatures: BTreeMap<[u8; 32], BTreeMap<usize, [u8; 64]>>,
}

#[derive(Default)]
struct CoinState {
    local_sent: bool,
    shares: BTreeMap<usize, Vec<u8>>,
    output: Option<u8>,
}

#[derive(Default)]
struct AbaEpochInbox {
    est_by_sender: BTreeMap<usize, [bool; 2]>,
    aux_by_sender: BTreeMap<usize, [bool; 2]>,
    conf_by_sender: BTreeMap<usize, [bool; 2]>,
    bin_values: [bool; 2],
}

#[derive(Default)]
struct AbaEpochProgress {
    est_sent: [bool; 2],
    aux_sent: Option<bool>,
    conf_sent: [bool; 3],
    conf_result: Option<[bool; 2]>,
    coin_value: Option<bool>,
}

struct AbaState {
    current_epoch: usize,
    est: bool,
    output: Option<bool>,
    epochs: BTreeMap<usize, AbaEpochProgress>,
}

impl AbaState {
    fn new(est: bool) -> Self {
        Self {
            current_epoch: 0,
            est,
            output: None,
            epochs: BTreeMap::new(),
        }
    }
}

struct Bkr93State {
    aba_input_sent: Vec<bool>,
    aba_outputs: Vec<Option<bool>>,
}

impl Bkr93State {
    fn new(nodes: usize) -> Self {
        Self {
            aba_input_sent: vec![false; nodes],
            aba_outputs: vec![None; nodes],
        }
    }

    fn count_ones(&self) -> usize {
        self.aba_outputs
            .iter()
            .filter(|outcome| matches!(outcome, Some(true)))
            .count()
    }

    fn aba_complete(&self) -> bool {
        self.aba_outputs.iter().all(Option::is_some)
    }
}

struct RoundState {
    round_id: usize,
    sid: String,
    mode: HbBroadcastMode,
    decision_emitted: bool,
    rbc: Vec<RbcState>,
    prbc: Vec<PrbcState>,
    bkr: Bkr93State,
    aba_states: Vec<Option<AbaState>>,
    aba_inboxes: BTreeMap<usize, BTreeMap<usize, AbaEpochInbox>>,
    coin_states: BTreeMap<HbCoinScope, CoinState>,
    outbound: VecDeque<AcsWireEvent>,
}

impl RoundState {
    fn new(round_id: usize, sid: String, nodes: usize, mode: HbBroadcastMode) -> Self {
        Self {
            round_id,
            sid,
            mode,
            decision_emitted: false,
            rbc: (0..nodes).map(|_| RbcState::default()).collect(),
            prbc: (0..nodes).map(|_| PrbcState::default()).collect(),
            bkr: Bkr93State::new(nodes),
            aba_states: (0..nodes).map(|_| None).collect(),
            aba_inboxes: BTreeMap::new(),
            coin_states: BTreeMap::new(),
            outbound: VecDeque::new(),
        }
    }

    fn nodes(&self) -> usize {
        self.rbc.len()
    }

    fn proposal_ready(&self, leader: usize) -> Option<&ProposalArtifact> {
        match self.mode {
            HbBroadcastMode::Rbc => self.rbc[leader].proposal_ready.as_ref(),
            HbBroadcastMode::Prbc => self.prbc[leader].proposal_ready.as_ref(),
        }
    }
}

#[derive(Default)]
struct RustHbState {
    current_round: Option<RoundState>,
    rounds_started: usize,
    rounds_finished: usize,
    processed_commands: usize,
    command_counts: CommandCounts,
    batch_item_counts: BatchItemCounts,
    pending_pull_limit: Option<usize>,
}

pub(crate) struct RustHbAcsHost {
    pid: usize,
    faulty: usize,
    mode: HbBroadcastMode,
    crypto: RustHbCryptoMaterial,
    state: Mutex<RustHbState>,
}

struct RustHbCryptoMaterial {
    ecdsa_pks: Vec<[u8; 33]>,
    ecdsa_sk: [u8; 32],
    coin_pk: SigPublicParams,
    coin_sk: SigPrivateKeyShare,
}

impl RustHbCryptoMaterial {
    fn decode_sig_pk(payload: &[u8]) -> Result<SigPublicParams, String> {
        let wire: SigPublicParamsWire = decode_result(payload)?;
        wire.into_runtime()
    }

    fn decode_sig_sk(payload: &[u8]) -> Result<SigPrivateKeyShare, String> {
        let wire: SigPrivateKeyShareWire = decode_result(payload)?;
        wire.into_runtime()
    }

    fn try_from_material(
        material: AcsCryptoMaterial,
        pid: usize,
        nodes: usize,
        faulty: usize,
    ) -> Result<Self, String> {
        let ecdsa_sk: [u8; 32] = material
            .ecdsa_sk
            .try_into()
            .map_err(|_| String::from("Rust HB ACS requires 32-byte ecdsa_sk"))?;
        let ecdsa_pks = material
            .ecdsa_pks
            .into_iter()
            .map(|value| {
                value
                    .try_into()
                    .map_err(|_| String::from("Rust HB ACS requires 33-byte ECDSA public keys"))
            })
            .collect::<Result<Vec<[u8; 33]>, _>>()?;
        let coin_pk = Self::decode_sig_pk(&material.sig_pk)?;
        let coin_sk = Self::decode_sig_sk(&material.sig_sk)?;
        if coin_pk.total_players != nodes {
            return Err(format!(
                "Rust HB ACS coin players mismatch: expected {nodes}, got {}",
                coin_pk.total_players
            ));
        }
        if coin_pk.threshold != faulty + 1 {
            return Err(format!(
                "Rust HB ACS coin threshold mismatch: expected {}, got {}",
                faulty + 1,
                coin_pk.threshold
            ));
        }
        if coin_sk.player_id != pid + 1 {
            return Err(format!(
                "Rust HB ACS coin share player mismatch: expected {}, got {}",
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

    fn coin_message(sid: &str, scope: HbCoinScope) -> Vec<u8> {
        match scope {
            HbCoinScope::Aba { instance, epoch } => {
                format!("{sid}COIN{instance}:{epoch}").into_bytes()
            }
        }
    }

    fn encode_envelope(&self, round_id: usize, message: RustHbMessage) -> Result<Vec<u8>, String> {
        bincode::serialize(&RustHbEnvelope {
            round_id: round_id as u32,
            sender: self.pid as u32,
            message,
        })
        .map_err(|err| err.to_string())
    }

    fn decode_envelope(payload: &[u8]) -> Result<RustHbEnvelope, String> {
        bincode::deserialize(payload).map_err(|err| err.to_string())
    }

    fn build_proposal_id(round_id: usize, proposer: usize, digest: &[u8; 32]) -> String {
        format!("{round_id}:{proposer}:{}", hex_encode(digest))
    }

    fn serialize_prbc_proof(proof: &PrbcProof) -> Vec<u8> {
        let mut chunks = Vec::with_capacity(2 + 32 + 2 + proof.sigmas.len() * (2 + 4 + 64));
        chunks.extend_from_slice(&(proof.roothash.len() as u16).to_be_bytes());
        chunks.extend_from_slice(&proof.roothash);
        chunks.extend_from_slice(&(proof.sigmas.len() as u16).to_be_bytes());
        for (sender, signature) in &proof.sigmas {
            chunks.extend_from_slice(&(*sender as u16).to_be_bytes());
            chunks.extend_from_slice(&(signature.len() as u32).to_be_bytes());
            chunks.extend_from_slice(signature);
        }
        chunks
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

    fn provide_aba_input(
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

    fn on_broadcast_output(&self, round: &mut RoundState, leader: usize) -> Result<bool, String> {
        self.provide_aba_input(round, leader, true)
    }

    fn on_aba_decided(
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

    fn output_rbc(
        &self,
        round: &mut RoundState,
        leader: usize,
        roothash: [u8; 32],
    ) -> Result<bool, String> {
        let data_threshold = self.data_threshold(round);
        let nodes = round.nodes();
        let available = {
            let proposal = &round.rbc[leader];
            if proposal.proposal_ready.is_some() {
                return Ok(false);
            }
            let Some(stripes) = proposal.stripes.get(&roothash) else {
                return Ok(false);
            };
            let Some(proofs) = proposal.proofs.get(&roothash) else {
                return Ok(false);
            };
            stripes
                .iter()
                .filter_map(|(index, stripe)| {
                    proofs
                        .get(index)
                        .cloned()
                        .map(|proof| (*index, stripe.clone(), proof))
                })
                .collect::<Vec<_>>()
        };
        if available.len() < data_threshold {
            return Ok(false);
        }
        let payload = merkle::decode_owned(available, &roothash, data_threshold, nodes)
            .map_err(|err| err.to_string())?;
        let proposal_id = Self::build_proposal_id(round.round_id, leader, &roothash);
        let artifact = ProposalArtifact {
            proposal_id,
            proposer: leader,
            payload: payload.clone(),
            digest: roothash.to_vec(),
            certificate: roothash.to_vec(),
        };
        let proposal = &mut round.rbc[leader];
        proposal.payload = Some(payload);
        proposal.proposal_ready = Some(artifact.clone());
        round.outbound.push_back(AcsWireEvent::ProposalReady {
            round_id: round.round_id,
            proposal: artifact,
        });
        self.on_broadcast_output(round, leader)
    }

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
            let proposal = &round.prbc[leader];
            if proposal.output.is_some() {
                return Ok(false);
            }
            let Some(stripes) = proposal.stripes.get(&roothash) else {
                return Ok(false);
            };
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
        let artifact = ProposalArtifact {
            proposal_id,
            proposer: leader,
            payload: payload.clone(),
            digest: roothash.to_vec(),
            certificate: Self::serialize_prbc_proof(&proof),
        };
        let proposal = &mut round.prbc[leader];
        proposal.payload = Some(payload);
        proposal.output = Some(proof);
        proposal.proposal_ready = Some(artifact.clone());
        round.outbound.push_back(AcsWireEvent::ProposalReady {
            round_id: round.round_id,
            proposal: artifact,
        });
        self.on_broadcast_output(round, leader)
    }

    fn drive_rbc(&self, round: &mut RoundState) -> Result<bool, String> {
        let mut changed = false;
        let threshold = self.threshold(round);
        let output_threshold = self.output_threshold();
        let data_threshold = self.data_threshold(round);
        for leader in 0..round.nodes() {
            let mut send_ready_for = None;
            let mut maybe_output_for = None;
            {
                let proposal = &round.rbc[leader];
                if proposal.proposal_ready.is_none() {
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
                        if ready_count >= output_threshold {
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
                let proposal = &mut round.rbc[leader];
                if !proposal.ready_sent {
                    proposal.ready_sent = true;
                    proposal.ready_by_sender.insert(self.pid, roothash);
                    self.queue_broadcast(
                        round,
                        RustHbMessage::RbcReady {
                            leader: leader as u32,
                            roothash,
                        },
                    )?;
                    changed = true;
                }
            }
            if let Some(roothash) = maybe_output_for {
                changed |= self.output_rbc(round, leader, roothash)?;
            }
        }
        Ok(changed)
    }

    fn drive_prbc(&self, round: &mut RoundState) -> Result<bool, String> {
        let mut changed = false;
        let threshold = self.threshold(round);
        let data_threshold = self.data_threshold(round);
        for leader in 0..round.nodes() {
            let mut send_ready_for = None;
            let mut maybe_output_for = None;
            {
                let proposal = &round.prbc[leader];
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
                let proposal = &mut round.prbc[leader];
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
                        RustHbMessage::PrbcReady {
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
        }
        Ok(changed)
    }

    fn current_aba_inbox(
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

    fn aba_conf_index(values: [bool; 2]) -> Option<usize> {
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

    fn drive_aba_instances(&self, round: &mut RoundState) -> Result<bool, String> {
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

    fn maybe_finalize_decision(&self, round: &mut RoundState) -> Result<bool, String> {
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

    #[allow(clippy::too_many_arguments)]
    fn handle_rbc_val(
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
        let proposal = &mut round.rbc[leader];
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
            RustHbMessage::RbcEcho {
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
    fn handle_rbc_echo(
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
        let proposal = &mut round.rbc[leader];
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

    fn handle_rbc_ready(
        &self,
        round: &mut RoundState,
        sender: usize,
        leader: usize,
        roothash: [u8; 32],
    ) -> Result<bool, String> {
        if leader >= round.nodes() {
            return Ok(false);
        }
        let proposal = &mut round.rbc[leader];
        if let Some(existing) = proposal.ready_by_sender.get(&sender) {
            if *existing != roothash {
                return Ok(false);
            }
            return Ok(false);
        }
        proposal.ready_by_sender.insert(sender, roothash);
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_prbc_val(
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
        let proposal = &mut round.prbc[leader];
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
            RustHbMessage::PrbcEcho {
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
    fn handle_prbc_echo(
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
        let proposal = &mut round.prbc[leader];
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

    fn handle_prbc_ready(
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
        let proposal = &mut round.prbc[leader];
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

    fn handle_aba_est(
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

    fn handle_aba_aux(
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

    fn handle_aba_conf(
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

    fn handle_coin_share(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drive_acs::run_acs_round;

    fn build_hosts(nodes: usize, faulty: usize, mode: HbBroadcastMode) -> Vec<RustHbAcsHost> {
        let config_json = match mode {
            HbBroadcastMode::Rbc => {
                r#"{"acs_host_backend":"rust_hb","hb_broadcast_protocol":"rbc"}"#
            }
            HbBroadcastMode::Prbc => {
                r#"{"acs_host_backend":"rust_hb","hb_broadcast_protocol":"prbc"}"#
            }
        };
        serialize_crypto_payloads(Protocol::HoneyBadger, nodes, faulty)
            .expect("crypto payloads should serialize")
            .into_iter()
            .enumerate()
            .map(|(pid, payload)| {
                RustHbAcsHost::new(
                    pid,
                    nodes,
                    faulty,
                    crate::acs_host::parse_acs_crypto_payload(Protocol::HoneyBadger, &payload)
                        .expect("crypto payload should parse"),
                    config_json,
                )
                .expect("Rust HB ACS host should construct")
            })
            .collect()
    }

    #[test]
    fn rust_hb_rbc_round_reaches_consistent_decision() {
        let hosts = build_hosts(4, 1, HbBroadcastMode::Rbc);
        let proposals = (0..4)
            .map(|pid| format!("rust-hb-rbc-proposal-{pid}").into_bytes())
            .collect::<Vec<_>>();
        let outcome = run_acs_round(&hosts, 0, "test:rust-hb:rbc:0:", &proposals, 5.0)
            .expect("round succeeds");

        assert!(outcome.selected_proposal_ids.len() >= 3);
        assert_eq!(
            outcome.selected_proposal_ids.len(),
            outcome.selected_pids.len()
        );
        assert!(outcome.selected_pids.iter().all(|pid| *pid < 4));
    }

    #[test]
    fn rust_hb_prbc_round_reaches_consistent_decision() {
        let hosts = build_hosts(4, 1, HbBroadcastMode::Prbc);
        let proposals = (0..4)
            .map(|pid| format!("rust-hb-prbc-proposal-{pid}").into_bytes())
            .collect::<Vec<_>>();
        let outcome = run_acs_round(&hosts, 0, "test:rust-hb:prbc:0:", &proposals, 5.0)
            .expect("round succeeds");

        assert!(outcome.selected_proposal_ids.len() >= 3);
        assert_eq!(
            outcome.selected_proposal_ids.len(),
            outcome.selected_pids.len()
        );
        assert!(outcome.selected_pids.iter().all(|pid| *pid < 4));
    }
}
