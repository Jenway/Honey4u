//! Rust-native ACS host implementing a FIN-style ACS core.
//!
//! This backend keeps the repository's existing proposal-reuse boundary by
//! using PRBC for proposal availability and artifact emission, then runs a
//! FIN-style MVBA over completion vectors to decide the ACS subset.

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
const COIN_DOMAIN: &str = "rust-fin-acs";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
enum CoinScope {
    Election { iteration: u32 },
    Raba { iteration: u32, loop_index: u32 },
}

#[derive(Clone, Serialize, Deserialize)]
struct RustAcsEnvelope {
    round_id: u32,
    sender: u32,
    message: RustAcsMessage,
}

#[derive(Clone, Serialize, Deserialize)]
enum RustAcsMessage {
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
    WrbcSend {
        proposer: u32,
        value: Vec<u8>,
    },
    WrbcEcho {
        proposer: u32,
        digest: [u8; 32],
    },
    WrbcReady {
        proposer: u32,
        digest: [u8; 32],
    },
    WrbcValue {
        proposer: u32,
        value: Vec<u8>,
    },
    RabaVal {
        iteration: u32,
        loop_index: u32,
        value: bool,
    },
    RabaAux {
        iteration: u32,
        loop_index: u32,
        value: bool,
    },
    RabaConf {
        iteration: u32,
        loop_index: u32,
        values: [bool; 2],
    },
    RabaFinish {
        iteration: u32,
        value: bool,
    },
    CoinShare {
        scope: CoinScope,
        share: Vec<u8>,
    },
}

#[derive(Clone)]
struct PrbcProof {
    roothash: [u8; 32],
    sigmas: Vec<(usize, [u8; 64])>,
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
struct WrbcState {
    send_value: Option<Vec<u8>>,
    send_digest: Option<[u8; 32]>,
    echo_sent: bool,
    ready_sent: bool,
    delivered_digest: Option<[u8; 32]>,
    delivered_value: Option<Vec<u8>>,
    value_broadcasted: bool,
    known_values: BTreeMap<[u8; 32], Vec<u8>>,
    echo_by_sender: BTreeMap<usize, [u8; 32]>,
    ready_by_sender: BTreeMap<usize, [u8; 32]>,
}

#[derive(Default)]
struct CoinState {
    local_sent: bool,
    shares: BTreeMap<usize, Vec<u8>>,
    output: Option<u8>,
}

#[derive(Clone)]
enum BufferedRabaMessage {
    Val {
        sender: usize,
        loop_index: usize,
        value: bool,
    },
    Aux {
        sender: usize,
        loop_index: usize,
        value: bool,
    },
    Conf {
        sender: usize,
        loop_index: usize,
        values: [bool; 2],
    },
    Finish {
        sender: usize,
        value: bool,
    },
}

struct RabaLoopState {
    index: usize,
    input: bool,
    values: [bool; 2],
    val_by_sender: BTreeMap<usize, [bool; 2]>,
    aux_by_sender: BTreeMap<usize, [bool; 2]>,
    conf_by_sender: BTreeMap<usize, [bool; 2]>,
    val_sent: [bool; 2],
    aux_sent: [bool; 2],
    conf_sent: bool,
    coin_requested: bool,
    coin_value: Option<bool>,
    resolved: bool,
    reproposed_true: bool,
}

impl RabaLoopState {
    fn new(index: usize, input: bool) -> Self {
        Self {
            index,
            input,
            values: [false, false],
            val_by_sender: BTreeMap::new(),
            aux_by_sender: BTreeMap::new(),
            conf_by_sender: BTreeMap::new(),
            val_sent: [false, false],
            aux_sent: [false, false],
            conf_sent: false,
            coin_requested: false,
            coin_value: None,
            resolved: false,
            reproposed_true: false,
        }
    }
}

struct RabaState {
    iteration: usize,
    leader: usize,
    current_loop: RabaLoopState,
    finish_by_sender: BTreeMap<usize, bool>,
    finish_sent: Option<bool>,
    output: Option<bool>,
    future_messages: BTreeMap<usize, Vec<BufferedRabaMessage>>,
}

impl RabaState {
    fn new(iteration: usize, leader: usize, input: bool) -> Self {
        Self {
            iteration,
            leader,
            current_loop: RabaLoopState::new(0, input),
            finish_by_sender: BTreeMap::new(),
            finish_sent: None,
            output: None,
            future_messages: BTreeMap::new(),
        }
    }
}

struct MvbaIterationState {
    index: usize,
    leader: Option<usize>,
    raba: Option<RabaState>,
}

struct MvbaState {
    started: bool,
    local_input: Option<Vec<u8>>,
    wrbc: Vec<WrbcState>,
    coin_states: BTreeMap<CoinScope, CoinState>,
    current_iteration: Option<MvbaIterationState>,
    future_raba_messages: BTreeMap<usize, Vec<BufferedRabaMessage>>,
    output_value: Option<Vec<u8>>,
}

impl MvbaState {
    fn new(nodes: usize) -> Self {
        Self {
            started: false,
            local_input: None,
            wrbc: (0..nodes).map(|_| WrbcState::default()).collect(),
            coin_states: BTreeMap::new(),
            current_iteration: None,
            future_raba_messages: BTreeMap::new(),
            output_value: None,
        }
    }
}

struct RoundState {
    round_id: usize,
    sid: String,
    decision_emitted: bool,
    decision_vector: Option<Vec<bool>>,
    proposals: Vec<PrbcState>,
    mvba: MvbaState,
    outbound: VecDeque<AcsWireEvent>,
}

impl RoundState {
    fn new(round_id: usize, sid: String, nodes: usize) -> Self {
        Self {
            round_id,
            sid,
            decision_emitted: false,
            decision_vector: None,
            proposals: (0..nodes).map(|_| PrbcState::default()).collect(),
            mvba: MvbaState::new(nodes),
            outbound: VecDeque::new(),
        }
    }

    fn nodes(&self) -> usize {
        self.proposals.len()
    }

    fn prbc_completion_count(&self) -> usize {
        self.proposals
            .iter()
            .filter(|proposal| proposal.proposal_ready.is_some())
            .count()
    }

    fn completion_vector(&self) -> Vec<bool> {
        self.proposals
            .iter()
            .map(|proposal| proposal.proposal_ready.is_some())
            .collect()
    }

    fn wrbc_completion_count(&self) -> usize {
        self.mvba
            .wrbc
            .iter()
            .filter(|instance| instance.delivered_digest.is_some())
            .count()
    }
}

#[derive(Default)]
struct RustAcsState {
    current_round: Option<RoundState>,
    rounds_started: usize,
    rounds_finished: usize,
    processed_commands: usize,
    command_counts: CommandCounts,
    batch_item_counts: BatchItemCounts,
    pending_pull_limit: Option<usize>,
}

pub(crate) struct RustAcsHost {
    pid: usize,
    faulty: usize,
    crypto: RustAcsCryptoMaterial,
    state: Mutex<RustAcsState>,
}

struct RustAcsCryptoMaterial {
    ecdsa_pks: Vec<[u8; 33]>,
    ecdsa_sk: [u8; 32],
    coin_pk: SigPublicParams,
    coin_sk: SigPrivateKeyShare,
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

    fn try_from_material(
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

impl RustAcsHost {
    pub(crate) fn new(
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

    fn encode_envelope(&self, round_id: usize, message: RustAcsMessage) -> Result<Vec<u8>, String> {
        bincode::serialize(&RustAcsEnvelope {
            round_id: round_id as u32,
            sender: self.pid as u32,
            message,
        })
        .map_err(|err| err.to_string())
    }

    fn decode_envelope(payload: &[u8]) -> Result<RustAcsEnvelope, String> {
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

    fn payload_digest(payload: &[u8]) -> [u8; 32] {
        Sha256::digest(payload).into()
    }

    fn encode_completion_vector(bits: &[bool]) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + bits.len());
        out.extend_from_slice(&(bits.len() as u16).to_be_bytes());
        for bit in bits {
            out.push(u8::from(*bit));
        }
        out
    }

    fn decode_completion_vector(raw: &[u8], n: usize) -> Result<Vec<bool>, String> {
        if raw.len() < 2 {
            return Err(String::from("invalid completion vector header"));
        }
        let size = u16::from_be_bytes([raw[0], raw[1]]) as usize;
        if size != n {
            return Err(format!(
                "completion vector size mismatch: expected {n}, got {size}"
            ));
        }
        if raw.len() != size + 2 {
            return Err(String::from("completion vector has trailing bytes"));
        }
        let mut bits = Vec::with_capacity(size);
        for &byte in &raw[2..] {
            match byte {
                0 => bits.push(false),
                1 => bits.push(true),
                _ => return Err(String::from("completion vector contains invalid bit")),
            }
        }
        Ok(bits)
    }

    fn coin_message(sid: &str, scope: CoinScope) -> Vec<u8> {
        match scope {
            CoinScope::Election { iteration } => {
                format!("{sid}{COIN_DOMAIN}:election:{iteration}").into_bytes()
            }
            CoinScope::Raba {
                iteration,
                loop_index,
            } => format!("{sid}{COIN_DOMAIN}:raba:{iteration}:{loop_index}").into_bytes(),
        }
    }

    fn count_matching_sender_map(map: &BTreeMap<usize, [u8; 32]>, digest: &[u8; 32]) -> usize {
        map.values().filter(|value| **value == *digest).count()
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

    fn queue_send(
        &self,
        round: &mut RoundState,
        recipient: usize,
        message: RustAcsMessage,
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
        message: RustAcsMessage,
    ) -> Result<(), String> {
        let payload = self.encode_envelope(round.round_id, message)?;
        round.outbound.push_back(AcsWireEvent::Broadcast {
            round_id: round.round_id,
            payload,
            include_self: false,
        });
        Ok(())
    }

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
                .map(|(sender, signature)| (*sender, *signature))
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
        let proposal = &mut round.proposals[leader];
        proposal.payload = Some(payload);
        proposal.output = Some(proof);
        proposal.proposal_ready = Some(artifact.clone());
        round.outbound.push_back(AcsWireEvent::ProposalReady {
            round_id: round.round_id,
            proposal: artifact,
        });
        Ok(true)
    }

    fn drive_prbc(&self, round: &mut RoundState) -> Result<bool, String> {
        let mut changed = false;
        let threshold = self.threshold(round);
        let data_threshold = self.data_threshold(round);
        for leader in 0..round.nodes() {
            let mut send_ready_for = None;
            let mut maybe_output_for = None;
            {
                let proposal = &round.proposals[leader];
                if proposal.output.is_none() {
                    for roothash in proposal.stripes.keys() {
                        let echo_count =
                            Self::count_matching_sender_map(&proposal.echo_by_sender, roothash);
                        let ready_count =
                            Self::count_matching_sender_map(&proposal.ready_by_sender, roothash);
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
                        RustAcsMessage::PrbcReady {
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

    fn drive_wrbc(&self, round: &mut RoundState) -> Result<bool, String> {
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

    fn drive_mvba(&self, round: &mut RoundState) -> Result<bool, String> {
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

    fn maybe_finalize_decision(&self, round: &mut RoundState) -> Result<bool, String> {
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
    ) -> Result<(), String> {
        if leader >= round.nodes() || sender != leader || stripe_index != self.pid {
            return Ok(());
        }
        if !merkle::verify_shard(&stripe, &proof, &roothash) {
            return Ok(());
        }
        let proposal = &mut round.proposals[leader];
        if proposal.leader_root.is_some() {
            return Ok(());
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
            RustAcsMessage::PrbcEcho {
                leader: leader as u32,
                roothash,
                proof,
                stripe,
                stripe_index: self.pid as u32,
            },
        )?;
        self.drive_round(round)
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
    ) -> Result<(), String> {
        if leader >= round.nodes() || stripe_index != sender {
            return Ok(());
        }
        if !merkle::verify_shard(&stripe, &proof, &roothash) {
            return Ok(());
        }
        let proposal = &mut round.proposals[leader];
        if let Some(existing) = proposal.echo_by_sender.get(&sender) {
            if *existing != roothash {
                return Ok(());
            }
            return Ok(());
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
        self.drive_round(round)
    }

    fn handle_prbc_ready(
        &self,
        round: &mut RoundState,
        sender: usize,
        leader: usize,
        roothash: [u8; 32],
        signature: Vec<u8>,
    ) -> Result<(), String> {
        if leader >= round.nodes() || sender >= self.crypto.ecdsa_pks.len() {
            return Ok(());
        }
        let signature: [u8; 64] = match signature.as_slice().try_into() {
            Ok(signature) => signature,
            Err(_) => return Ok(()),
        };
        let proposal = &mut round.proposals[leader];
        if let Some(existing) = proposal.ready_by_sender.get(&sender) {
            if *existing != roothash {
                return Ok(());
            }
            return Ok(());
        }
        let sid = Self::prbc_sid(&round.sid, leader);
        let digest = Self::ready_digest(&sid, &roothash);
        if sender == self.pid {
            match proposal.local_ready {
                Some((local_root, local_signature))
                    if local_root == roothash && local_signature == signature => {}
                _ => return Ok(()),
            }
        } else if !ecdsa::verify(&self.crypto.ecdsa_pks[sender], &digest, &signature) {
            return Ok(());
        }
        proposal.ready_by_sender.insert(sender, roothash);
        proposal
            .ready_signatures
            .entry(roothash)
            .or_default()
            .insert(sender, signature);
        self.drive_round(round)
    }

    fn handle_wrbc_send(
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

    fn handle_wrbc_echo(
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

    fn handle_wrbc_ready(
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

    fn handle_wrbc_value(
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

    fn buffer_or_handle_raba_message(
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

    fn handle_coin_share(
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

    fn handle_message(
        &self,
        round: &mut RoundState,
        sender: usize,
        message: RustAcsMessage,
    ) -> Result<(), String> {
        if round.decision_emitted {
            return Ok(());
        }
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
                proof,
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
                proof,
                stripe,
                stripe_index as usize,
            ),
            RustAcsMessage::PrbcReady {
                leader,
                roothash,
                signature,
            } => self.handle_prbc_ready(round, sender, leader as usize, roothash, signature),
            RustAcsMessage::WrbcSend { proposer, value } => {
                self.handle_wrbc_send(round, sender, proposer as usize, value)
            }
            RustAcsMessage::WrbcEcho { proposer, digest } => {
                self.handle_wrbc_echo(round, sender, proposer as usize, digest)
            }
            RustAcsMessage::WrbcReady { proposer, digest } => {
                self.handle_wrbc_ready(round, sender, proposer as usize, digest)
            }
            RustAcsMessage::WrbcValue { proposer, value } => {
                self.handle_wrbc_value(round, sender, proposer as usize, value)
            }
            RustAcsMessage::RabaVal {
                iteration,
                loop_index,
                value,
            } => self.buffer_or_handle_raba_message(
                round,
                iteration as usize,
                BufferedRabaMessage::Val {
                    sender,
                    loop_index: loop_index as usize,
                    value,
                },
            ),
            RustAcsMessage::RabaAux {
                iteration,
                loop_index,
                value,
            } => self.buffer_or_handle_raba_message(
                round,
                iteration as usize,
                BufferedRabaMessage::Aux {
                    sender,
                    loop_index: loop_index as usize,
                    value,
                },
            ),
            RustAcsMessage::RabaConf {
                iteration,
                loop_index,
                values,
            } => self.buffer_or_handle_raba_message(
                round,
                iteration as usize,
                BufferedRabaMessage::Conf {
                    sender,
                    loop_index: loop_index as usize,
                    values,
                },
            ),
            RustAcsMessage::RabaFinish { iteration, value } => self.buffer_or_handle_raba_message(
                round,
                iteration as usize,
                BufferedRabaMessage::Finish { sender, value },
            ),
            RustAcsMessage::CoinShare { scope, share } => {
                self.handle_coin_share(round, sender, scope, share)
            }
        }
    }
}

impl AcsHost for RustAcsHost {
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
                proof: merkle_result.proofs[recipient].clone(),
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

    fn finish_pull_outbound_wire_batch(&self) -> Result<Vec<AcsWireEvent>, String> {
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
            .map_err(|_| String::from("Rust ACS state poisoned"))?;
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
            .map_err(|_| String::from("Rust ACS state poisoned"))?;
        state.current_round = None;
        state.pending_pull_limit = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drive_acs::run_acs_round;

    fn build_hosts(protocol: Protocol, nodes: usize, faulty: usize) -> Vec<RustAcsHost> {
        serialize_crypto_payloads(protocol, nodes, faulty)
            .expect("crypto payloads should serialize")
            .into_iter()
            .enumerate()
            .map(|(pid, payload)| {
                RustAcsHost::new(
                    pid,
                    nodes,
                    faulty,
                    crate::acs_host::parse_acs_crypto_payload(protocol, &payload)
                        .expect("crypto payload should parse"),
                    r#"{"acs_host_backend":"rust"}"#,
                )
                .expect("Rust ACS host should construct")
            })
            .collect()
    }

    #[test]
    fn completion_vector_roundtrip_rejects_invalid_bits() {
        let encoded = RustAcsHost::encode_completion_vector(&[true, false, true, true]);
        let decoded =
            RustAcsHost::decode_completion_vector(&encoded, 4).expect("vector should decode");
        assert_eq!(decoded, vec![true, false, true, true]);
        assert!(RustAcsHost::decode_completion_vector(&[0, 4, 2, 0, 0, 1], 4).is_err());
    }

    #[test]
    fn rust_acs_round_reaches_consistent_decision() {
        let hosts = build_hosts(Protocol::HoneyBadger, 4, 1);
        let proposals = (0..4)
            .map(|pid| format!("rust-acs-proposal-{pid}").into_bytes())
            .collect::<Vec<_>>();
        let outcome =
            run_acs_round(&hosts, 0, "test:rust-acs:0:", &proposals, 5.0).expect("round succeeds");

        assert!(outcome.selected_proposal_ids.len() >= 3);
        assert_eq!(
            outcome.selected_proposal_ids.len(),
            outcome.selected_pids.len()
        );
        assert!(outcome.selected_pids.iter().all(|pid| *pid < 4));
    }
}
