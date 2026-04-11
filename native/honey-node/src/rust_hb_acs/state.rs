use super::*;

#[derive(Default)]
pub(super) struct CommandCounts {
    pub(super) start_round: usize,
    pub(super) push_inbound_wire_batch: usize,
    pub(super) pull_outbound_wire_batch: usize,
    pub(super) stats: usize,
}

#[derive(Default)]
pub(super) struct BatchItemCounts {
    pub(super) push_inbound_wire_batch_items: usize,
    pub(super) pull_outbound_wire_batch_items: usize,
}

#[derive(Default)]
pub(super) struct RbcState {
    pub(super) leader_root: Option<[u8; 32]>,
    pub(super) payload: Option<Vec<u8>>,
    pub(super) proposal_ready: Option<ProposalArtifact>,
    pub(super) ready_sent: bool,
    pub(super) stripes: BTreeMap<[u8; 32], BTreeMap<usize, Vec<u8>>>,
    pub(super) proofs: BTreeMap<[u8; 32], BTreeMap<usize, MerkleProof>>,
    pub(super) echo_by_sender: BTreeMap<usize, [u8; 32]>,
    pub(super) ready_by_sender: BTreeMap<usize, [u8; 32]>,
}

#[derive(Default)]
pub(super) struct PrbcState {
    pub(super) leader_root: Option<[u8; 32]>,
    pub(super) payload: Option<Vec<u8>>,
    pub(super) output: Option<PrbcProof>,
    pub(super) proposal_ready: Option<ProposalArtifact>,
    pub(super) ready_sent: bool,
    pub(super) local_ready: Option<([u8; 32], [u8; 64])>,
    pub(super) stripes: BTreeMap<[u8; 32], BTreeMap<usize, Vec<u8>>>,
    pub(super) proofs: BTreeMap<[u8; 32], BTreeMap<usize, MerkleProof>>,
    pub(super) echo_by_sender: BTreeMap<usize, [u8; 32]>,
    pub(super) ready_by_sender: BTreeMap<usize, [u8; 32]>,
    pub(super) ready_signatures: BTreeMap<[u8; 32], BTreeMap<usize, [u8; 64]>>,
}

#[derive(Default)]
pub(super) struct CoinState {
    pub(super) local_sent: bool,
    pub(super) shares: BTreeMap<usize, Vec<u8>>,
    pub(super) output: Option<u8>,
}

#[derive(Default)]
pub(super) struct AbaEpochInbox {
    pub(super) est_by_sender: BTreeMap<usize, [bool; 2]>,
    pub(super) aux_by_sender: BTreeMap<usize, [bool; 2]>,
    pub(super) conf_by_sender: BTreeMap<usize, [bool; 2]>,
    pub(super) bin_values: [bool; 2],
}

#[derive(Default)]
pub(super) struct AbaEpochProgress {
    pub(super) est_sent: [bool; 2],
    pub(super) aux_sent: Option<bool>,
    pub(super) conf_sent: [bool; 3],
    pub(super) conf_result: Option<[bool; 2]>,
    pub(super) coin_value: Option<bool>,
}

pub(super) struct AbaState {
    pub(super) current_epoch: usize,
    pub(super) est: bool,
    pub(super) output: Option<bool>,
    pub(super) epochs: BTreeMap<usize, AbaEpochProgress>,
}

impl AbaState {
    pub(super) fn new(est: bool) -> Self {
        Self {
            current_epoch: 0,
            est,
            output: None,
            epochs: BTreeMap::new(),
        }
    }
}

pub(super) struct Bkr93State {
    pub(super) aba_input_sent: Vec<bool>,
    pub(super) aba_outputs: Vec<Option<bool>>,
}

impl Bkr93State {
    pub(super) fn new(nodes: usize) -> Self {
        Self {
            aba_input_sent: vec![false; nodes],
            aba_outputs: vec![None; nodes],
        }
    }

    pub(super) fn count_ones(&self) -> usize {
        self.aba_outputs
            .iter()
            .filter(|outcome| matches!(outcome, Some(true)))
            .count()
    }

    pub(super) fn aba_complete(&self) -> bool {
        self.aba_outputs.iter().all(Option::is_some)
    }
}

pub(super) struct RoundState {
    pub(super) round_id: usize,
    pub(super) sid: String,
    pub(super) mode: HbBroadcastMode,
    pub(super) decision_emitted: bool,
    pub(super) rbc: Vec<RbcState>,
    pub(super) prbc: Vec<PrbcState>,
    pub(super) bkr: Bkr93State,
    pub(super) aba_states: Vec<Option<AbaState>>,
    pub(super) aba_inboxes: BTreeMap<usize, BTreeMap<usize, AbaEpochInbox>>,
    pub(super) coin_states: BTreeMap<HbCoinScope, CoinState>,
    pub(super) outbound: VecDeque<AcsWireEvent>,
}

impl RoundState {
    pub(super) fn new(round_id: usize, sid: String, nodes: usize, mode: HbBroadcastMode) -> Self {
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

    pub(super) fn nodes(&self) -> usize {
        self.rbc.len()
    }

    pub(super) fn proposal_ready(&self, leader: usize) -> Option<&ProposalArtifact> {
        match self.mode {
            HbBroadcastMode::Rbc => self.rbc[leader].proposal_ready.as_ref(),
            HbBroadcastMode::Prbc => self.prbc[leader].proposal_ready.as_ref(),
        }
    }
}

#[derive(Default)]
pub(super) struct RustHbState {
    pub(super) current_round: Option<RoundState>,
    pub(super) rounds_started: usize,
    pub(super) rounds_finished: usize,
    pub(super) processed_commands: usize,
    pub(super) command_counts: CommandCounts,
    pub(super) batch_item_counts: BatchItemCounts,
    pub(super) pending_pull_limit: Option<usize>,
}
