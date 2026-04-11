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
pub(super) struct WrbcState {
    pub(super) send_value: Option<Vec<u8>>,
    pub(super) send_digest: Option<[u8; 32]>,
    pub(super) echo_sent: bool,
    pub(super) ready_sent: bool,
    pub(super) delivered_digest: Option<[u8; 32]>,
    pub(super) delivered_value: Option<Vec<u8>>,
    pub(super) value_broadcasted: bool,
    pub(super) known_values: BTreeMap<[u8; 32], Vec<u8>>,
    pub(super) echo_by_sender: BTreeMap<usize, [u8; 32]>,
    pub(super) ready_by_sender: BTreeMap<usize, [u8; 32]>,
}

#[derive(Default)]
pub(super) struct CoinState {
    pub(super) local_sent: bool,
    pub(super) shares: BTreeMap<usize, Vec<u8>>,
    pub(super) output: Option<u8>,
}

#[derive(Clone)]
pub(super) enum BufferedRabaMessage {
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

pub(super) struct RabaLoopState {
    pub(super) index: usize,
    pub(super) input: bool,
    pub(super) values: [bool; 2],
    pub(super) val_by_sender: BTreeMap<usize, [bool; 2]>,
    pub(super) aux_by_sender: BTreeMap<usize, [bool; 2]>,
    pub(super) conf_by_sender: BTreeMap<usize, [bool; 2]>,
    pub(super) val_sent: [bool; 2],
    pub(super) aux_sent: [bool; 2],
    pub(super) conf_sent: bool,
    pub(super) coin_requested: bool,
    pub(super) coin_value: Option<bool>,
    pub(super) resolved: bool,
    pub(super) reproposed_true: bool,
}

impl RabaLoopState {
    pub(super) fn new(index: usize, input: bool) -> Self {
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

pub(super) struct RabaState {
    pub(super) iteration: usize,
    pub(super) leader: usize,
    pub(super) current_loop: RabaLoopState,
    pub(super) finish_by_sender: BTreeMap<usize, bool>,
    pub(super) finish_sent: Option<bool>,
    pub(super) output: Option<bool>,
    pub(super) future_messages: BTreeMap<usize, Vec<BufferedRabaMessage>>,
}

impl RabaState {
    pub(super) fn new(iteration: usize, leader: usize, input: bool) -> Self {
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

pub(super) struct MvbaIterationState {
    pub(super) index: usize,
    pub(super) leader: Option<usize>,
    pub(super) raba: Option<RabaState>,
}

pub(super) struct MvbaState {
    pub(super) started: bool,
    pub(super) local_input: Option<Vec<u8>>,
    pub(super) wrbc: Vec<WrbcState>,
    pub(super) coin_states: BTreeMap<CoinScope, CoinState>,
    pub(super) current_iteration: Option<MvbaIterationState>,
    pub(super) future_raba_messages: BTreeMap<usize, Vec<BufferedRabaMessage>>,
    pub(super) output_value: Option<Vec<u8>>,
}

impl MvbaState {
    pub(super) fn new(nodes: usize) -> Self {
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

pub(super) struct RoundState {
    pub(super) round_id: usize,
    pub(super) sid: String,
    pub(super) decision_emitted: bool,
    pub(super) decision_vector: Option<Vec<bool>>,
    pub(super) proposals: Vec<PrbcState>,
    pub(super) mvba: MvbaState,
    pub(super) outbound: VecDeque<AcsWireEvent>,
}

impl RoundState {
    pub(super) fn new(round_id: usize, sid: String, nodes: usize) -> Self {
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

    pub(super) fn nodes(&self) -> usize {
        self.proposals.len()
    }

    pub(super) fn prbc_completion_count(&self) -> usize {
        self.proposals
            .iter()
            .filter(|proposal| proposal.proposal_ready.is_some())
            .count()
    }

    pub(super) fn completion_vector(&self) -> Vec<bool> {
        self.proposals
            .iter()
            .map(|proposal| proposal.proposal_ready.is_some())
            .collect()
    }

    pub(super) fn wrbc_completion_count(&self) -> usize {
        self.mvba
            .wrbc
            .iter()
            .filter(|instance| instance.delivered_digest.is_some())
            .count()
    }
}

#[derive(Default)]
pub(super) struct RustAcsState {
    pub(super) current_round: Option<RoundState>,
    pub(super) rounds_started: usize,
    pub(super) rounds_finished: usize,
    pub(super) processed_commands: usize,
    pub(super) command_counts: CommandCounts,
    pub(super) batch_item_counts: BatchItemCounts,
    pub(super) pending_pull_limit: Option<usize>,
}
