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
    pub(super) proposal_ready: Option<AvailableProposal>,
    pub(super) ready_sent: bool,
    pub(super) local_ready: Option<([u8; 32], [u8; 64])>,
    pub(super) stripes: BTreeMap<[u8; 32], BTreeMap<usize, Vec<u8>>>,
    pub(super) proofs: BTreeMap<[u8; 32], BTreeMap<usize, MerkleProof>>,
    pub(super) echo_by_sender: BTreeMap<usize, [u8; 32]>,
    pub(super) ready_by_sender: BTreeMap<usize, [u8; 32]>,
    pub(super) ready_signatures: BTreeMap<[u8; 32], BTreeMap<usize, [u8; 64]>>,
    pub(super) proof_diffused: bool,
}

#[derive(Default)]
pub(super) struct PdState {
    pub(super) input_root: Option<[u8; 32]>,
    pub(super) input_sent: bool,
    pub(super) local_store: Option<PdStoreRecord>,
    pub(super) local_lock: Option<ThresholdProof>,
    pub(super) local_done: Option<ThresholdProof>,
    pub(super) stored_shares: BTreeMap<usize, Vec<u8>>,
    pub(super) locked_shares: BTreeMap<usize, Vec<u8>>,
    pub(super) lock_sent: bool,
    pub(super) done_sent: bool,
    pub(super) local_lock_proof: Option<ThresholdProof>,
    pub(super) local_done_proof: Option<ThresholdProof>,
}

#[derive(Default)]
pub(super) struct CoinState {
    pub(super) local_sent: bool,
    pub(super) shares: BTreeMap<usize, Vec<u8>>,
    pub(super) output: Option<u8>,
}

#[derive(Default)]
pub(super) struct RcPrepareInbox {
    pub(super) none_senders: BTreeSet<usize>,
    pub(super) proofs: BTreeMap<usize, ThresholdProof>,
}

#[derive(Default)]
pub(super) struct RcRecastInbox {
    pub(super) locks: BTreeMap<usize, ThresholdProof>,
    pub(super) stores: BTreeMap<([u8; 32], u32), PdStoreRecord>,
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

pub(super) type RecastShardsByRoot = BTreeMap<[u8; 32], BTreeMap<usize, (Vec<u8>, MerkleProof)>>;

pub(super) struct RecastState {
    pub(super) selected_lock: ThresholdProof,
    pub(super) lock_sent: bool,
    pub(super) store_sent: bool,
    pub(super) stripes_by_root: RecastShardsByRoot,
    pub(super) output_value: Option<Vec<u8>>,
}

impl RecastState {
    pub(super) fn new(selected_lock: ThresholdProof) -> Self {
        Self {
            selected_lock,
            lock_sent: false,
            store_sent: false,
            stripes_by_root: BTreeMap::new(),
            output_value: None,
        }
    }
}

pub(super) struct ActiveMvbaRound {
    pub(super) round_id: usize,
    pub(super) leader: usize,
    pub(super) prepare_sent: bool,
    pub(super) ballot: Option<bool>,
    pub(super) selected_lock: Option<ThresholdProof>,
    pub(super) aba: Option<AbaState>,
    pub(super) recast: Option<RecastState>,
}

impl ActiveMvbaRound {
    pub(super) fn new(round_id: usize, leader: usize) -> Self {
        Self {
            round_id,
            leader,
            prepare_sent: false,
            ballot: None,
            selected_lock: None,
            aba: None,
            recast: None,
        }
    }
}

pub(super) struct DumboMvbaState {
    pub(super) local_input: Option<Vec<u8>>,
    pub(super) proof_vector: Vec<Option<PrbcProof>>,
    pub(super) pd: Vec<PdState>,
    pub(super) stores: BTreeMap<usize, PdStoreRecord>,
    pub(super) locks: BTreeMap<usize, ThresholdProof>,
    pub(super) dones: BTreeMap<usize, ThresholdProof>,
    pub(super) coin_states: BTreeMap<DumboCoinScope, CoinState>,
    pub(super) permutations: BTreeMap<usize, Vec<usize>>,
    pub(super) next_mvba_round: usize,
    pub(super) active_round: Option<ActiveMvbaRound>,
    pub(super) rc_prepare_inboxes: BTreeMap<usize, RcPrepareInbox>,
    pub(super) rc_recast_inboxes: BTreeMap<usize, RcRecastInbox>,
    pub(super) aba_inboxes: BTreeMap<usize, BTreeMap<usize, AbaEpochInbox>>,
    pub(super) output_value: Option<Vec<u8>>,
}

impl DumboMvbaState {
    pub(super) fn new(nodes: usize) -> Self {
        Self {
            local_input: None,
            proof_vector: (0..nodes).map(|_| None).collect(),
            pd: (0..nodes).map(|_| PdState::default()).collect(),
            stores: BTreeMap::new(),
            locks: BTreeMap::new(),
            dones: BTreeMap::new(),
            coin_states: BTreeMap::new(),
            permutations: BTreeMap::new(),
            next_mvba_round: 0,
            active_round: None,
            rc_prepare_inboxes: BTreeMap::new(),
            rc_recast_inboxes: BTreeMap::new(),
            aba_inboxes: BTreeMap::new(),
            output_value: None,
        }
    }
}

pub(super) struct RoundState {
    pub(super) round_id: usize,
    pub(super) sid: String,
    pub(super) decision_emitted: bool,
    pub(super) selected_proofs: Option<Vec<Option<PrbcProof>>>,
    pub(super) proposals: Vec<PrbcState>,
    pub(super) mvba: DumboMvbaState,
    pub(super) dirty_prbc_leaders: BTreeSet<usize>,
    pub(super) mvba_dirty: bool,
    pub(super) outbound: VecDeque<AcsEvent>,
}

impl RoundState {
    pub(super) fn new(round_id: usize, sid: String, nodes: usize) -> Self {
        Self {
            round_id,
            sid,
            decision_emitted: false,
            selected_proofs: None,
            proposals: (0..nodes).map(|_| PrbcState::default()).collect(),
            mvba: DumboMvbaState::new(nodes),
            dirty_prbc_leaders: BTreeSet::new(),
            mvba_dirty: false,
            outbound: VecDeque::new(),
        }
    }

    pub(super) fn nodes(&self) -> usize {
        self.proposals.len()
    }

    pub(super) fn mark_prbc_dirty(&mut self, leader: usize) {
        self.dirty_prbc_leaders.insert(leader);
    }

    pub(super) fn take_dirty_prbc_leaders(&mut self) -> Vec<usize> {
        self.dirty_prbc_leaders.iter().copied().collect::<Vec<_>>()
    }

    pub(super) fn clear_dirty_prbc_leader(&mut self, leader: usize) {
        self.dirty_prbc_leaders.remove(&leader);
    }

    pub(super) fn mark_mvba_dirty(&mut self) {
        self.mvba_dirty = true;
    }

    pub(super) fn valid_diffuse_count(&self) -> usize {
        self.mvba
            .proof_vector
            .iter()
            .filter(|proof| proof.is_some())
            .count()
    }
}

#[derive(Default)]
pub(super) struct RustDumboState {
    pub(super) current_round: Option<RoundState>,
    pub(super) rounds_started: usize,
    pub(super) rounds_finished: usize,
    pub(super) processed_commands: usize,
    pub(super) command_counts: CommandCounts,
    pub(super) batch_item_counts: BatchItemCounts,
    pub(super) pending_pull_limit: Option<usize>,
}
