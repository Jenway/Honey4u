use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct AvailableProposal {
    pub proposal_id: String,
    pub proposer: usize,
    pub payload: Vec<u8>,
    pub digest: Vec<u8>,
    pub availability_proof: Vec<u8>,
}

pub type ProposalStore = BTreeMap<String, AvailableProposal>;
