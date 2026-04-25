use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub(crate) struct AvailableProposal {
    pub(crate) proposal_id: String,
    pub(crate) proposer: usize,
    pub(crate) payload: Vec<u8>,
    pub(crate) digest: Vec<u8>,
    pub(crate) availability_proof: Vec<u8>,
}

pub(crate) type ProposalStore = BTreeMap<String, AvailableProposal>;
