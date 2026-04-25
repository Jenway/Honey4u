use crate::acs::protocol::AcsProtocol;

pub(crate) struct NodeRuntimeArgs {
    pub(crate) pid: usize,
    pub(crate) sid: String,
    pub(crate) acs_protocol: AcsProtocol,
    pub(crate) nodes: usize,
    pub(crate) faulty: usize,
    pub(crate) rounds: usize,
    pub(crate) batch_size: usize,
    pub(crate) global_timeout: f64,
    pub(crate) addresses_json: String,
    pub(crate) hb_crypto_json: String,
    pub(crate) acs_crypto_json: String,
    pub(crate) config_json: String,
    pub(crate) start_at_ms: Option<u64>,
    pub(crate) result_path: Option<String>,
}
