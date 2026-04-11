use super::config::{BroadcastPoolBackend, BroadcastPoolConfig};
use crate::{
    AcsHost, DriverPhaseStats, HbPkePrivateKeyShare, HbPkePublicParams, RunDriverNodeArgs,
};
use honey_node::transport::LocalTcpTransport;
use std::collections::BTreeMap;

pub(super) struct InboundShareBundle {
    pub(super) sender: usize,
    pub(super) selected_batch_refs: Vec<(u32, u32)>,
    pub(super) shares: Vec<Option<Vec<u8>>>,
}

pub(super) type BatchArchive = BTreeMap<(u32, u32), Vec<u8>>;

#[derive(Default)]
pub(super) struct DriverCarryovers {
    pub(super) acs_wire_payloads: BTreeMap<usize, Vec<Vec<u8>>>,
    pub(super) sealed_batches: BTreeMap<usize, BTreeMap<usize, Vec<u8>>>,
    pub(super) share_bundles: BTreeMap<usize, Vec<InboundShareBundle>>,
}

#[derive(Default)]
pub(super) struct QueuePeaksSnapshot {
    pub(super) raw_inbound_messages: usize,
    pub(super) raw_outbound_messages: usize,
    pub(super) transport_inbound: usize,
    pub(super) transport_outbound: usize,
}

pub(super) struct DriverRoundOutcome {
    pub(super) build_seconds: f64,
    pub(super) acs_seconds: f64,
    pub(super) tpke_seconds: f64,
    pub(super) protocol_seconds: f64,
    pub(super) wall_seconds: f64,
    pub(super) acs_pull_seconds: f64,
    pub(super) tpke_partial_open_seconds: f64,
    pub(super) tpke_combine_seconds: f64,
    pub(super) acs_pull_calls: usize,
    pub(super) acs_empty_pull_calls: usize,
    pub(super) acs_inbound_wire_batches: usize,
    pub(super) acs_inbound_wire_items: usize,
    pub(super) acs_outbound_events: usize,
    pub(super) tpke_combine_calls: usize,
    pub(super) stale_acs_frames_dropped: usize,
    pub(super) selected_proposal_ids: Vec<String>,
    pub(super) selected_pids: Vec<usize>,
    pub(super) reused_reference_count: usize,
    pub(super) delivered_count: usize,
    pub(super) block_payload: Vec<u8>,
    pub(super) driver_stats: DriverPhaseStats,
}

pub(super) struct DriverNodeRoundTelemetry {
    pub(super) selected_proposal_ids: Vec<String>,
    pub(super) selected_pids: Vec<usize>,
    pub(super) block_digest: String,
    pub(super) block_size: usize,
    pub(super) chain_digest: String,
    pub(super) build_seconds: f64,
    pub(super) acs_seconds: f64,
    pub(super) tpke_seconds: f64,
    pub(super) protocol_seconds: f64,
    pub(super) wall_seconds: f64,
    pub(super) delivered_count: usize,
    pub(super) reused_reference_count: usize,
    pub(super) tpke_partial_open_seconds: f64,
    pub(super) tpke_combine_seconds: f64,
    pub(super) acs_outbound_events: usize,
    pub(super) tpke_combine_calls: usize,
    pub(super) driver_phase_stats: DriverPhaseStats,
}

pub(super) struct DriverRoundCtx<'a> {
    pub(super) host: &'a dyn AcsHost,
    pub(super) transport: &'a LocalTcpTransport,
    pub(super) public_key: &'a HbPkePublicParams,
    pub(super) private_share: &'a HbPkePrivateKeyShare,
    pub(super) args: &'a RunDriverNodeArgs,
    pub(super) broadcast_pool_config: &'a BroadcastPoolConfig,
}

pub(super) struct DriverNodeResult {
    pub(super) round_build_latencies: Vec<f64>,
    pub(super) acs_latencies: Vec<f64>,
    pub(super) tpke_stage_latencies: Vec<f64>,
    pub(super) round_latencies: Vec<f64>,
    pub(super) round_wall_latencies: Vec<f64>,
    pub(super) acs_pull_latencies: Vec<f64>,
    pub(super) tpke_partial_open_latencies: Vec<f64>,
    pub(super) tpke_combine_latencies: Vec<f64>,
    pub(super) round_proposed_counts: Vec<usize>,
    pub(super) round_delivered_counts: Vec<usize>,
    pub(super) origin_tx_latencies_by_round: Vec<Vec<f64>>,
    pub(super) acs_pull_calls: Vec<usize>,
    pub(super) acs_empty_pull_calls: Vec<usize>,
    pub(super) acs_inbound_wire_batches: Vec<usize>,
    pub(super) acs_inbound_wire_items: Vec<usize>,
    pub(super) acs_outbound_events: Vec<usize>,
    pub(super) tpke_combine_calls: Vec<usize>,
    pub(super) stale_acs_frames_dropped: Vec<usize>,
    pub(super) chain_digest: String,
    pub(super) per_round_selected_pids: Vec<Vec<usize>>,
    pub(super) per_round_block_digests: Vec<String>,
    pub(super) per_round_block_sizes: Vec<usize>,
    pub(super) per_round_chain_digests: Vec<String>,
    pub(super) round_details: Vec<DriverNodeRoundTelemetry>,
    pub(super) rust_broadcast_mempool_size: usize,
    pub(super) broadcast_pool_backend: BroadcastPoolBackend,
}
