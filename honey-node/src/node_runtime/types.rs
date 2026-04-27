use super::config::{BroadcastPoolConfig, ByzantineNodeConfig};
use super::hb::{HbPkePrivateKeyShare, HbPkePublicParams};
use super::phase_stats::DriverPhaseStats;
use super::pool_wire::PoolFetchWire;
use crate::node_runtime::args::NodeRuntimeArgs;
use honey_acs::AcsBackend;
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
    pub(super) pool_fetch_responses: BTreeMap<usize, Vec<PoolFetchWire>>,
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
    pub(super) fetch_requests_sent: usize,
    pub(super) fetch_responses_served: usize,
    pub(super) fetch_responses_received: usize,
    pub(super) fetched_reference_count: usize,
    pub(super) byzantine_invalid_fetch_responses_sent: usize,
    pub(super) byzantine_fetch_requests_ignored: usize,
    pub(super) byzantine_batch_broadcast_suppressed: usize,
    pub(super) byzantine_share_broadcast_suppressed: usize,
    pub(super) byzantine_empty_proposal_used: bool,
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
    pub(super) fetch_requests_sent: usize,
    pub(super) fetch_responses_served: usize,
    pub(super) fetch_responses_received: usize,
    pub(super) fetched_reference_count: usize,
    pub(super) byzantine_invalid_fetch_responses_sent: usize,
    pub(super) byzantine_fetch_requests_ignored: usize,
    pub(super) byzantine_batch_broadcast_suppressed: usize,
    pub(super) byzantine_share_broadcast_suppressed: usize,
    pub(super) byzantine_empty_proposal_used: bool,
    pub(super) driver_phase_stats: DriverPhaseStats,
}

pub(super) struct DriverRoundCtx<'a> {
    pub(super) host: &'a dyn AcsBackend,
    pub(super) transport: &'a LocalTcpTransport,
    pub(super) public_key: &'a HbPkePublicParams,
    pub(super) private_share: &'a HbPkePrivateKeyShare,
    pub(super) args: &'a NodeRuntimeArgs,
    pub(super) broadcast_pool_config: &'a BroadcastPoolConfig,
    pub(super) byzantine_node_config: ByzantineNodeConfig,
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
    pub(super) fetch_requests_sent: Vec<usize>,
    pub(super) fetch_responses_served: Vec<usize>,
    pub(super) fetch_responses_received: Vec<usize>,
    pub(super) fetched_reference_count: Vec<usize>,
    pub(super) byzantine_invalid_fetch_responses_sent: Vec<usize>,
    pub(super) byzantine_fetch_requests_ignored: Vec<usize>,
    pub(super) byzantine_batch_broadcast_suppressed: Vec<usize>,
    pub(super) byzantine_share_broadcast_suppressed: Vec<usize>,
    pub(super) byzantine_empty_proposal_used: Vec<bool>,
    pub(super) byzantine_behavior: &'static str,
    pub(super) chain_digest: String,
    pub(super) per_round_selected_pids: Vec<Vec<usize>>,
    pub(super) per_round_block_digests: Vec<String>,
    pub(super) per_round_block_sizes: Vec<usize>,
    pub(super) per_round_chain_digests: Vec<String>,
    pub(super) round_details: Vec<DriverNodeRoundTelemetry>,
    pub(super) rust_broadcast_mempool_size: usize,
}
