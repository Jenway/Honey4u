use super::super::config::{BroadcastPoolConfig, ByzantineNodeConfig};
use super::super::hb_shell::{HbPkePrivateKeyShare, HbPkePublicParams};
use super::super::telemetry::DriverPhaseStats;
use super::super::wire::fetch::PoolFetchWire;
use super::metrics::RoundMetricsSnapshot;
use crate::driver_node::args::NodeRuntimeArgs;
use honey_acs::AcsBackend;
use honey_node::transport::LocalTcpTransport;
use std::collections::BTreeMap;

pub(in crate::driver_node) struct InboundShareBundle {
    pub(in crate::driver_node) sender: usize,
    pub(in crate::driver_node) selected_proposal_ids: Vec<String>,
    pub(in crate::driver_node) selected_digests: Vec<Vec<u8>>,
    pub(in crate::driver_node) shares: Vec<Option<Vec<u8>>>,
}

#[derive(Default)]
pub(in crate::driver_node) struct DriverCarryovers {
    pub(in crate::driver_node) acs_wire_payloads: BTreeMap<usize, Vec<Vec<u8>>>,
    pub(in crate::driver_node) share_bundles: BTreeMap<usize, Vec<InboundShareBundle>>,
    pub(in crate::driver_node) pool_fetch_responses: BTreeMap<usize, Vec<PoolFetchWire>>,
}

#[derive(Default)]
pub(in crate::driver_node) struct QueuePeaksSnapshot {
    pub(in crate::driver_node) raw_inbound_messages: usize,
    pub(in crate::driver_node) raw_outbound_messages: usize,
    pub(in crate::driver_node) transport_inbound: usize,
    pub(in crate::driver_node) transport_outbound: usize,
}

pub(in crate::driver_node) struct DriverRoundOutcome {
    pub(in crate::driver_node) build_seconds: f64,
    pub(in crate::driver_node) acs_seconds: f64,
    pub(in crate::driver_node) tpke_seconds: f64,
    pub(in crate::driver_node) protocol_seconds: f64,
    pub(in crate::driver_node) wall_seconds: f64,
    pub(in crate::driver_node) metrics: RoundMetricsSnapshot,
    pub(in crate::driver_node) selected_proposal_ids: Vec<String>,
    pub(in crate::driver_node) selected_pids: Vec<usize>,
    pub(in crate::driver_node) reused_reference_count: usize,
    pub(in crate::driver_node) delivered_count: usize,
    pub(in crate::driver_node) block_payload: Vec<u8>,
}

pub(in crate::driver_node) struct DriverNodeRoundTelemetry {
    pub(in crate::driver_node) selected_proposal_ids: Vec<String>,
    pub(in crate::driver_node) selected_pids: Vec<usize>,
    pub(in crate::driver_node) block_digest: String,
    pub(in crate::driver_node) block_size: usize,
    pub(in crate::driver_node) chain_digest: String,
    pub(in crate::driver_node) build_seconds: f64,
    pub(in crate::driver_node) acs_seconds: f64,
    pub(in crate::driver_node) tpke_seconds: f64,
    pub(in crate::driver_node) protocol_seconds: f64,
    pub(in crate::driver_node) wall_seconds: f64,
    pub(in crate::driver_node) delivered_count: usize,
    pub(in crate::driver_node) reused_reference_count: usize,
    pub(in crate::driver_node) tpke_partial_open_seconds: f64,
    pub(in crate::driver_node) tpke_combine_seconds: f64,
    pub(in crate::driver_node) acs_outbound_events: usize,
    pub(in crate::driver_node) tpke_combine_calls: usize,
    pub(in crate::driver_node) fetch_requests_sent: usize,
    pub(in crate::driver_node) fetch_responses_served: usize,
    pub(in crate::driver_node) fetch_responses_received: usize,
    pub(in crate::driver_node) fetched_reference_count: usize,
    pub(in crate::driver_node) byzantine_invalid_fetch_responses_sent: usize,
    pub(in crate::driver_node) byzantine_fetch_requests_ignored: usize,
    pub(in crate::driver_node) byzantine_share_broadcast_suppressed: usize,
    pub(in crate::driver_node) byzantine_empty_proposal_used: bool,
    pub(in crate::driver_node) driver_phase_stats: DriverPhaseStats,
}

pub(in crate::driver_node) struct DriverRoundCtx<'a> {
    pub(in crate::driver_node) host: &'a dyn AcsBackend,
    pub(in crate::driver_node) transport: &'a LocalTcpTransport,
    pub(in crate::driver_node) public_key: &'a HbPkePublicParams,
    pub(in crate::driver_node) private_share: &'a HbPkePrivateKeyShare,
    pub(in crate::driver_node) args: &'a NodeRuntimeArgs,
    pub(in crate::driver_node) broadcast_pool_config: &'a BroadcastPoolConfig,
    pub(in crate::driver_node) byzantine_node_config: ByzantineNodeConfig,
}

pub(in crate::driver_node) struct DriverNodeResult {
    pub(in crate::driver_node) round_build_latencies: Vec<f64>,
    pub(in crate::driver_node) acs_latencies: Vec<f64>,
    pub(in crate::driver_node) tpke_stage_latencies: Vec<f64>,
    pub(in crate::driver_node) round_latencies: Vec<f64>,
    pub(in crate::driver_node) round_wall_latencies: Vec<f64>,
    pub(in crate::driver_node) acs_pull_latencies: Vec<f64>,
    pub(in crate::driver_node) tpke_partial_open_latencies: Vec<f64>,
    pub(in crate::driver_node) tpke_combine_latencies: Vec<f64>,
    pub(in crate::driver_node) round_proposed_counts: Vec<usize>,
    pub(in crate::driver_node) round_delivered_counts: Vec<usize>,
    pub(in crate::driver_node) origin_tx_latencies_by_round: Vec<Vec<f64>>,
    pub(in crate::driver_node) acs_pull_calls: Vec<usize>,
    pub(in crate::driver_node) acs_empty_pull_calls: Vec<usize>,
    pub(in crate::driver_node) acs_inbound_wire_batches: Vec<usize>,
    pub(in crate::driver_node) acs_inbound_wire_items: Vec<usize>,
    pub(in crate::driver_node) acs_outbound_events: Vec<usize>,
    pub(in crate::driver_node) tpke_combine_calls: Vec<usize>,
    pub(in crate::driver_node) stale_acs_frames_dropped: Vec<usize>,
    pub(in crate::driver_node) fetch_requests_sent: Vec<usize>,
    pub(in crate::driver_node) fetch_responses_served: Vec<usize>,
    pub(in crate::driver_node) fetch_responses_received: Vec<usize>,
    pub(in crate::driver_node) fetched_reference_count: Vec<usize>,
    pub(in crate::driver_node) byzantine_invalid_fetch_responses_sent: Vec<usize>,
    pub(in crate::driver_node) byzantine_fetch_requests_ignored: Vec<usize>,
    pub(in crate::driver_node) byzantine_share_broadcast_suppressed: Vec<usize>,
    pub(in crate::driver_node) byzantine_empty_proposal_used: Vec<bool>,
    pub(in crate::driver_node) byzantine_behavior: &'static str,
    pub(in crate::driver_node) chain_digest: String,
    pub(in crate::driver_node) per_round_selected_pids: Vec<Vec<usize>>,
    pub(in crate::driver_node) per_round_block_digests: Vec<String>,
    pub(in crate::driver_node) per_round_block_sizes: Vec<usize>,
    pub(in crate::driver_node) per_round_chain_digests: Vec<String>,
    pub(in crate::driver_node) round_details: Vec<DriverNodeRoundTelemetry>,
    pub(in crate::driver_node) rust_broadcast_mempool_size: usize,
}
