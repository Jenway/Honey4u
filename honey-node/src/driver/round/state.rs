use super::super::config::{BroadcastPoolConfig, ByzantineNodeConfig};
use super::super::encryption::{HbPkePrivateKeyShare, HbPkePublicParams};
use super::super::frame::PoolFetchWire;
use super::metrics::{DriverPhaseStats, RoundMetricsSnapshot};
use crate::driver::args::NodeRuntimeArgs;
use honey_acs::{AcsBackend, AcsRuntimeCapabilities};
use honey_transport::TransportHandle;
use std::collections::BTreeMap;

pub(in crate::driver) struct InboundTpkeShare {
    pub(in crate::driver) sender: usize,
    pub(in crate::driver) payload_digest: Vec<u8>,
    pub(in crate::driver) share: Vec<u8>,
}

#[derive(Default)]
pub(in crate::driver) struct DriverCarryovers {
    pub(in crate::driver) acs_wire_payloads: BTreeMap<usize, Vec<Vec<u8>>>,
    pub(in crate::driver) tpke_shares: BTreeMap<usize, Vec<InboundTpkeShare>>,
    pub(in crate::driver) pool_fetch_responses: BTreeMap<usize, Vec<PoolFetchWire>>,
}

#[derive(Default)]
pub(in crate::driver) struct QueuePeaksSnapshot {
    pub(in crate::driver) raw_inbound_messages: usize,
    pub(in crate::driver) raw_outbound_messages: usize,
    pub(in crate::driver) transport_inbound: usize,
    pub(in crate::driver) transport_outbound: usize,
}

pub(in crate::driver) struct DriverRoundOutcome {
    pub(in crate::driver) build_seconds: f64,
    pub(in crate::driver) acs_seconds: f64,
    pub(in crate::driver) tpke_seconds: f64,
    pub(in crate::driver) protocol_seconds: f64,
    pub(in crate::driver) wall_seconds: f64,
    pub(in crate::driver) metrics: RoundMetricsSnapshot,
    pub(in crate::driver) selected_proposal_ids: Vec<String>,
    pub(in crate::driver) selected_pids: Vec<usize>,
    pub(in crate::driver) reused_reference_count: usize,
    pub(in crate::driver) delivered_count: usize,
    pub(in crate::driver) block_payload: Vec<u8>,
}

pub(in crate::driver) struct DriverNodeRoundTelemetry {
    pub(in crate::driver) selected_proposal_ids: Vec<String>,
    pub(in crate::driver) selected_pids: Vec<usize>,
    pub(in crate::driver) block_digest: String,
    pub(in crate::driver) block_size: usize,
    pub(in crate::driver) chain_digest: String,
    pub(in crate::driver) build_seconds: f64,
    pub(in crate::driver) acs_seconds: f64,
    pub(in crate::driver) tpke_seconds: f64,
    pub(in crate::driver) protocol_seconds: f64,
    pub(in crate::driver) wall_seconds: f64,
    pub(in crate::driver) delivered_count: usize,
    pub(in crate::driver) reused_reference_count: usize,
    pub(in crate::driver) tpke_partial_open_seconds: f64,
    pub(in crate::driver) tpke_combine_seconds: f64,
    pub(in crate::driver) acs_outbound_events: usize,
    pub(in crate::driver) tpke_combine_calls: usize,
    pub(in crate::driver) fetch_requests_sent: usize,
    pub(in crate::driver) fetch_responses_served: usize,
    pub(in crate::driver) fetch_responses_received: usize,
    pub(in crate::driver) fetched_reference_count: usize,
    pub(in crate::driver) byzantine_invalid_fetch_responses_sent: usize,
    pub(in crate::driver) byzantine_fetch_requests_ignored: usize,
    pub(in crate::driver) byzantine_share_broadcast_suppressed: usize,
    pub(in crate::driver) byzantine_empty_proposal_used: bool,
    pub(in crate::driver) driver_phase_stats: DriverPhaseStats,
}

pub(in crate::driver) struct DriverRoundCtx<'a> {
    pub(in crate::driver) host: &'a dyn AcsBackend,
    pub(in crate::driver) transport: &'a dyn TransportHandle,
    pub(in crate::driver) public_key: &'a HbPkePublicParams,
    pub(in crate::driver) private_share: &'a HbPkePrivateKeyShare,
    pub(in crate::driver) args: &'a NodeRuntimeArgs,
    pub(in crate::driver) broadcast_pool_config: &'a BroadcastPoolConfig,
    pub(in crate::driver) runtime_capabilities: AcsRuntimeCapabilities,
    pub(in crate::driver) byzantine_node_config: ByzantineNodeConfig,
}

pub(in crate::driver) struct DriverNodeResult {
    pub(in crate::driver) round_build_latencies: Vec<f64>,
    pub(in crate::driver) acs_latencies: Vec<f64>,
    pub(in crate::driver) tpke_stage_latencies: Vec<f64>,
    pub(in crate::driver) round_latencies: Vec<f64>,
    pub(in crate::driver) round_wall_latencies: Vec<f64>,
    pub(in crate::driver) acs_pull_latencies: Vec<f64>,
    pub(in crate::driver) tpke_partial_open_latencies: Vec<f64>,
    pub(in crate::driver) tpke_combine_latencies: Vec<f64>,
    pub(in crate::driver) round_proposed_counts: Vec<usize>,
    pub(in crate::driver) round_delivered_counts: Vec<usize>,
    pub(in crate::driver) origin_tx_latencies_by_round: Vec<Vec<f64>>,
    pub(in crate::driver) acs_pull_calls: Vec<usize>,
    pub(in crate::driver) acs_empty_pull_calls: Vec<usize>,
    pub(in crate::driver) acs_inbound_wire_batches: Vec<usize>,
    pub(in crate::driver) acs_inbound_wire_items: Vec<usize>,
    pub(in crate::driver) acs_outbound_events: Vec<usize>,
    pub(in crate::driver) tpke_combine_calls: Vec<usize>,
    pub(in crate::driver) stale_acs_frames_dropped: Vec<usize>,
    pub(in crate::driver) fetch_requests_sent: Vec<usize>,
    pub(in crate::driver) fetch_responses_served: Vec<usize>,
    pub(in crate::driver) fetch_responses_received: Vec<usize>,
    pub(in crate::driver) fetched_reference_count: Vec<usize>,
    pub(in crate::driver) byzantine_invalid_fetch_responses_sent: Vec<usize>,
    pub(in crate::driver) byzantine_fetch_requests_ignored: Vec<usize>,
    pub(in crate::driver) byzantine_share_broadcast_suppressed: Vec<usize>,
    pub(in crate::driver) byzantine_empty_proposal_used: Vec<bool>,
    pub(in crate::driver) byzantine_behavior: &'static str,
    pub(in crate::driver) chain_digest: String,
    pub(in crate::driver) per_round_selected_pids: Vec<Vec<usize>>,
    pub(in crate::driver) per_round_block_digests: Vec<String>,
    pub(in crate::driver) per_round_block_sizes: Vec<usize>,
    pub(in crate::driver) per_round_chain_digests: Vec<String>,
    pub(in crate::driver) round_details: Vec<DriverNodeRoundTelemetry>,
    pub(in crate::driver) rust_broadcast_mempool_size: usize,
}

// ─── DriverRunAccumulator ─────────────────────────────────────────────────

use super::super::encryption::digest::{GENESIS_CHAIN_DIGEST, compute_chain_digest, sha256_hex};
use honey_wire::codec::hex_encode;

pub(super) struct DriverRunAccumulator {
    result: DriverNodeResult,
    chain_digest: [u8; 32],
}

impl DriverRunAccumulator {
    pub(super) fn new(rounds: usize, byzantine_node_config: ByzantineNodeConfig) -> Self {
        Self {
            result: DriverNodeResult {
                round_build_latencies: Vec::with_capacity(rounds),
                acs_latencies: Vec::with_capacity(rounds),
                tpke_stage_latencies: Vec::with_capacity(rounds),
                round_latencies: Vec::with_capacity(rounds),
                round_wall_latencies: Vec::with_capacity(rounds),
                acs_pull_latencies: Vec::with_capacity(rounds),
                tpke_partial_open_latencies: Vec::with_capacity(rounds),
                tpke_combine_latencies: Vec::with_capacity(rounds),
                round_proposed_counts: Vec::with_capacity(rounds),
                round_delivered_counts: Vec::with_capacity(rounds),
                origin_tx_latencies_by_round: Vec::with_capacity(rounds),
                acs_pull_calls: Vec::with_capacity(rounds),
                acs_empty_pull_calls: Vec::with_capacity(rounds),
                acs_inbound_wire_batches: Vec::with_capacity(rounds),
                acs_inbound_wire_items: Vec::with_capacity(rounds),
                acs_outbound_events: Vec::with_capacity(rounds),
                tpke_combine_calls: Vec::with_capacity(rounds),
                stale_acs_frames_dropped: Vec::with_capacity(rounds),
                fetch_requests_sent: Vec::with_capacity(rounds),
                fetch_responses_served: Vec::with_capacity(rounds),
                fetch_responses_received: Vec::with_capacity(rounds),
                fetched_reference_count: Vec::with_capacity(rounds),
                byzantine_invalid_fetch_responses_sent: Vec::with_capacity(rounds),
                byzantine_fetch_requests_ignored: Vec::with_capacity(rounds),
                byzantine_share_broadcast_suppressed: Vec::with_capacity(rounds),
                byzantine_empty_proposal_used: Vec::with_capacity(rounds),
                byzantine_behavior: byzantine_node_config.behavior_label(),
                chain_digest: String::new(),
                per_round_selected_pids: Vec::with_capacity(rounds),
                per_round_block_digests: Vec::with_capacity(rounds),
                per_round_block_sizes: Vec::with_capacity(rounds),
                per_round_chain_digests: Vec::with_capacity(rounds),
                round_details: Vec::with_capacity(rounds),
                rust_broadcast_mempool_size: 0,
            },
            chain_digest: GENESIS_CHAIN_DIGEST,
        }
    }

    pub(super) fn push_round(
        &mut self,
        round_id: usize,
        local_pid: usize,
        batch_size: usize,
        round_outcome: DriverRoundOutcome,
    ) {
        let metrics = round_outcome.metrics.clone();

        self.result
            .round_build_latencies
            .push(round_outcome.build_seconds);
        self.result.acs_latencies.push(round_outcome.acs_seconds);
        self.result
            .tpke_stage_latencies
            .push(round_outcome.tpke_seconds);
        self.result
            .round_latencies
            .push(round_outcome.protocol_seconds);
        self.result
            .round_wall_latencies
            .push(round_outcome.wall_seconds);
        self.result
            .acs_pull_latencies
            .push(metrics.acs_pull_seconds);
        self.result
            .tpke_partial_open_latencies
            .push(metrics.tpke_partial_open_seconds);
        self.result
            .tpke_combine_latencies
            .push(metrics.tpke_combine_seconds);
        self.result.round_proposed_counts.push(batch_size);
        self.result
            .round_delivered_counts
            .push(round_outcome.delivered_count);
        self.result.acs_pull_calls.push(metrics.acs_pull_calls);
        self.result
            .acs_empty_pull_calls
            .push(metrics.acs_empty_pull_calls);
        self.result
            .acs_inbound_wire_batches
            .push(metrics.acs_inbound_wire_batches);
        self.result
            .acs_inbound_wire_items
            .push(metrics.acs_inbound_wire_items);
        self.result
            .acs_outbound_events
            .push(metrics.acs_outbound_events);
        self.result
            .tpke_combine_calls
            .push(metrics.tpke_combine_calls);
        self.result
            .stale_acs_frames_dropped
            .push(metrics.stale_acs_frames_dropped);
        self.result
            .fetch_requests_sent
            .push(metrics.fetch_requests_sent);
        self.result
            .fetch_responses_served
            .push(metrics.fetch_responses_served);
        self.result
            .fetch_responses_received
            .push(metrics.fetch_responses_received);
        self.result
            .fetched_reference_count
            .push(metrics.fetched_reference_count);
        self.result
            .byzantine_invalid_fetch_responses_sent
            .push(metrics.byzantine_invalid_fetch_responses_sent);
        self.result
            .byzantine_fetch_requests_ignored
            .push(metrics.byzantine_fetch_requests_ignored);
        self.result
            .byzantine_share_broadcast_suppressed
            .push(metrics.byzantine_share_broadcast_suppressed);
        self.result
            .byzantine_empty_proposal_used
            .push(metrics.byzantine_empty_proposal_used);

        self.result
            .per_round_selected_pids
            .push(round_outcome.selected_pids.clone());
        let block_digest = sha256_hex(&round_outcome.block_payload);
        let block_size = round_outcome.block_payload.len();
        self.result
            .per_round_block_digests
            .push(block_digest.clone());
        self.result.per_round_block_sizes.push(block_size);
        self.chain_digest =
            compute_chain_digest(&self.chain_digest, round_id, &round_outcome.block_payload);
        let chain_digest_hex = hex_encode(&self.chain_digest);
        self.result
            .per_round_chain_digests
            .push(chain_digest_hex.clone());
        self.result.origin_tx_latencies_by_round.push(
            if round_outcome.selected_pids.contains(&local_pid) {
                vec![round_outcome.wall_seconds; batch_size]
            } else {
                Vec::new()
            },
        );
        self.result.round_details.push(DriverNodeRoundTelemetry {
            selected_proposal_ids: round_outcome.selected_proposal_ids,
            selected_pids: round_outcome.selected_pids,
            block_digest,
            block_size,
            chain_digest: chain_digest_hex,
            build_seconds: round_outcome.build_seconds,
            acs_seconds: round_outcome.acs_seconds,
            tpke_seconds: round_outcome.tpke_seconds,
            protocol_seconds: round_outcome.protocol_seconds,
            wall_seconds: round_outcome.wall_seconds,
            delivered_count: round_outcome.delivered_count,
            reused_reference_count: round_outcome.reused_reference_count,
            tpke_partial_open_seconds: metrics.tpke_partial_open_seconds,
            tpke_combine_seconds: metrics.tpke_combine_seconds,
            acs_outbound_events: metrics.acs_outbound_events,
            tpke_combine_calls: metrics.tpke_combine_calls,
            fetch_requests_sent: metrics.fetch_requests_sent,
            fetch_responses_served: metrics.fetch_responses_served,
            fetch_responses_received: metrics.fetch_responses_received,
            fetched_reference_count: metrics.fetched_reference_count,
            byzantine_invalid_fetch_responses_sent: metrics.byzantine_invalid_fetch_responses_sent,
            byzantine_fetch_requests_ignored: metrics.byzantine_fetch_requests_ignored,
            byzantine_share_broadcast_suppressed: metrics.byzantine_share_broadcast_suppressed,
            byzantine_empty_proposal_used: metrics.byzantine_empty_proposal_used,
            driver_phase_stats: metrics.driver_stats,
        });
    }

    pub(super) fn finish(mut self, rust_broadcast_mempool_size: usize) -> DriverNodeResult {
        self.result.chain_digest = hex_encode(&self.chain_digest);
        self.result.rust_broadcast_mempool_size = rust_broadcast_mempool_size;
        self.result
    }
}
