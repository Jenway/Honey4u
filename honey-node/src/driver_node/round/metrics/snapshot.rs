use super::super::super::telemetry::{DriverHostPhaseStats, DriverPhaseStats};

#[derive(Clone)]
pub(in crate::driver_node) struct RoundMetricsSnapshot {
    pub(in crate::driver_node) acs_pull_seconds: f64,
    pub(in crate::driver_node) tpke_partial_open_seconds: f64,
    pub(in crate::driver_node) tpke_combine_seconds: f64,
    pub(in crate::driver_node) acs_pull_calls: usize,
    pub(in crate::driver_node) acs_empty_pull_calls: usize,
    pub(in crate::driver_node) acs_inbound_wire_batches: usize,
    pub(in crate::driver_node) acs_inbound_wire_items: usize,
    pub(in crate::driver_node) acs_outbound_events: usize,
    pub(in crate::driver_node) tpke_combine_calls: usize,
    pub(in crate::driver_node) stale_acs_frames_dropped: usize,
    pub(in crate::driver_node) fetch_requests_sent: usize,
    pub(in crate::driver_node) fetch_responses_served: usize,
    pub(in crate::driver_node) fetch_responses_received: usize,
    pub(in crate::driver_node) fetched_reference_count: usize,
    pub(in crate::driver_node) byzantine_invalid_fetch_responses_sent: usize,
    pub(in crate::driver_node) byzantine_fetch_requests_ignored: usize,
    pub(in crate::driver_node) byzantine_share_broadcast_suppressed: usize,
    pub(in crate::driver_node) byzantine_empty_proposal_used: bool,
    pub(in crate::driver_node) driver_stats: DriverPhaseStats,
}

impl RoundMetricsSnapshot {
    pub(super) fn new(nodes: usize) -> Self {
        Self {
            acs_pull_seconds: 0.0,
            tpke_partial_open_seconds: 0.0,
            tpke_combine_seconds: 0.0,
            acs_pull_calls: 0,
            acs_empty_pull_calls: 0,
            acs_inbound_wire_batches: 0,
            acs_inbound_wire_items: 0,
            acs_outbound_events: 0,
            tpke_combine_calls: 0,
            stale_acs_frames_dropped: 0,
            fetch_requests_sent: 0,
            fetch_responses_served: 0,
            fetch_responses_received: 0,
            fetched_reference_count: 0,
            byzantine_invalid_fetch_responses_sent: 0,
            byzantine_fetch_requests_ignored: 0,
            byzantine_share_broadcast_suppressed: 0,
            byzantine_empty_proposal_used: false,
            driver_stats: DriverPhaseStats {
                host_stats: (0..nodes)
                    .map(|pid| DriverHostPhaseStats {
                        pid,
                        ..DriverHostPhaseStats::default()
                    })
                    .collect(),
                ..DriverPhaseStats::default()
            },
        }
    }
}
