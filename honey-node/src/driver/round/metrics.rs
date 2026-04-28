pub(crate) use honey_wire::phase_stats::{
    DriverHostPhaseStats, DriverPhaseStats, driver_phase_stats_json,
};

// ─── Snapshot ─────────────────────────────────────────────────────────────

#[derive(Clone)]
pub(in crate::driver) struct RoundMetricsSnapshot {
    pub(in crate::driver) acs_pull_seconds: f64,
    pub(in crate::driver) tpke_partial_open_seconds: f64,
    pub(in crate::driver) tpke_combine_seconds: f64,
    pub(in crate::driver) acs_pull_calls: usize,
    pub(in crate::driver) acs_empty_pull_calls: usize,
    pub(in crate::driver) acs_inbound_wire_batches: usize,
    pub(in crate::driver) acs_inbound_wire_items: usize,
    pub(in crate::driver) acs_outbound_events: usize,
    pub(in crate::driver) tpke_combine_calls: usize,
    pub(in crate::driver) stale_acs_frames_dropped: usize,
    pub(in crate::driver) fetch_requests_sent: usize,
    pub(in crate::driver) fetch_responses_served: usize,
    pub(in crate::driver) fetch_responses_received: usize,
    pub(in crate::driver) fetched_reference_count: usize,
    pub(in crate::driver) byzantine_invalid_fetch_responses_sent: usize,
    pub(in crate::driver) byzantine_fetch_requests_ignored: usize,
    pub(in crate::driver) byzantine_share_broadcast_suppressed: usize,
    pub(in crate::driver) byzantine_empty_proposal_used: bool,
    pub(in crate::driver) driver_stats: DriverPhaseStats,
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

// ─── RoundLoop metrics ────────────────────────────────────────────────────

pub(in crate::driver) struct RoundLoopMetrics<'a> {
    snapshot: &'a mut RoundMetricsSnapshot,
}

impl<'a> RoundLoopMetrics<'a> {
    pub(super) fn new(snapshot: &'a mut RoundMetricsSnapshot) -> Self {
        Self { snapshot }
    }

    pub(in crate::driver) fn sweep(&mut self, pending_deliveries: usize) {
        self.snapshot.driver_stats.sweep_count += 1;
        self.snapshot.driver_stats.total_pending_deliveries += pending_deliveries;
        self.snapshot.driver_stats.max_pending_deliveries = self
            .snapshot
            .driver_stats
            .max_pending_deliveries
            .max(pending_deliveries);
    }

    pub(in crate::driver) fn active_sweep(&mut self) {
        self.snapshot.driver_stats.active_sweeps += 1;
    }

    pub(in crate::driver) fn idle_backoff(&mut self) {
        self.snapshot.driver_stats.idle_sweeps += 1;
        self.snapshot.driver_stats.idle_backoff_count += 1;
    }

    pub(in crate::driver) fn transport_drain(&mut self, _frame_count: usize) {}
}

// ─── ACS metrics ──────────────────────────────────────────────────────────

pub(in crate::driver) struct AcsMetrics<'a> {
    snapshot: &'a mut RoundMetricsSnapshot,
}

impl<'a> AcsMetrics<'a> {
    pub(super) fn new(snapshot: &'a mut RoundMetricsSnapshot) -> Self {
        Self { snapshot }
    }

    pub(in crate::driver) fn push(&mut self, pid: usize, batch_len: usize, seconds: f64) {
        self.snapshot.acs_inbound_wire_batches += 1;
        self.snapshot.acs_inbound_wire_items += batch_len;
        if batch_len != 0 {
            let host = &mut self.snapshot.driver_stats.host_stats[pid];
            host.push_calls += 1;
            host.push_items += batch_len;
            host.max_push_batch = host.max_push_batch.max(batch_len);
            host.push_seconds += seconds;
            self.snapshot.driver_stats.total_pushed_items += batch_len;
            self.snapshot.driver_stats.total_push_seconds += seconds;
        }
    }

    pub(in crate::driver) fn pull(
        &mut self,
        pid: usize,
        event_count: usize,
        seconds: f64,
        limit: usize,
    ) {
        self.snapshot.acs_pull_seconds += seconds;
        self.snapshot.acs_pull_calls += 1;
        self.snapshot.acs_outbound_events += event_count;
        if event_count == 0 {
            self.snapshot.acs_empty_pull_calls += 1;
        }

        let host = &mut self.snapshot.driver_stats.host_stats[pid];
        host.pull_calls += 1;
        host.pull_seconds += seconds;
        host.pulled_events += event_count;
        host.max_pull_batch = host.max_pull_batch.max(event_count);
        if event_count == 0 {
            host.empty_pull_calls += 1;
        }
        if event_count >= limit {
            host.pull_limit_hits += 1;
            self.snapshot.driver_stats.pull_limit_hits += 1;
        }
        self.snapshot.driver_stats.total_pulled_events += event_count;
        self.snapshot.driver_stats.max_pull_batch =
            self.snapshot.driver_stats.max_pull_batch.max(event_count);
        self.snapshot.driver_stats.total_pull_seconds += seconds;
    }

    pub(in crate::driver) fn send(&mut self, payload_len: usize) {
        self.snapshot.driver_stats.send_events += 1;
        self.snapshot.driver_stats.send_payload_bytes += payload_len;
    }

    pub(in crate::driver) fn broadcast(&mut self, sent: usize, payload_len: usize) {
        self.snapshot.driver_stats.send_events += sent;
        self.snapshot.driver_stats.send_payload_bytes += payload_len * sent;
    }

    pub(in crate::driver) fn proposal_available(&mut self, payload_len: usize, proof_len: usize) {
        self.snapshot.driver_stats.proposal_available_events += 1;
        self.snapshot.driver_stats.proposal_available_payload_bytes += payload_len;
        self.snapshot.driver_stats.proposal_available_proof_bytes += proof_len;
    }

    pub(in crate::driver) fn decision(&mut self) {
        self.snapshot.driver_stats.decision_events += 1;
    }

    pub(in crate::driver) fn failure(&mut self) {
        self.snapshot.driver_stats.failure_events += 1;
    }

    pub(in crate::driver) fn stale_frames(&mut self, count: usize) {
        self.snapshot.stale_acs_frames_dropped += count;
    }
}

// ─── TPKE metrics ─────────────────────────────────────────────────────────

pub(in crate::driver) struct TpkeMetrics<'a> {
    snapshot: &'a mut RoundMetricsSnapshot,
}

impl<'a> TpkeMetrics<'a> {
    pub(super) fn new(snapshot: &'a mut RoundMetricsSnapshot) -> Self {
        Self { snapshot }
    }

    pub(in crate::driver) fn partial_open(&mut self, seconds: f64) {
        self.snapshot.tpke_partial_open_seconds += seconds;
    }

    pub(in crate::driver) fn combine(&mut self, seconds: f64) {
        self.snapshot.tpke_combine_seconds += seconds;
        self.snapshot.tpke_combine_calls += 1;
    }
}

// ─── Fetch metrics ────────────────────────────────────────────────────────

pub(in crate::driver) struct FetchMetrics<'a> {
    snapshot: &'a mut RoundMetricsSnapshot,
}

impl<'a> FetchMetrics<'a> {
    pub(super) fn new(snapshot: &'a mut RoundMetricsSnapshot) -> Self {
        Self { snapshot }
    }

    pub(in crate::driver) fn request_sent(&mut self, sent: bool) {
        if !sent {
            return;
        }
        self.snapshot.fetch_requests_sent += 1;
    }

    pub(in crate::driver) fn response_served(&mut self) {
        self.snapshot.fetch_responses_served += 1;
    }

    pub(in crate::driver) fn response_received(&mut self) {
        self.snapshot.fetch_responses_received += 1;
    }

    pub(in crate::driver) fn reference_inserted(&mut self, inserted: bool) {
        if !inserted {
            return;
        }
        self.snapshot.fetched_reference_count += 1;
    }
}

// ─── Byzantine metrics ────────────────────────────────────────────────────

pub(in crate::driver) struct ByzantineMetrics<'a> {
    snapshot: &'a mut RoundMetricsSnapshot,
}

impl<'a> ByzantineMetrics<'a> {
    pub(super) fn new(snapshot: &'a mut RoundMetricsSnapshot) -> Self {
        Self { snapshot }
    }

    pub(in crate::driver) fn invalid_fetch_response(&mut self) {
        self.snapshot.byzantine_invalid_fetch_responses_sent += 1;
    }

    pub(in crate::driver) fn fetch_ignored(&mut self) {
        self.snapshot.byzantine_fetch_requests_ignored += 1;
    }

    pub(in crate::driver) fn share_broadcast_suppressed(&mut self) {
        self.snapshot.byzantine_share_broadcast_suppressed = 1;
    }

    pub(in crate::driver) fn empty_proposal(&mut self) {
        self.snapshot.byzantine_empty_proposal_used = true;
    }
}

// ─── RoundMetricsRecorder ─────────────────────────────────────────────────

pub(in crate::driver) struct RoundMetricsRecorder {
    snapshot: RoundMetricsSnapshot,
}

impl RoundMetricsRecorder {
    pub(in crate::driver) fn new(nodes: usize) -> Self {
        Self {
            snapshot: RoundMetricsSnapshot::new(nodes),
        }
    }

    pub(in crate::driver) fn round(&mut self) -> RoundLoopMetrics<'_> {
        RoundLoopMetrics::new(&mut self.snapshot)
    }

    pub(in crate::driver) fn acs(&mut self) -> AcsMetrics<'_> {
        AcsMetrics::new(&mut self.snapshot)
    }

    pub(in crate::driver) fn fetch(&mut self) -> FetchMetrics<'_> {
        FetchMetrics::new(&mut self.snapshot)
    }

    pub(in crate::driver) fn byzantine(&mut self) -> ByzantineMetrics<'_> {
        ByzantineMetrics::new(&mut self.snapshot)
    }

    pub(in crate::driver) fn tpke(&mut self) -> TpkeMetrics<'_> {
        TpkeMetrics::new(&mut self.snapshot)
    }

    pub(in crate::driver) fn finish(self) -> RoundMetricsSnapshot {
        self.snapshot
    }
}
