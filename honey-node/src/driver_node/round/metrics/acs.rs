use super::sink::MetricsSink;
use super::snapshot::RoundMetricsSnapshot;

pub(in crate::driver_node) struct AcsMetrics<'a> {
    snapshot: &'a mut RoundMetricsSnapshot,
}

impl<'a> AcsMetrics<'a> {
    pub(super) fn new(snapshot: &'a mut RoundMetricsSnapshot) -> Self {
        Self { snapshot }
    }

    pub(in crate::driver_node) fn push(&mut self, pid: usize, batch_len: usize, seconds: f64) {
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
        MetricsSink::counter("honey_node.acs.inbound_wire_batches", 1);
        MetricsSink::counter("honey_node.acs.inbound_wire_items", batch_len);
        MetricsSink::histogram("honey_node.acs.push_seconds", seconds);
    }

    pub(in crate::driver_node) fn pull(
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

        MetricsSink::counter("honey_node.acs.pull_calls", 1);
        MetricsSink::counter(
            "honey_node.acs.empty_pull_calls",
            usize::from(event_count == 0),
        );
        MetricsSink::counter("honey_node.acs.outbound_events", event_count);
        MetricsSink::histogram("honey_node.acs.pull_seconds", seconds);
    }

    pub(in crate::driver_node) fn send(&mut self, payload_len: usize) {
        self.snapshot.driver_stats.send_events += 1;
        self.snapshot.driver_stats.send_payload_bytes += payload_len;
        MetricsSink::counter("honey_node.acs.send_events", 1);
        MetricsSink::counter("honey_node.acs.send_payload_bytes", payload_len);
    }

    pub(in crate::driver_node) fn broadcast(&mut self, sent: usize, payload_len: usize) {
        self.snapshot.driver_stats.send_events += sent;
        self.snapshot.driver_stats.send_payload_bytes += payload_len * sent;
        MetricsSink::counter("honey_node.acs.broadcast_recipients", sent);
        MetricsSink::counter("honey_node.acs.broadcast_payload_bytes", payload_len * sent);
    }

    pub(in crate::driver_node) fn proposal_available(
        &mut self,
        payload_len: usize,
        proof_len: usize,
    ) {
        self.snapshot.driver_stats.proposal_available_events += 1;
        self.snapshot.driver_stats.proposal_available_payload_bytes += payload_len;
        self.snapshot.driver_stats.proposal_available_proof_bytes += proof_len;
        MetricsSink::counter("honey_node.acs.proposal_available", 1);
        MetricsSink::counter("honey_node.acs.proposal_payload_bytes", payload_len);
        MetricsSink::counter("honey_node.acs.proposal_proof_bytes", proof_len);
    }

    pub(in crate::driver_node) fn decision(&mut self) {
        self.snapshot.driver_stats.decision_events += 1;
        MetricsSink::counter("honey_node.acs.decisions", 1);
    }

    pub(in crate::driver_node) fn failure(&mut self) {
        self.snapshot.driver_stats.failure_events += 1;
        MetricsSink::counter("honey_node.acs.failures", 1);
    }

    pub(in crate::driver_node) fn stale_frames(&mut self, count: usize) {
        self.snapshot.stale_acs_frames_dropped += count;
        MetricsSink::counter("honey_node.acs.stale_frames_dropped", count);
    }
}
