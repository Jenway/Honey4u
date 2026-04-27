use super::sink::MetricsSink;
use super::snapshot::RoundMetricsSnapshot;

pub(in crate::driver_node) struct ByzantineMetrics<'a> {
    snapshot: &'a mut RoundMetricsSnapshot,
}

impl<'a> ByzantineMetrics<'a> {
    pub(super) fn new(snapshot: &'a mut RoundMetricsSnapshot) -> Self {
        Self { snapshot }
    }

    pub(in crate::driver_node) fn invalid_fetch_response(&mut self) {
        self.snapshot.byzantine_invalid_fetch_responses_sent += 1;
        MetricsSink::counter("honey_node.byzantine.invalid_fetch_responses_sent", 1);
    }

    pub(in crate::driver_node) fn fetch_ignored(&mut self) {
        self.snapshot.byzantine_fetch_requests_ignored += 1;
        MetricsSink::counter("honey_node.byzantine.fetch_requests_ignored", 1);
    }

    pub(in crate::driver_node) fn share_broadcast_suppressed(&mut self) {
        self.snapshot.byzantine_share_broadcast_suppressed = 1;
        MetricsSink::counter("honey_node.byzantine.share_broadcast_suppressed", 1);
    }

    pub(in crate::driver_node) fn empty_proposal(&mut self) {
        self.snapshot.byzantine_empty_proposal_used = true;
        MetricsSink::counter("honey_node.byzantine.empty_proposal_used", 1);
    }
}
