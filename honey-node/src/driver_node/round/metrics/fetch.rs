use super::sink::MetricsSink;
use super::snapshot::RoundMetricsSnapshot;

pub(in crate::driver_node) struct FetchMetrics<'a> {
    snapshot: &'a mut RoundMetricsSnapshot,
}

impl<'a> FetchMetrics<'a> {
    pub(super) fn new(snapshot: &'a mut RoundMetricsSnapshot) -> Self {
        Self { snapshot }
    }

    pub(in crate::driver_node) fn request_sent(&mut self, sent: bool) {
        if !sent {
            return;
        }
        self.snapshot.fetch_requests_sent += 1;
        MetricsSink::counter("honey_node.fetch.requests_sent", 1);
    }

    pub(in crate::driver_node) fn response_served(&mut self) {
        self.snapshot.fetch_responses_served += 1;
        MetricsSink::counter("honey_node.fetch.responses_served", 1);
    }

    pub(in crate::driver_node) fn response_received(&mut self) {
        self.snapshot.fetch_responses_received += 1;
        MetricsSink::counter("honey_node.fetch.responses_received", 1);
    }

    pub(in crate::driver_node) fn reference_inserted(&mut self, inserted: bool) {
        if !inserted {
            return;
        }
        self.snapshot.fetched_reference_count += 1;
        MetricsSink::counter("honey_node.fetch.references_inserted", 1);
    }
}
