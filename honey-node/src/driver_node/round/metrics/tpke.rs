use super::sink::MetricsSink;
use super::snapshot::RoundMetricsSnapshot;

pub(in crate::driver_node) struct TpkeMetrics<'a> {
    snapshot: &'a mut RoundMetricsSnapshot,
}

impl<'a> TpkeMetrics<'a> {
    pub(super) fn new(snapshot: &'a mut RoundMetricsSnapshot) -> Self {
        Self { snapshot }
    }

    pub(in crate::driver_node) fn partial_open(&mut self, seconds: f64) {
        self.snapshot.tpke_partial_open_seconds += seconds;
        MetricsSink::histogram("honey_node.tpke.partial_open_seconds", seconds);
    }

    pub(in crate::driver_node) fn combine(&mut self, seconds: f64) {
        self.snapshot.tpke_combine_seconds += seconds;
        self.snapshot.tpke_combine_calls += 1;
        MetricsSink::counter("honey_node.tpke.combine_calls", 1);
        MetricsSink::histogram("honey_node.tpke.combine_seconds", seconds);
    }
}
