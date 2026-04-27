use super::sink::MetricsSink;
use super::snapshot::RoundMetricsSnapshot;

pub(in crate::driver_node) struct RoundLoopMetrics<'a> {
    snapshot: &'a mut RoundMetricsSnapshot,
}

impl<'a> RoundLoopMetrics<'a> {
    pub(super) fn new(snapshot: &'a mut RoundMetricsSnapshot) -> Self {
        Self { snapshot }
    }

    pub(in crate::driver_node) fn sweep(&mut self, pending_deliveries: usize) {
        self.snapshot.driver_stats.sweep_count += 1;
        self.snapshot.driver_stats.total_pending_deliveries += pending_deliveries;
        self.snapshot.driver_stats.max_pending_deliveries = self
            .snapshot
            .driver_stats
            .max_pending_deliveries
            .max(pending_deliveries);
        MetricsSink::counter("honey_node.round.sweeps", 1);
        MetricsSink::gauge("honey_node.round.pending_deliveries", pending_deliveries);
    }

    pub(in crate::driver_node) fn active_sweep(&mut self) {
        self.snapshot.driver_stats.active_sweeps += 1;
        MetricsSink::counter("honey_node.round.active_sweeps", 1);
    }

    pub(in crate::driver_node) fn idle_backoff(&mut self) {
        self.snapshot.driver_stats.idle_sweeps += 1;
        self.snapshot.driver_stats.idle_backoff_count += 1;
        MetricsSink::counter("honey_node.round.idle_backoffs", 1);
    }

    pub(in crate::driver_node) fn transport_drain(&mut self, frame_count: usize) {
        MetricsSink::counter("honey_node.transport.drained_frames", frame_count);
    }
}
