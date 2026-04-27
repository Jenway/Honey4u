mod acs;
mod byzantine;
mod fetch;
mod round;
mod sink;
mod snapshot;
mod tpke;

pub(in crate::driver_node) use snapshot::RoundMetricsSnapshot;

use self::acs::AcsMetrics;
use self::byzantine::ByzantineMetrics;
use self::fetch::FetchMetrics;
use self::round::RoundLoopMetrics;
use self::tpke::TpkeMetrics;

pub(in crate::driver_node) struct RoundMetricsRecorder {
    snapshot: RoundMetricsSnapshot,
}

impl RoundMetricsRecorder {
    pub(in crate::driver_node) fn new(nodes: usize) -> Self {
        Self {
            snapshot: RoundMetricsSnapshot::new(nodes),
        }
    }

    pub(in crate::driver_node) fn round(&mut self) -> RoundLoopMetrics<'_> {
        RoundLoopMetrics::new(&mut self.snapshot)
    }

    pub(in crate::driver_node) fn acs(&mut self) -> AcsMetrics<'_> {
        AcsMetrics::new(&mut self.snapshot)
    }

    pub(in crate::driver_node) fn fetch(&mut self) -> FetchMetrics<'_> {
        FetchMetrics::new(&mut self.snapshot)
    }

    pub(in crate::driver_node) fn byzantine(&mut self) -> ByzantineMetrics<'_> {
        ByzantineMetrics::new(&mut self.snapshot)
    }

    pub(in crate::driver_node) fn tpke(&mut self) -> TpkeMetrics<'_> {
        TpkeMetrics::new(&mut self.snapshot)
    }

    pub(in crate::driver_node) fn finish(self) -> RoundMetricsSnapshot {
        self.snapshot
    }
}
