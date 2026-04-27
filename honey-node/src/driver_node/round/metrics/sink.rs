pub(super) struct MetricsSink;

impl MetricsSink {
    pub(super) fn counter(name: &'static str, value: usize) {
        if value != 0 {
            metrics::counter!(name).increment(value as u64);
        }
    }

    pub(super) fn histogram(name: &'static str, value: f64) {
        metrics::histogram!(name).record(value);
    }

    pub(super) fn gauge(name: &'static str, value: usize) {
        metrics::gauge!(name).set(value as f64);
    }
}
