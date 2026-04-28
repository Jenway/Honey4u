use std::io;
use std::thread;

#[derive(Clone, Copy, Debug, Default)]
pub struct TransportStats {
    pub sent_frames: usize,
    pub recv_frames: usize,
    pub connect_retries: usize,
    pub send_retries: usize,
    pub delayed_frames: usize,
    pub total_injected_delay_ms: u64,
    pub network_fault_seed: u64,
    pub configured_fixed_delay_ms: u64,
    pub configured_jitter_ms: u64,
    pub configured_slow_honest_extra_delay_ms: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetworkFaultConfig {
    pub enabled: bool,
    pub seed: u64,
    pub fixed_delay_ms: u64,
    pub jitter_ms: u64,
    pub slow_honest_extra_delay_ms: u64,
}

impl NetworkFaultConfig {
    pub fn is_active(self) -> bool {
        self.enabled
            && (self.fixed_delay_ms > 0
                || self.jitter_ms > 0
                || self.slow_honest_extra_delay_ms > 0)
    }
}

pub trait TransportHandle: Send + Sync {
    fn send(&self, recipient: usize, payload: &[u8]) -> io::Result<()>;
    fn recv_batch(&self, max_items: usize) -> io::Result<Vec<Vec<u8>>>;
    fn pending_inbound(&self) -> usize;
    fn pending_outbound(&self) -> usize;
    fn stats(&self) -> TransportStats;
    fn register_wakeup_waiter(&self, t: thread::Thread);
    fn unregister_wakeup_waiter(&self);
}
