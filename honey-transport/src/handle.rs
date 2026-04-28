use std::io;
use std::thread;

const RNG_MIX_CONST: u64 = 0x9E37_79B9_7F4A_7C15;
const RNG_FALLBACK_SEED: u64 = 0xA076_1D64_78BD_642F;

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

    pub fn mixed_seed(self, pid: usize) -> u64 {
        let mixed = self.seed ^ ((pid as u64).wrapping_add(1).wrapping_mul(RNG_MIX_CONST));
        if mixed == 0 { RNG_FALLBACK_SEED } else { mixed }
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
