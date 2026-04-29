use crate::handle::{NetworkFaultConfig, TransportHandle, TransportStats};
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, unbounded};
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering as AtomicOrdering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
struct DelayRng {
    state: u64,
}

impl DelayRng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

#[derive(Debug)]
struct ScheduledOutbound {
    ready_at: Instant,
    sequence: u64,
    recipient: usize,
    payload: Vec<u8>,
}

impl PartialEq for ScheduledOutbound {
    fn eq(&self, other: &Self) -> bool {
        self.ready_at == other.ready_at && self.sequence == other.sequence
    }
}

impl Eq for ScheduledOutbound {}

impl PartialOrd for ScheduledOutbound {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScheduledOutbound {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .ready_at
            .cmp(&self.ready_at)
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}

struct SenderLoopCtx {
    stop: Arc<AtomicBool>,
    inner: Arc<dyn TransportHandle>,
    outbound_rx: Receiver<(usize, Vec<u8>)>,
    outbound_len: Arc<AtomicUsize>,
    delayed_frames: Arc<AtomicUsize>,
    injected_delay_ms_total: Arc<AtomicU64>,
    network_faults: NetworkFaultConfig,
    rng_seed: u64,
}

pub struct FaultInjectedTransport {
    inner: Arc<dyn TransportHandle>,
    stop: Arc<AtomicBool>,
    outbound_tx: Sender<(usize, Vec<u8>)>,
    outbound_len: Arc<AtomicUsize>,
    delayed_frames: Arc<AtomicUsize>,
    injected_delay_ms_total: Arc<AtomicU64>,
    sender_handle: Option<JoinHandle<()>>,
    network_faults: NetworkFaultConfig,
    rng_seed: u64,
}

impl FaultInjectedTransport {
    pub fn new(
        inner: Arc<dyn TransportHandle>,
        network_faults: NetworkFaultConfig,
        pid: usize,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let (outbound_tx, outbound_rx) = unbounded::<(usize, Vec<u8>)>();
        let outbound_len = Arc::new(AtomicUsize::new(0));
        let delayed_frames = Arc::new(AtomicUsize::new(0));
        let injected_delay_ms_total = Arc::new(AtomicU64::new(0));
        let rng_seed = network_faults.mixed_seed(pid);

        let sender_handle = thread::spawn({
            let sender_stop = Arc::clone(&stop);
            let sender_inner = Arc::clone(&inner);
            let sender_outbound_len = Arc::clone(&outbound_len);
            let sender_delayed_frames = Arc::clone(&delayed_frames);
            let sender_injected_delay_ms_total = Arc::clone(&injected_delay_ms_total);
            move || {
                sender_loop(SenderLoopCtx {
                    stop: sender_stop,
                    inner: sender_inner,
                    outbound_rx,
                    outbound_len: sender_outbound_len,
                    delayed_frames: sender_delayed_frames,
                    injected_delay_ms_total: sender_injected_delay_ms_total,
                    network_faults,
                    rng_seed,
                })
            }
        });

        Self {
            inner,
            stop,
            outbound_tx,
            outbound_len,
            delayed_frames,
            injected_delay_ms_total,
            sender_handle: Some(sender_handle),
            network_faults,
            rng_seed,
        }
    }
}

impl Drop for FaultInjectedTransport {
    fn drop(&mut self) {
        self.stop.store(true, AtomicOrdering::Relaxed);
        if let Some(handle) = self.sender_handle.take() {
            let _ = handle.join();
        }
    }
}

impl TransportHandle for FaultInjectedTransport {
    fn send(&self, recipient: usize, payload: &[u8]) -> io::Result<()> {
        self.outbound_len.fetch_add(1, AtomicOrdering::Relaxed);
        self.outbound_tx
            .send((recipient, payload.to_vec()))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "fault injector disconnected"))
    }

    fn recv_batch(&self, max_items: usize) -> io::Result<Vec<Vec<u8>>> {
        self.inner.recv_batch(max_items)
    }

    fn pending_inbound(&self) -> usize {
        self.inner.pending_inbound()
    }

    fn pending_outbound(&self) -> usize {
        self.outbound_len.load(AtomicOrdering::Relaxed) + self.inner.pending_outbound()
    }

    fn stats(&self) -> TransportStats {
        let inner = self.inner.stats();
        TransportStats {
            sent_frames: inner.sent_frames,
            recv_frames: inner.recv_frames,
            connect_retries: inner.connect_retries,
            send_retries: inner.send_retries,
            delayed_frames: inner.delayed_frames
                + self.delayed_frames.load(AtomicOrdering::Relaxed),
            total_injected_delay_ms: inner.total_injected_delay_ms
                + self.injected_delay_ms_total.load(AtomicOrdering::Relaxed),
            network_fault_seed: self.rng_seed,
            configured_fixed_delay_ms: self.network_faults.fixed_delay_ms,
            configured_jitter_ms: self.network_faults.jitter_ms,
            configured_slow_honest_extra_delay_ms: self.network_faults.slow_honest_extra_delay_ms,
        }
    }

    fn register_wakeup_waiter(&self, t: thread::Thread) {
        self.inner.register_wakeup_waiter(t);
    }

    fn unregister_wakeup_waiter(&self) {
        self.inner.unregister_wakeup_waiter();
    }
}

fn sender_loop(ctx: SenderLoopCtx) {
    let mut rng = DelayRng::new(ctx.rng_seed);
    let mut pending = BinaryHeap::new();
    let mut sequence = 0u64;
    loop {
        while let Ok((recipient, payload)) = ctx.outbound_rx.try_recv() {
            ctx.outbound_len.fetch_sub(1, AtomicOrdering::Relaxed);
            let injected_delay_ms = compute_injected_delay_ms(ctx.network_faults, &mut rng);
            if injected_delay_ms > 0 {
                ctx.delayed_frames.fetch_add(1, AtomicOrdering::Relaxed);
                ctx.injected_delay_ms_total
                    .fetch_add(injected_delay_ms, AtomicOrdering::Relaxed);
            }
            pending.push(ScheduledOutbound {
                ready_at: Instant::now() + Duration::from_millis(injected_delay_ms),
                sequence,
                recipient,
                payload,
            });
            sequence = sequence.wrapping_add(1);
        }

        while pending
            .peek()
            .is_some_and(|item| item.ready_at <= Instant::now())
        {
            let ScheduledOutbound {
                recipient, payload, ..
            } = pending.pop().expect("pending heap peeked as non-empty");
            if ctx.stop.load(AtomicOrdering::Relaxed) {
                return;
            }
            let _ = ctx.inner.send(recipient, &payload);
        }

        if ctx.stop.load(AtomicOrdering::Relaxed) {
            break;
        }

        let wait = pending
            .peek()
            .map(|item| item.ready_at.saturating_duration_since(Instant::now()))
            .unwrap_or(Duration::from_millis(100))
            .min(Duration::from_millis(100));
        let (recipient, payload) = match ctx.outbound_rx.recv_timeout(wait) {
            Ok(item) => item,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        ctx.outbound_len.fetch_sub(1, AtomicOrdering::Relaxed);
        let injected_delay_ms = compute_injected_delay_ms(ctx.network_faults, &mut rng);
        if injected_delay_ms > 0 {
            ctx.delayed_frames.fetch_add(1, AtomicOrdering::Relaxed);
            ctx.injected_delay_ms_total
                .fetch_add(injected_delay_ms, AtomicOrdering::Relaxed);
        }
        pending.push(ScheduledOutbound {
            ready_at: Instant::now() + Duration::from_millis(injected_delay_ms),
            sequence,
            recipient,
            payload,
        });
        sequence = sequence.wrapping_add(1);
    }
}

fn compute_injected_delay_ms(config: NetworkFaultConfig, rng: &mut DelayRng) -> u64 {
    if !config.is_active() {
        return 0;
    }
    let jitter = if config.jitter_ms == 0 {
        0
    } else {
        rng.next_u64() % (config.jitter_ms + 1)
    };
    config
        .fixed_delay_ms
        .saturating_add(config.slow_honest_extra_delay_ms)
        .saturating_add(jitter)
}

#[cfg(test)]
mod tests {
    use super::{DelayRng, FaultInjectedTransport, compute_injected_delay_ms};
    use crate::handle::{NetworkFaultConfig, TransportHandle, TransportStats};
    use std::io;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    #[derive(Default)]
    struct ProbeTransport {
        sent_at: Mutex<Vec<Instant>>,
    }

    impl TransportHandle for ProbeTransport {
        fn send(&self, _recipient: usize, _payload: &[u8]) -> io::Result<()> {
            self.sent_at
                .lock()
                .expect("probe transport lock should not poison")
                .push(Instant::now());
            Ok(())
        }

        fn recv_batch(&self, _max_items: usize) -> io::Result<Vec<Vec<u8>>> {
            Ok(Vec::new())
        }

        fn pending_inbound(&self) -> usize {
            0
        }

        fn pending_outbound(&self) -> usize {
            0
        }

        fn stats(&self) -> TransportStats {
            TransportStats::default()
        }

        fn register_wakeup_waiter(&self, _t: thread::Thread) {}

        fn unregister_wakeup_waiter(&self) {}
    }

    #[test]
    fn network_fault_delay_combines_fixed_slow_and_jitter() {
        let config = NetworkFaultConfig {
            enabled: true,
            seed: 7,
            fixed_delay_ms: 10,
            jitter_ms: 5,
            slow_honest_extra_delay_ms: 20,
        };
        let mut rng = DelayRng::new(config.mixed_seed(3));

        let delay = compute_injected_delay_ms(config, &mut rng);

        assert!((30..=35).contains(&delay));
    }

    #[test]
    fn network_fault_delay_is_zero_when_disabled() {
        let config = NetworkFaultConfig {
            enabled: false,
            seed: 7,
            fixed_delay_ms: 10,
            jitter_ms: 5,
            slow_honest_extra_delay_ms: 20,
        };
        let mut rng = DelayRng::new(config.mixed_seed(1));

        let delay = compute_injected_delay_ms(config, &mut rng);

        assert_eq!(delay, 0);
    }

    #[test]
    fn fault_injection_does_not_serially_throttle_burst() {
        let probe = Arc::new(ProbeTransport::default());
        let inner: Arc<dyn TransportHandle> = probe.clone();
        let wrapped = FaultInjectedTransport::new(
            inner,
            NetworkFaultConfig {
                enabled: true,
                seed: 7,
                fixed_delay_ms: 0,
                jitter_ms: 0,
                slow_honest_extra_delay_ms: 20,
            },
            0,
        );

        for _ in 0..8 {
            wrapped
                .send(1, b"burst-frame")
                .expect("burst frame should enqueue successfully");
        }

        let start = Instant::now();
        let deadline = start + Duration::from_millis(300);
        while Instant::now() < deadline {
            let delivered = probe
                .sent_at
                .lock()
                .expect("probe transport lock should not poison")
                .len();
            if delivered >= 8 {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }

        let sent_count = probe
            .sent_at
            .lock()
            .expect("probe transport lock should not poison")
            .len();
        assert_eq!(
            sent_count, 8,
            "inner transport should receive the full burst"
        );
        assert!(
            start.elapsed() < Duration::from_millis(120),
            "burst delay should not accumulate per-frame sleep"
        );
    }
}
