use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, TryRecvError, unbounded};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::transport::handle::{TransportHandle, WakeupCounter};

type ConnectionMap = Arc<Mutex<HashMap<usize, TcpStream>>>;

const RNG_MIX_CONST: u64 = 0x9E37_79B9_7F4A_7C15;
const RNG_FALLBACK_SEED: u64 = 0xA076_1D64_78BD_642F;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetworkFaultConfig {
    pub enabled: bool,
    pub seed: u64,
    pub fixed_delay_ms: u64,
    pub jitter_ms: u64,
    pub slow_honest_extra_delay_ms: u64,
}

impl NetworkFaultConfig {
    fn is_active(self) -> bool {
        self.enabled
            && (self.fixed_delay_ms > 0
                || self.jitter_ms > 0
                || self.slow_honest_extra_delay_ms > 0)
    }

    fn mixed_seed(self, pid: usize) -> u64 {
        let mixed = self.seed ^ ((pid as u64).wrapping_add(1).wrapping_mul(RNG_MIX_CONST));
        if mixed == 0 { RNG_FALLBACK_SEED } else { mixed }
    }
}

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

struct SenderLoopCtx {
    stop: Arc<AtomicBool>,
    addresses: Vec<(String, u16)>,
    connections: ConnectionMap,
    outbound_rx: Receiver<(usize, Vec<u8>)>,
    outbound_len: Arc<AtomicUsize>,
    sent_frames: Arc<AtomicUsize>,
    connect_retries: Arc<AtomicUsize>,
    send_retries: Arc<AtomicUsize>,
    delayed_frames: Arc<AtomicUsize>,
    injected_delay_ms_total: Arc<AtomicU64>,
    network_faults: NetworkFaultConfig,
    rng_seed: u64,
}

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

fn send_frame(stream: &mut TcpStream, payload: &[u8]) -> io::Result<()> {
    let size = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "payload too large"))?;
    stream.write_all(&size.to_be_bytes())?;
    stream.write_all(payload)
}

fn recv_frame(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    let size = u32::from_be_bytes(header) as usize;
    let mut payload = vec![0u8; size];
    stream.read_exact(&mut payload)?;
    Ok(payload)
}

fn set_stream_defaults(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_millis(200)))?;
    stream.set_write_timeout(Some(Duration::from_millis(200)))?;
    Ok(())
}

fn get_connection(
    recipient: usize,
    addresses: &[(String, u16)],
    connections: &ConnectionMap,
) -> io::Result<TcpStream> {
    {
        let guard = connections
            .lock()
            .map_err(|_| io::Error::other("failed to lock connections"))?;
        if let Some(stream) = guard.get(&recipient) {
            return stream.try_clone();
        }
    }

    let (host, port) = addresses
        .get(recipient)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "recipient out of range"))?;
    let stream = TcpStream::connect((host.as_str(), *port))?;
    set_stream_defaults(&stream)?;

    {
        let mut guard = connections
            .lock()
            .map_err(|_| io::Error::other("failed to lock connections"))?;
        guard.insert(recipient, stream.try_clone()?);
    }

    Ok(stream)
}

fn drop_connection(recipient: usize, connections: &ConnectionMap) {
    if let Ok(mut guard) = connections.lock() {
        guard.remove(&recipient);
    }
}

fn close_connections(connections: &ConnectionMap) {
    if let Ok(mut guard) = connections.lock() {
        for (_recipient, stream) in guard.drain() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

fn sender_loop(ctx: SenderLoopCtx) {
    let mut rng = DelayRng::new(ctx.rng_seed);
    while !ctx.stop.load(Ordering::Relaxed) {
        let (recipient, payload) = match ctx.outbound_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(item) => item,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        ctx.outbound_len.fetch_sub(1, Ordering::Relaxed);

        let injected_delay_ms = compute_injected_delay_ms(ctx.network_faults, &mut rng);
        if injected_delay_ms > 0 {
            ctx.delayed_frames.fetch_add(1, Ordering::Relaxed);
            ctx.injected_delay_ms_total
                .fetch_add(injected_delay_ms, Ordering::Relaxed);
            thread::sleep(Duration::from_millis(injected_delay_ms));
        }

        let mut failures = 0usize;
        while !ctx.stop.load(Ordering::Relaxed) {
            let mut stream = match get_connection(recipient, &ctx.addresses, &ctx.connections) {
                Ok(stream) => stream,
                Err(_) => {
                    failures += 1;
                    ctx.connect_retries.fetch_add(1, Ordering::Relaxed);
                    if failures >= 1000 {
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
            };

            match send_frame(&mut stream, &payload) {
                Ok(()) => {
                    ctx.sent_frames.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                Err(_) => {
                    failures += 1;
                    ctx.send_retries.fetch_add(1, Ordering::Relaxed);
                    drop_connection(recipient, &ctx.connections);
                    if failures >= 1000 {
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
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

pub struct LocalTcpTransport {
    stop: Arc<AtomicBool>,
    inbound_rx: Receiver<Vec<u8>>,
    inbound_len: Arc<AtomicUsize>,
    outbound_tx: Sender<(usize, Vec<u8>)>,
    outbound_len: Arc<AtomicUsize>,
    sent_frames: Arc<AtomicUsize>,
    recv_frames: Arc<AtomicUsize>,
    connect_retries: Arc<AtomicUsize>,
    send_retries: Arc<AtomicUsize>,
    delayed_frames: Arc<AtomicUsize>,
    injected_delay_ms_total: Arc<AtomicU64>,
    wakeup_counter: Arc<WakeupCounter>,
    connections: ConnectionMap,
    accept_handle: Option<JoinHandle<()>>,
    sender_handle: Option<JoinHandle<()>>,
    worker_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
    network_faults: NetworkFaultConfig,
    rng_seed: u64,
}

impl LocalTcpTransport {
    pub fn new(
        pid: usize,
        addresses: Vec<(String, u16)>,
        network_faults: NetworkFaultConfig,
    ) -> io::Result<Self> {
        if pid >= addresses.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pid out of range for addresses",
            ));
        }

        let (host, port) = addresses[pid].clone();
        let listener = TcpListener::bind((host.as_str(), port))?;
        listener.set_nonblocking(true)?;

        let stop = Arc::new(AtomicBool::new(false));
        let connections: ConnectionMap = Arc::new(Mutex::new(HashMap::new()));
        let (inbound_tx, inbound_rx) = unbounded::<Vec<u8>>();
        let inbound_len = Arc::new(AtomicUsize::new(0));
        let (outbound_tx, outbound_rx) = unbounded::<(usize, Vec<u8>)>();
        let outbound_len = Arc::new(AtomicUsize::new(0));
        let sent_frames = Arc::new(AtomicUsize::new(0));
        let recv_frames = Arc::new(AtomicUsize::new(0));
        let connect_retries = Arc::new(AtomicUsize::new(0));
        let send_retries = Arc::new(AtomicUsize::new(0));
        let delayed_frames = Arc::new(AtomicUsize::new(0));
        let injected_delay_ms_total = Arc::new(AtomicU64::new(0));
        let wakeup_counter = Arc::new(WakeupCounter::new());
        let worker_handles = Arc::new(Mutex::new(Vec::new()));
        let rng_seed = network_faults.mixed_seed(pid);

        let accept_stop = Arc::clone(&stop);
        let accept_worker_handles = Arc::clone(&worker_handles);
        let accept_inbound_tx = inbound_tx.clone();
        let accept_inbound_len = Arc::clone(&inbound_len);
        let accept_recv_frames = Arc::clone(&recv_frames);
        let accept_wakeup_counter = Arc::clone(&wakeup_counter);

        let accept_handle = thread::spawn(move || {
            while !accept_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _addr)) => {
                        if set_stream_defaults(&stream).is_err() {
                            continue;
                        }
                        let reader_stop = Arc::clone(&accept_stop);
                        let reader_inbound_tx = accept_inbound_tx.clone();
                        let reader_inbound_len = Arc::clone(&accept_inbound_len);
                        let reader_recv_frames = Arc::clone(&accept_recv_frames);
                        let reader_wakeup_counter = Arc::clone(&accept_wakeup_counter);
                        let handle = thread::spawn(move || {
                            let mut stream = stream;
                            while !reader_stop.load(Ordering::Relaxed) {
                                match recv_frame(&mut stream) {
                                    Ok(payload) => {
                                        reader_inbound_len.fetch_add(1, Ordering::Relaxed);
                                        reader_recv_frames.fetch_add(1, Ordering::Relaxed);
                                        reader_wakeup_counter.notify();
                                        if reader_inbound_tx.send(payload).is_err() {
                                            break;
                                        }
                                    }
                                    Err(err)
                                        if matches!(
                                            err.kind(),
                                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                                        ) =>
                                    {
                                        continue;
                                    }
                                    Err(_) => break,
                                }
                            }
                        });
                        if let Ok(mut handles) = accept_worker_handles.lock() {
                            handles.push(handle);
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => {
                        thread::sleep(Duration::from_millis(10));
                    }
                }
            }
        });

        let sender_handle = thread::spawn({
            let sender_stop = Arc::clone(&stop);
            let sender_connections = Arc::clone(&connections);
            let sender_outbound_len = Arc::clone(&outbound_len);
            let sender_sent_frames = Arc::clone(&sent_frames);
            let sender_connect_retries = Arc::clone(&connect_retries);
            let sender_send_retries = Arc::clone(&send_retries);
            let sender_delayed_frames = Arc::clone(&delayed_frames);
            let sender_injected_delay_ms_total = Arc::clone(&injected_delay_ms_total);
            move || {
                sender_loop(SenderLoopCtx {
                    stop: sender_stop,
                    addresses,
                    connections: sender_connections,
                    outbound_rx,
                    outbound_len: sender_outbound_len,
                    sent_frames: sender_sent_frames,
                    connect_retries: sender_connect_retries,
                    send_retries: sender_send_retries,
                    delayed_frames: sender_delayed_frames,
                    injected_delay_ms_total: sender_injected_delay_ms_total,
                    network_faults,
                    rng_seed,
                })
            }
        });

        Ok(Self {
            stop,
            inbound_rx,
            inbound_len,
            outbound_tx,
            outbound_len,
            sent_frames,
            recv_frames,
            connect_retries,
            send_retries,
            delayed_frames,
            injected_delay_ms_total,
            wakeup_counter,
            connections,
            accept_handle: Some(accept_handle),
            sender_handle: Some(sender_handle),
            worker_handles,
            network_faults,
            rng_seed,
        })
    }

    pub fn send(&self, recipient: usize, payload: &[u8]) -> io::Result<()> {
        self.outbound_len.fetch_add(1, Ordering::Relaxed);
        self.outbound_tx
            .send((recipient, payload.to_vec()))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "transport sender disconnected"))
    }

    pub fn recv_batch(&self, max_items: usize) -> io::Result<Vec<Vec<u8>>> {
        if max_items == 0 {
            return Ok(Vec::new());
        }

        let mut messages = Vec::new();
        while messages.len() < max_items {
            match self.inbound_rx.try_recv() {
                Ok(payload) => {
                    self.inbound_len.fetch_sub(1, Ordering::Relaxed);
                    messages.push(payload);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "transport receiver disconnected",
                    ));
                }
            }
        }
        Ok(messages)
    }

    pub fn pending_inbound(&self) -> usize {
        self.inbound_len.load(Ordering::Relaxed)
    }

    pub fn pending_outbound(&self) -> usize {
        self.outbound_len.load(Ordering::Relaxed)
    }

    pub fn stats(&self) -> TransportStats {
        TransportStats {
            sent_frames: self.sent_frames.load(Ordering::Relaxed),
            recv_frames: self.recv_frames.load(Ordering::Relaxed),
            connect_retries: self.connect_retries.load(Ordering::Relaxed),
            send_retries: self.send_retries.load(Ordering::Relaxed),
            delayed_frames: self.delayed_frames.load(Ordering::Relaxed),
            total_injected_delay_ms: self.injected_delay_ms_total.load(Ordering::Relaxed),
            network_fault_seed: self.rng_seed,
            configured_fixed_delay_ms: self.network_faults.fixed_delay_ms,
            configured_jitter_ms: self.network_faults.jitter_ms,
            configured_slow_honest_extra_delay_ms: self.network_faults.slow_honest_extra_delay_ms,
        }
    }

    pub fn close(&mut self) -> io::Result<()> {
        self.stop.store(true, Ordering::Relaxed);
        close_connections(&self.connections);

        if let Some(handle) = self.accept_handle.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.sender_handle.take() {
            let _ = handle.join();
        }

        let handles = {
            let mut guard = self
                .worker_handles
                .lock()
                .map_err(|_| io::Error::other("failed to acquire transport worker handles"))?;
            std::mem::take(&mut *guard)
        };
        for handle in handles {
            let _ = handle.join();
        }
        Ok(())
    }
}

impl Drop for LocalTcpTransport {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

impl TransportHandle for LocalTcpTransport {
    fn send(&self, recipient: usize, payload: &[u8]) -> io::Result<()> {
        Self::send(self, recipient, payload)
    }

    fn recv_batch(&self, max_items: usize) -> io::Result<Vec<Vec<u8>>> {
        Self::recv_batch(self, max_items)
    }

    fn pending_inbound(&self) -> usize {
        Self::pending_inbound(self)
    }

    fn pending_outbound(&self) -> usize {
        Self::pending_outbound(self)
    }

    fn wakeup_seq(&self) -> u64 {
        self.wakeup_counter.snapshot()
    }
}

#[cfg(test)]
mod tests {
    use super::{DelayRng, NetworkFaultConfig, compute_injected_delay_ms};

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
}
