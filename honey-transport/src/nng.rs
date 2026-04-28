use crate::handle::{NetworkFaultConfig, TransportHandle, TransportStats};
use crate::wakeup::WakeupCounter;
use crossbeam_channel::{Receiver, TryRecvError, unbounded};
use nng::options::Options;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const NNG_PORT_OFFSET: u16 = 11000;

pub struct NngTransport {
    stop: Arc<AtomicBool>,
    inbound_rx: Receiver<Vec<u8>>,
    inbound_len: Arc<AtomicUsize>,
    send_sockets: Arc<Vec<Option<nng::Socket>>>,
    sent_frames: Arc<AtomicUsize>,
    recv_frames: Arc<AtomicUsize>,
    wakeup_counter: Arc<WakeupCounter>,
    _recv_thread: Option<JoinHandle<()>>,
    network_faults: NetworkFaultConfig,
    rng_seed: u64,
}

impl NngTransport {
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

        let stop = Arc::new(AtomicBool::new(false));
        let (inbound_tx, inbound_rx) = unbounded::<Vec<u8>>();
        let inbound_len = Arc::new(AtomicUsize::new(0));
        let sent_frames = Arc::new(AtomicUsize::new(0));
        let recv_frames = Arc::new(AtomicUsize::new(0));
        let wakeup_counter = Arc::new(WakeupCounter::new());
        let rng_seed = network_faults.mixed_seed(pid);

        let nodes = addresses.len();
        let mut send_sockets = Vec::with_capacity(nodes);

        let (_host, port) = addresses[pid].clone();
        let listen_port = port.saturating_add(NNG_PORT_OFFSET);

        for target_pid in 0..nodes {
            if target_pid == pid {
                send_sockets.push(None);
                continue;
            }
            match nng::Socket::new(nng::Protocol::Pair0) {
                Ok(socket) => {
                    if socket
                        .set_opt::<nng::options::RecvTimeout>(Some(Duration::from_millis(200)))
                        .is_err()
                    {
                        send_sockets.push(None);
                        continue;
                    }
                    let (peer_host, peer_port) = addresses[target_pid].clone();
                    let peer_nng_port = peer_port.saturating_add(NNG_PORT_OFFSET);
                    let dial_url = format!("tcp://{peer_host}:{peer_nng_port}");
                    if socket.dial(&dial_url).is_ok() {}
                    send_sockets.push(Some(socket));
                }
                Err(_) => {
                    send_sockets.push(None);
                }
            }
        }

        let send_sockets = Arc::new(send_sockets);

        let recv_stop = Arc::clone(&stop);
        let recv_inbound_tx = inbound_tx.clone();
        let recv_inbound_len = Arc::clone(&inbound_len);
        let recv_recv_frames = Arc::clone(&recv_frames);
        let recv_wakeup_counter = Arc::clone(&wakeup_counter);
        let recv_listen_port = listen_port;

        let recv_thread = thread::spawn(move || {
            let listener = match nng::Socket::new(nng::Protocol::Pair0) {
                Ok(s) => s,
                Err(_) => return,
            };
            let listen_url = format!("tcp://0.0.0.0:{recv_listen_port}");
            if listener.listen(&listen_url).is_err() {
                return;
            }

            while !recv_stop.load(Ordering::Relaxed) {
                match listener.recv() {
                    Ok(msg) => {
                        let data = msg.as_slice().to_vec();
                        recv_inbound_len.fetch_add(1, Ordering::Relaxed);
                        recv_recv_frames.fetch_add(1, Ordering::Relaxed);
                        recv_wakeup_counter.notify();
                        if recv_inbound_tx.send(data).is_err() {
                            break;
                        }
                    }
                    Err(nng::Error::TimedOut) => continue,
                    Err(_) => {
                        if recv_stop.load(Ordering::Relaxed) {
                            break;
                        }
                    }
                }
            }
        });

        Ok(Self {
            stop,
            inbound_rx,
            inbound_len,
            send_sockets,
            sent_frames,
            recv_frames,
            wakeup_counter,
            _recv_thread: Some(recv_thread),
            network_faults,
            rng_seed,
        })
    }

    pub fn send(&self, recipient: usize, payload: &[u8]) -> io::Result<()> {
        let Some(socket) = self.send_sockets.get(recipient).and_then(|s| s.as_ref()) else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                format!("no NNG socket for peer {recipient}"),
            ));
        };
        let msg = nng::Message::from(payload);
        socket.send(msg).map_err(|err| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("NNG send error: {err:?}"),
            )
        })?;
        self.sent_frames.fetch_add(1, Ordering::Relaxed);
        Ok(())
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
                Err(TryRecvError::Disconnected) => break,
            }
        }
        Ok(messages)
    }

    pub fn pending_inbound(&self) -> usize {
        self.inbound_len.load(Ordering::Relaxed)
    }

    pub fn pending_outbound(&self) -> usize {
        0
    }

    pub fn stats(&self) -> TransportStats {
        TransportStats {
            sent_frames: self.sent_frames.load(Ordering::Relaxed),
            recv_frames: self.recv_frames.load(Ordering::Relaxed),
            connect_retries: 0,
            send_retries: 0,
            delayed_frames: 0,
            total_injected_delay_ms: 0,
            network_fault_seed: self.rng_seed,
            configured_fixed_delay_ms: self.network_faults.fixed_delay_ms,
            configured_jitter_ms: self.network_faults.jitter_ms,
            configured_slow_honest_extra_delay_ms: self.network_faults.slow_honest_extra_delay_ms,
        }
    }

    pub fn close(&self) -> io::Result<()> {
        self.stop.store(true, Ordering::Relaxed);
        Ok(())
    }
}

impl Drop for NngTransport {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

impl TransportHandle for NngTransport {
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

    fn stats(&self) -> TransportStats {
        Self::stats(self)
    }

    fn register_wakeup_waiter(&self, t: thread::Thread) {
        self.wakeup_counter.register(t);
    }

    fn unregister_wakeup_waiter(&self) {
        self.wakeup_counter.unregister();
    }
}
