use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, TryRecvError, unbounded};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::transport::handle::{TransportHandle, WakeupCounter};

type ConnectionMap = Arc<Mutex<HashMap<usize, TcpStream>>>;

#[derive(Clone, Copy, Debug, Default)]
pub struct TransportStats {
    pub sent_frames: usize,
    pub recv_frames: usize,
    pub connect_retries: usize,
    pub send_retries: usize,
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

fn sender_loop(
    stop: Arc<AtomicBool>,
    addresses: Vec<(String, u16)>,
    connections: ConnectionMap,
    outbound_rx: Receiver<(usize, Vec<u8>)>,
    outbound_len: Arc<AtomicUsize>,
    sent_frames: Arc<AtomicUsize>,
    connect_retries: Arc<AtomicUsize>,
    send_retries: Arc<AtomicUsize>,
) {
    while !stop.load(Ordering::Relaxed) {
        let (recipient, payload) = match outbound_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(item) => item,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        outbound_len.fetch_sub(1, Ordering::Relaxed);

        let mut failures = 0usize;
        while !stop.load(Ordering::Relaxed) {
            let mut stream = match get_connection(recipient, &addresses, &connections) {
                Ok(stream) => stream,
                Err(_) => {
                    failures += 1;
                    connect_retries.fetch_add(1, Ordering::Relaxed);
                    if failures >= 1000 {
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
            };

            match send_frame(&mut stream, &payload) {
                Ok(()) => {
                    sent_frames.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                Err(_) => {
                    failures += 1;
                    send_retries.fetch_add(1, Ordering::Relaxed);
                    drop_connection(recipient, &connections);
                    if failures >= 1000 {
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }
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
    wakeup_counter: Arc<WakeupCounter>,
    connections: ConnectionMap,
    accept_handle: Option<JoinHandle<()>>,
    sender_handle: Option<JoinHandle<()>>,
    worker_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl LocalTcpTransport {
    pub fn new(pid: usize, addresses: Vec<(String, u16)>) -> io::Result<Self> {
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
        let wakeup_counter = Arc::new(WakeupCounter::new());
        let worker_handles = Arc::new(Mutex::new(Vec::new()));

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
            move || {
                sender_loop(
                    sender_stop,
                    addresses,
                    sender_connections,
                    outbound_rx,
                    sender_outbound_len,
                    sender_sent_frames,
                    sender_connect_retries,
                    sender_send_retries,
                )
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
            wakeup_counter,
            connections,
            accept_handle: Some(accept_handle),
            sender_handle: Some(sender_handle),
            worker_handles,
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
