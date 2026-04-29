use crate::handle::{NetworkFaultConfig, TransportHandle, TransportStats};
use crate::wakeup::WakeupCounter;
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, TryRecvError, unbounded};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const STARTUP_READY_TIMEOUT: Duration = Duration::from_secs(5);
const SOCKET_BIND_RETRIES: usize = 50;
const CONNECT_RETRY_LIMIT: usize = 500;
const SEND_RETRY_LIMIT: usize = 500;
const RETRY_BACKOFF: Duration = Duration::from_millis(10);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

pub struct QuicTransport {
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
    runtime_error: Arc<Mutex<Option<String>>>,
    rt_guard: Mutex<Option<thread::JoinHandle<()>>>,
    peer_count: usize,
    network_faults: NetworkFaultConfig,
    rng_seed: u64,
}

fn generate_self_signed_cert() -> io::Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let key =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(io::Error::other)?;
    let cert = rcgen::CertificateParams::default()
        .self_signed(&key)
        .map_err(io::Error::other)?;
    let cert_der = cert.der().clone();
    let key_der = key.serialize_der();
    let private_key = PrivatePkcs8KeyDer::from(key_der);
    Ok((cert_der, PrivateKeyDer::Pkcs8(private_key)))
}

impl QuicTransport {
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
        let socket_addr: SocketAddr = format!("{host}:{port}")
            .parse()
            .map_err(|err| io::Error::other(format!("invalid address {host}:{port}: {err}")))?;

        let stop = Arc::new(AtomicBool::new(false));
        let (inbound_tx, inbound_rx) = unbounded::<Vec<u8>>();
        let inbound_len = Arc::new(AtomicUsize::new(0));
        let (outbound_tx, outbound_rx) = unbounded::<(usize, Vec<u8>)>();
        let outbound_len = Arc::new(AtomicUsize::new(0));
        let sent_frames = Arc::new(AtomicUsize::new(0));
        let recv_frames = Arc::new(AtomicUsize::new(0));
        let connect_retries = Arc::new(AtomicUsize::new(0));
        let send_retries = Arc::new(AtomicUsize::new(0));
        let wakeup_counter = Arc::new(WakeupCounter::new());
        let runtime_error = Arc::new(Mutex::new(None));
        let rng_seed = network_faults.mixed_seed(pid);

        let peer_addrs: Vec<SocketAddr> = addresses
            .iter()
            .map(|(h, p)| {
                format!("{h}:{p}")
                    .parse::<SocketAddr>()
                    .map_err(|err| io::Error::other(err.to_string()))
            })
            .collect::<io::Result<Vec<_>>>()?;

        let (cert_der, key_der) = generate_self_signed_cert()?;
        let (ready_tx, ready_rx) = unbounded::<io::Result<()>>();

        let rt_stop = Arc::clone(&stop);
        let rt_runtime_error = Arc::clone(&runtime_error);
        let rt_inbound_tx = inbound_tx;
        let rt_inbound_len = Arc::clone(&inbound_len);
        let rt_recv_frames = Arc::clone(&recv_frames);
        let rt_wakeup_counter = Arc::clone(&wakeup_counter);
        let rt_sent_frames = Arc::clone(&sent_frames);
        let rt_connect_retries = Arc::clone(&connect_retries);
        let rt_send_retries = Arc::clone(&send_retries);
        let rt_outbound_len = Arc::clone(&outbound_len);
        let rt_guard = thread::spawn(move || {
            let result = run_quic_runtime(
                Arc::clone(&rt_stop),
                pid,
                socket_addr,
                peer_addrs,
                cert_der,
                key_der,
                rt_inbound_tx,
                rt_inbound_len,
                rt_recv_frames,
                rt_wakeup_counter,
                outbound_rx,
                rt_outbound_len,
                rt_sent_frames,
                rt_connect_retries,
                rt_send_retries,
                ready_tx,
            );
            match result {
                Ok(()) if !rt_stop.load(Ordering::Relaxed) => {
                    set_runtime_error(
                        &rt_runtime_error,
                        "quic transport runtime exited unexpectedly",
                    );
                }
                Err(err) if !rt_stop.load(Ordering::Relaxed) => {
                    set_runtime_error(&rt_runtime_error, err.to_string());
                }
                _ => {}
            }
        });

        match ready_rx.recv_timeout(STARTUP_READY_TIMEOUT) {
            Ok(Ok(())) => Ok(Self {
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
                runtime_error,
                rt_guard: Mutex::new(Some(rt_guard)),
                peer_count: addresses.len(),
                network_faults,
                rng_seed,
            }),
            Ok(Err(err)) => {
                stop.store(true, Ordering::Relaxed);
                let _ = rt_guard.join();
                Err(err)
            }
            Err(RecvTimeoutError::Timeout) => {
                stop.store(true, Ordering::Relaxed);
                let _ = rt_guard.join();
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "quic transport runtime did not become ready within 5s",
                ))
            }
            Err(RecvTimeoutError::Disconnected) => {
                stop.store(true, Ordering::Relaxed);
                let _ = rt_guard.join();
                Err(io::Error::other(
                    "quic transport runtime exited before reporting readiness",
                ))
            }
        }
    }

    pub fn send(&self, recipient: usize, payload: &[u8]) -> io::Result<()> {
        self.check_runtime_error()?;
        if recipient >= self.peer_count {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("recipient {recipient} out of range"),
            ));
        }
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
                    self.check_runtime_error()?;
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
        if let Some(handle) = self
            .rt_guard
            .lock()
            .map_err(|_| io::Error::other("failed to lock quic runtime handle"))?
            .take()
        {
            let _ = handle.join();
        }
        Ok(())
    }

    fn check_runtime_error(&self) -> io::Result<()> {
        if let Some(message) = runtime_error_snapshot(&self.runtime_error) {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, message));
        }
        Ok(())
    }
}

impl Drop for QuicTransport {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

impl TransportHandle for QuicTransport {
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

fn build_server_crypto(
    cert_der: CertificateDer<'static>,
    key_der: PrivateKeyDer<'static>,
) -> io::Result<QuicServerConfig> {
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der.clone_key())
        .map_err(io::Error::other)?;
    server_crypto.alpn_protocols = vec![b"honey-quic".to_vec()];
    QuicServerConfig::try_from(server_crypto).map_err(io::Error::other)
}

fn build_client_crypto(cert_der: &CertificateDer<'static>) -> io::Result<QuicClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der.clone()).map_err(io::Error::other)?;
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"honey-quic".to_vec()];
    client_crypto
        .dangerous()
        .set_certificate_verifier(Arc::new(SkipServerVerification));
    QuicClientConfig::try_from(client_crypto).map_err(io::Error::other)
}

fn run_quic_runtime(
    stop: Arc<AtomicBool>,
    pid: usize,
    socket_addr: SocketAddr,
    peer_addrs: Vec<SocketAddr>,
    cert_der: CertificateDer<'static>,
    key_der: PrivateKeyDer<'static>,
    inbound_tx: Sender<Vec<u8>>,
    inbound_len: Arc<AtomicUsize>,
    recv_frames: Arc<AtomicUsize>,
    wakeup_counter: Arc<WakeupCounter>,
    outbound_rx: Receiver<(usize, Vec<u8>)>,
    outbound_len: Arc<AtomicUsize>,
    sent_frames: Arc<AtomicUsize>,
    connect_retries: Arc<AtomicUsize>,
    send_retries: Arc<AtomicUsize>,
    ready_tx: Sender<io::Result<()>>,
) -> io::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .map_err(io::Error::other)?;
    rt.block_on(run_quic_node(
        stop,
        pid,
        socket_addr,
        peer_addrs,
        cert_der,
        key_der,
        inbound_tx,
        inbound_len,
        recv_frames,
        wakeup_counter,
        outbound_rx,
        outbound_len,
        sent_frames,
        connect_retries,
        send_retries,
        ready_tx,
    ))
}

#[allow(clippy::too_many_arguments)]
async fn run_quic_node(
    stop: Arc<AtomicBool>,
    pid: usize,
    socket_addr: SocketAddr,
    peer_addrs: Vec<SocketAddr>,
    cert_der: CertificateDer<'static>,
    key_der: PrivateKeyDer<'static>,
    inbound_tx: Sender<Vec<u8>>,
    inbound_len: Arc<AtomicUsize>,
    recv_frames: Arc<AtomicUsize>,
    wakeup_counter: Arc<WakeupCounter>,
    outbound_rx: Receiver<(usize, Vec<u8>)>,
    outbound_len: Arc<AtomicUsize>,
    sent_frames: Arc<AtomicUsize>,
    connect_retries: Arc<AtomicUsize>,
    send_retries: Arc<AtomicUsize>,
    ready_tx: Sender<io::Result<()>>,
) -> io::Result<()> {
    let server_crypto = build_server_crypto(cert_der.clone(), key_der.clone_key())?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
    let socket = bind_socket_with_retry(socket_addr).await?;
    let endpoint = Arc::new(
        quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(io::Error::other)?,
    );
    let client_crypto = build_client_crypto(&cert_der)?;
    let client_config = quinn::ClientConfig::new(Arc::new(client_crypto));

    let accept_handle = tokio::spawn(run_accept_loop(
        Arc::clone(&endpoint),
        Arc::clone(&stop),
        inbound_tx.clone(),
        Arc::clone(&inbound_len),
        Arc::clone(&recv_frames),
        Arc::clone(&wakeup_counter),
    ));

    ready_tx
        .send(Ok(()))
        .map_err(|_| io::Error::other("failed to report quic transport readiness"))?;

    let send_result = run_send_loop(
        stop,
        pid,
        endpoint.clone(),
        client_config,
        peer_addrs,
        inbound_tx,
        inbound_len,
        recv_frames,
        wakeup_counter,
        outbound_rx,
        outbound_len,
        sent_frames,
        connect_retries,
        send_retries,
    )
    .await;

    endpoint.close(0u32.into(), b"shutdown");
    let _ = accept_handle.await;
    send_result
}

async fn bind_socket_with_retry(socket_addr: SocketAddr) -> io::Result<UdpSocket> {
    let mut last_error = None;
    for _attempt in 0..SOCKET_BIND_RETRIES {
        match UdpSocket::bind(socket_addr) {
            Ok(socket) => return Ok(socket),
            Err(err) => {
                last_error = Some(err);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    Err(last_error.unwrap_or_else(|| io::Error::other("failed to bind quic socket")))
}

async fn run_accept_loop(
    endpoint: Arc<quinn::Endpoint>,
    stop: Arc<AtomicBool>,
    inbound_tx: Sender<Vec<u8>>,
    inbound_len: Arc<AtomicUsize>,
    recv_frames: Arc<AtomicUsize>,
    wakeup_counter: Arc<WakeupCounter>,
) {
    while !stop.load(Ordering::Relaxed) {
        let Some(incoming) = endpoint.accept().await else {
            break;
        };
        let tx = inbound_tx.clone();
        let len = Arc::clone(&inbound_len);
        let frames = Arc::clone(&recv_frames);
        let waker = Arc::clone(&wakeup_counter);
        tokio::spawn(async move {
            let Ok(conn) = incoming.await else { return };
            loop {
                match conn.accept_uni().await {
                    Ok(stream) => {
                        let tx = tx.clone();
                        let len = Arc::clone(&len);
                        let frames = Arc::clone(&frames);
                        let waker = Arc::clone(&waker);
                        tokio::spawn(async move {
                            if let Ok(data) = read_stream_to_end(stream).await {
                                len.fetch_add(1, Ordering::Relaxed);
                                frames.fetch_add(1, Ordering::Relaxed);
                                waker.notify();
                                let _ = tx.send(data);
                            }
                        });
                    }
                    Err(quinn::ConnectionError::ApplicationClosed { .. }) => break,
                    Err(_) => break,
                }
            }
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_send_loop(
    stop: Arc<AtomicBool>,
    pid: usize,
    endpoint: Arc<quinn::Endpoint>,
    client_config: quinn::ClientConfig,
    peer_addrs: Vec<SocketAddr>,
    inbound_tx: Sender<Vec<u8>>,
    inbound_len: Arc<AtomicUsize>,
    recv_frames: Arc<AtomicUsize>,
    wakeup_counter: Arc<WakeupCounter>,
    outbound_rx: Receiver<(usize, Vec<u8>)>,
    outbound_len: Arc<AtomicUsize>,
    sent_frames: Arc<AtomicUsize>,
    connect_retries: Arc<AtomicUsize>,
    send_retries: Arc<AtomicUsize>,
) -> io::Result<()> {
    let mut connections: Vec<Option<quinn::Connection>> = vec![None; peer_addrs.len()];
    loop {
        let (recipient, payload) = match outbound_rx.recv_timeout(POLL_INTERVAL) {
            Ok(item) => item,
            Err(RecvTimeoutError::Timeout) => {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => break,
        };
        outbound_len.fetch_sub(1, Ordering::Relaxed);

        if recipient == pid {
            sent_frames.fetch_add(1, Ordering::Relaxed);
            recv_frames.fetch_add(1, Ordering::Relaxed);
            inbound_len.fetch_add(1, Ordering::Relaxed);
            wakeup_counter.notify();
            inbound_tx.send(payload).map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "loopback receiver disconnected")
            })?;
            continue;
        }

        send_payload_with_retry(
            endpoint.as_ref(),
            &client_config,
            &peer_addrs,
            &mut connections,
            recipient,
            &payload,
            stop.as_ref(),
            connect_retries.as_ref(),
            send_retries.as_ref(),
        )
        .await?;
        sent_frames.fetch_add(1, Ordering::Relaxed);
    }
    Ok(())
}

async fn send_payload_with_retry(
    endpoint: &quinn::Endpoint,
    client_config: &quinn::ClientConfig,
    peer_addrs: &[SocketAddr],
    connections: &mut [Option<quinn::Connection>],
    recipient: usize,
    payload: &[u8],
    stop: &AtomicBool,
    connect_retries: &AtomicUsize,
    send_retries: &AtomicUsize,
) -> io::Result<()> {
    let mut attempts = 0usize;
    loop {
        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        let conn = ensure_connection(
            endpoint,
            client_config,
            peer_addrs,
            connections,
            recipient,
            stop,
            connect_retries,
        )
        .await?;
        match conn.open_uni().await {
            Ok(mut send) => {
                if let Err(err) = send.write_all(payload).await {
                    attempts += 1;
                    send_retries.fetch_add(1, Ordering::Relaxed);
                    connections[recipient] = None;
                    if attempts >= SEND_RETRY_LIMIT {
                        return Err(io::Error::other(format!(
                            "failed to write quic frame to recipient {recipient}: {err}"
                        )));
                    }
                    tokio::time::sleep(RETRY_BACKOFF).await;
                    continue;
                }
                if let Err(err) = send.finish() {
                    attempts += 1;
                    send_retries.fetch_add(1, Ordering::Relaxed);
                    connections[recipient] = None;
                    if attempts >= SEND_RETRY_LIMIT {
                        return Err(io::Error::other(format!(
                            "failed to finish quic frame for recipient {recipient}: {err}"
                        )));
                    }
                    tokio::time::sleep(RETRY_BACKOFF).await;
                    continue;
                }
                return Ok(());
            }
            Err(err) => {
                attempts += 1;
                send_retries.fetch_add(1, Ordering::Relaxed);
                connections[recipient] = None;
                if attempts >= SEND_RETRY_LIMIT {
                    return Err(io::Error::other(format!(
                        "failed to open quic stream for recipient {recipient}: {err}"
                    )));
                }
                tokio::time::sleep(RETRY_BACKOFF).await;
            }
        }
    }
}

async fn ensure_connection(
    endpoint: &quinn::Endpoint,
    client_config: &quinn::ClientConfig,
    peer_addrs: &[SocketAddr],
    connections: &mut [Option<quinn::Connection>],
    recipient: usize,
    stop: &AtomicBool,
    connect_retries: &AtomicUsize,
) -> io::Result<quinn::Connection> {
    if let Some(conn) = connections.get(recipient).and_then(|conn| conn.as_ref()) {
        return Ok(conn.clone());
    }

    for _attempt in 0..CONNECT_RETRY_LIMIT {
        if stop.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "quic transport stopped while connecting",
            ));
        }
        let connecting = endpoint
            .connect_with(client_config.clone(), peer_addrs[recipient], "localhost")
            .map_err(io::Error::other);
        match connecting {
            Ok(connecting) => match connecting.await {
                Ok(conn) => {
                    connections[recipient] = Some(conn.clone());
                    return Ok(conn);
                }
                Err(err) => {
                    connect_retries.fetch_add(1, Ordering::Relaxed);
                    tokio::time::sleep(RETRY_BACKOFF).await;
                    if stop.load(Ordering::Relaxed) {
                        return Err(io::Error::other(err));
                    }
                }
            },
            Err(_err) => {
                connect_retries.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(RETRY_BACKOFF).await;
            }
        }
    }

    Err(io::Error::other(format!(
        "failed to connect to recipient {recipient} after {CONNECT_RETRY_LIMIT} attempts"
    )))
}

async fn read_stream_to_end(mut recv: quinn::RecvStream) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    loop {
        match recv.read_chunk(8192, true).await {
            Ok(Some(chunk)) => {
                buf.extend_from_slice(&chunk.bytes);
            }
            Ok(None) => break,
            Err(_) => {
                if buf.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "stream error",
                    ));
                }
                break;
            }
        }
    }
    Ok(buf)
}

fn set_runtime_error(runtime_error: &Arc<Mutex<Option<String>>>, message: impl Into<String>) {
    if let Ok(mut guard) = runtime_error.lock()
        && guard.is_none()
    {
        *guard = Some(message.into());
    }
}

fn runtime_error_snapshot(runtime_error: &Arc<Mutex<Option<String>>>) -> Option<String> {
    runtime_error.lock().ok().and_then(|guard| guard.clone())
}

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::QuicTransport;
    use crate::handle::NetworkFaultConfig;
    use std::net::UdpSocket;
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn immediate_send_after_startup_reaches_receiver() {
        let reserved = (0..2)
            .map(|_| UdpSocket::bind("127.0.0.1:0").expect("should reserve loopback udp port"))
            .collect::<Vec<_>>();
        let addresses = reserved
            .iter()
            .map(|socket| {
                let addr = socket
                    .local_addr()
                    .expect("socket should expose local addr");
                (String::from("127.0.0.1"), addr.port())
            })
            .collect::<Vec<_>>();
        drop(reserved);

        let sender = QuicTransport::new(0, addresses.clone(), NetworkFaultConfig::default())
            .expect("sender transport should bind");
        let receiver = QuicTransport::new(1, addresses, NetworkFaultConfig::default())
            .expect("receiver transport should bind");

        for payload in [b"one".as_slice(), b"two".as_slice(), b"three".as_slice()] {
            sender
                .send(1, payload)
                .expect("quic frame should enqueue successfully");
        }

        let deadline = Instant::now() + Duration::from_secs(2);
        let mut received = Vec::new();
        while Instant::now() < deadline && received.len() < 3 {
            for payload in receiver
                .recv_batch(3 - received.len())
                .expect("receiver should stay connected")
            {
                received.push(payload);
            }
            if received.len() < 3 {
                thread::sleep(Duration::from_millis(5));
            }
        }

        assert_eq!(
            received.len(),
            3,
            "receiver should collect all queued frames"
        );
        assert_eq!(received[0], b"one");
        assert_eq!(received[1], b"two");
        assert_eq!(received[2], b"three");

        sender.close().expect("sender should close cleanly");
        receiver.close().expect("receiver should close cleanly");
    }
}
