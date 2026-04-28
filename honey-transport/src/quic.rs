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

pub struct QuicTransport {
    stop: Arc<AtomicBool>,
    inbound_rx: Receiver<Vec<u8>>,
    inbound_len: Arc<AtomicUsize>,
    outbound_tx: Sender<(usize, Vec<u8>)>,
    outbound_len: Arc<AtomicUsize>,
    sent_frames: Arc<AtomicUsize>,
    recv_frames: Arc<AtomicUsize>,
    wakeup_counter: Arc<WakeupCounter>,
    _rt_guard: Option<thread::JoinHandle<()>>,
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
        let wakeup_counter = Arc::new(WakeupCounter::new());
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

        let rt_stop = Arc::clone(&stop);
        let rt_inbound_tx = inbound_tx;
        let rt_inbound_len = Arc::clone(&inbound_len);
        let rt_recv_frames = Arc::clone(&recv_frames);
        let rt_wakeup_counter = Arc::clone(&wakeup_counter);
        let rt_sent_frames = Arc::clone(&sent_frames);
        let rt_pid = pid;
        let rt_socket_addr = socket_addr;

        let rt_outbound_len = Arc::clone(&outbound_len);
        let rt_guard = thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(_e) => {
                    return;
                }
            };
            let _ = rt.block_on(async move {
                run_quic_node(
                    rt_stop,
                    rt_pid,
                    rt_socket_addr,
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
                )
                .await
            });
        });

        Ok(Self {
            stop,
            inbound_rx,
            inbound_len,
            outbound_tx,
            outbound_len,
            sent_frames,
            recv_frames,
            wakeup_counter,
            _rt_guard: Some(rt_guard),
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
                Err(TryRecvError::Disconnected) => break,
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
) {
    let server_crypto = match build_server_crypto(cert_der.clone(), key_der.clone_key()) {
        Ok(c) => c,
        Err(_e) => {
            return;
        }
    };
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));

    let mut socket = None;
    for i in 0..50 {
        match UdpSocket::bind(socket_addr) {
            Ok(s) => {
                socket = Some(s);
                break;
            }
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    let socket = match socket {
        Some(s) => s,
        None => {
            return;
        }
    };

    let endpoint = match quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    ) {
        Ok(ep) => Arc::new(ep),
        Err(_e) => {
            return;
        }
    };

    let client_crypto = match build_client_crypto(&cert_der) {
        Ok(c) => c,
        Err(_e) => {
            return;
        }
    };
    let client_config = quinn::ClientConfig::new(Arc::new(client_crypto));

    let connections: Arc<Mutex<Vec<Option<quinn::Connection>>>> =
        Arc::new(Mutex::new(vec![None; peer_addrs.len()]));

    // ── Accept task (runs while we connect) ────────────────────────────
    let accept_ep = Arc::clone(&endpoint);
    let accept_stop = Arc::clone(&stop);
    tokio::spawn(async move {
        while let Some(incoming) = accept_ep.accept().await {
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
                        Err(_) => continue,
                    }
                }
            });
        }
    });
    tokio::task::yield_now().await;
    // ── Connect to every peer (with retry) ─────────────────────────────
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut client_endpoints: Vec<quinn::Endpoint> = Vec::with_capacity(peer_addrs.len());

    for (target_pid, addr) in peer_addrs.iter().enumerate() {
        if target_pid == pid {
            continue;
        }
        let client_socket = match UdpSocket::bind("127.0.0.1:0") {
            Ok(s) => s,
            Err(_e) => {
                continue;
            }
        };
        let client_ep = match quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            client_socket,
            Arc::new(quinn::TokioRuntime),
        ) {
            Ok(ep) => ep,
            Err(_e) => {
                continue;
            }
        };

        let mut connected = false;
        for attempt in 0..100 {
            match client_ep.connect_with(client_config.clone(), *addr, "localhost") {
                Ok(connecting) => match connecting.await {
                    Ok(conn) => {
                        if let Ok(mut guard) = connections.lock() {
                            guard[target_pid] = Some(conn);
                        }
                        connected = true;
                        break;
                    }
                    Err(_e) => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                },
                Err(_e) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        if connected {
            client_endpoints.push(client_ep);
        }
    }

    // ── Send task ──────────────────────────────────────────────────────
    let send_conns = Arc::clone(&connections);
    let send_stop = Arc::clone(&stop);
    tokio::spawn(async move {
        loop {
            let (recipient, payload) = match outbound_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(item) => item,
                Err(RecvTimeoutError::Timeout) => {
                    if send_stop.load(Ordering::Relaxed) {
                        break;
                    }
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => break,
            };
            outbound_len.fetch_sub(1, Ordering::Relaxed);

            let conn = {
                let guard = send_conns.lock().unwrap();
                guard.get(recipient).and_then(|c| c.as_ref()).cloned()
            };
            if let Some(conn) = conn {
                match conn.open_uni().await {
                    Ok(mut send) => {
                        if send.write_all(&payload).await.is_ok() {
                            let _ = send.finish();
                            sent_frames.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(_e) => {}
                }
            } else {
            }

            if send_stop.load(Ordering::Relaxed) {
                break;
            }
        }
    });

    // ── Wait until stopped ─────────────────────────────────────────────
    loop {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if stop.load(Ordering::Relaxed) {
            break;
        }
    }

    endpoint.close(0u32.into(), b"shutdown");
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
