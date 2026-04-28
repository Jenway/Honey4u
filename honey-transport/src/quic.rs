use crate::handle::{NetworkFaultConfig, TransportHandle, TransportStats};
use crate::wakeup::WakeupCounter;
use crossbeam_channel::{Receiver, Sender, TryRecvError, unbounded};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::io;
use std::net::SocketAddr;
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
    _sender_guard: Option<thread::JoinHandle<()>>,
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
                    .parse()
                    .map_err(|err| io::Error::other(err.to_string()))
            })
            .collect::<io::Result<Vec<_>>>()?;

        let (cert_der, key_der) = generate_self_signed_cert()?;

        let rt_stop = Arc::clone(&stop);
        let rt_inbound_tx = inbound_tx.clone();
        let rt_inbound_len = Arc::clone(&inbound_len);
        let rt_recv_frames = Arc::clone(&recv_frames);
        let rt_wakeup_counter = Arc::clone(&wakeup_counter);
        let rt_outbound_rx = outbound_rx.clone();
        let rt_outbound_len = Arc::clone(&outbound_len);
        let rt_sent_frames = Arc::clone(&sent_frames);
        let rt_peer_addrs = peer_addrs.clone();
        let rt_pid = pid;
        let rt_socket_addr = socket_addr;

        let rt_guard = thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(_) => return,
            };

            match rt.block_on(run_quic_node(
                rt_stop,
                rt_pid,
                rt_socket_addr,
                rt_peer_addrs,
                cert_der,
                key_der,
                rt_inbound_tx,
                rt_inbound_len,
                rt_recv_frames,
                rt_wakeup_counter,
                rt_outbound_rx,
                rt_outbound_len,
                rt_sent_frames,
                network_faults,
            )) {
                Ok(()) => {}
                Err(_err) => {
                    // Transport stopped
                }
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
            wakeup_counter,
            _rt_guard: Some(rt_guard),
            _sender_guard: None,
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
        if let Some(handle) = self._rt_guard.as_ref() {
            let _ = handle.thread().unpark();
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
    _faults: NetworkFaultConfig,
) -> io::Result<()> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der.clone()).map_err(io::Error::other)?;

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der.clone_key())
        .map_err(io::Error::other)?;
    server_crypto.alpn_protocols = vec![b"honey-quic".to_vec()];

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert_der).map_err(io::Error::other)?;
    client_crypto.dangerous()
        .set_certificate_verifier(Arc::new(SkipServerVerification::new()));
    client_crypto.alpn_protocols = vec![b"honey-quic".to_vec()];

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    transport_config.keep_alive_interval(Some(Duration::from_secs(5)));

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
    let endpoint =
        quinn::Endpoint::new(quinn::EndpointConfig::default(), Some(server_config), socket_addr)
            .map_err(io::Error::other)?;

    let mut connections: Vec<Option<quinn::Connection>> = vec![None; peer_addrs.len()];
    for (target_pid, addr) in peer_addrs.iter().enumerate() {
        if target_pid == pid {
            connections[pid] = None;
            continue;
        }
        let client_config = quinn::ClientConfig::new(Arc::new(client_crypto.clone()));
        match quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            "[::]:0".parse().unwrap(),
        )
        .map_err(io::Error::other)?
        .connect_with(client_config, *addr, "localhost")
        .map_err(io::Error::other)?
        .await
        {
            Ok(conn) => {
                connections[target_pid] = Some(conn);
            }
            Err(_) => {
                connections[target_pid] = None;
            }
        }
    }

    let connections = Arc::new(Mutex::new(connections));
    tokio::pin! {
        let accept_fut = accept_loop(
            &endpoint,
            Arc::clone(&inbound_tx),
            Arc::clone(&inbound_len),
            Arc::clone(&recv_frames),
            Arc::clone(&wakeup_counter),
        );
    }

    let conns_for_send = Arc::clone(&connections);
    let send_task = tokio::spawn(async move {
        while !stop.load(Ordering::Relaxed) {
            let (recipient, payload) = match outbound_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(item) => item,
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
            };
            outbound_len.fetch_sub(1, Ordering::Relaxed);

            let guard = conns_for_send.lock().unwrap();
            if let Some(Some(conn)) = guard.get(recipient) {
                if let Ok(mut send) = conn.open_uni().await {
                    if send.write_all(&payload).await.is_ok() {
                        let _ = send.finish().await;
                        sent_frames.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    });

    tokio::select! {
        _ = accept_fut => {},
        _ = send_task => {},
        _ = tokio::signal::ctrl_c() => {},
    }

    endpoint.close(0u32.into(), b"shutdown");
    Ok(())
}

async fn accept_loop(
    endpoint: &quinn::Endpoint,
    inbound_tx: Sender<Vec<u8>>,
    inbound_len: Arc<AtomicUsize>,
    recv_frames: Arc<AtomicUsize>,
    wakeup_counter: Arc<WakeupCounter>,
) {
    loop {
        match endpoint.accept().await {
            Some(incoming) => {
                let tx = inbound_tx.clone();
                let len = Arc::clone(&inbound_len);
                let frames = Arc::clone(&recv_frames);
                let waker = Arc::clone(&wakeup_counter);
                tokio::spawn(async move {
                    match incoming.accept() {
                        Ok(conn) => {
                            while let Ok(stream) = conn.accept_uni().await {
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
                        }
                        Err(_) => {}
                    }
                });
            }
            None => break,
        }
    }
}

async fn read_stream_to_end(mut recv: quinn::RecvStream) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    loop {
        match recv.read_chunk(8192, false).await {
            Ok(Some(chunk)) => {
                buf.extend_from_slice(&chunk.bytes);
            }
            Ok(None) => break,
            Err(_) => {
                if buf.is_empty() {
                    return Err(io::Error::new(io::ErrorKind::ConnectionReset, "stream error"));
                }
                break;
            }
        }
    }
    Ok(buf)
}

#[derive(Debug)]
struct SkipServerVerification {
    verified: Arc<rustls::crypto::CryptoProvider>,
}

impl SkipServerVerification {
    fn new() -> Self {
        Self {
            verified: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }
}

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
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.verified.signature_verification_algorithms())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.verified.signature_verification_algorithms())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.verified.signature_verification_algorithms().supported_schemes()
    }
}
