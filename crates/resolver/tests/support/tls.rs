#![allow(clippy::unwrap_used, dead_code)]
use hickory_proto::{
    op::Message,
    rr::{RData, Record, rdata::A},
};
use rustwalld_dns_resolver::UpstreamTransport;
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{ServerConfig, crypto::ring, pki_types::PrivatePkcs8KeyDer},
};

pub struct Mock {
    pub address: SocketAddr,
    pub transport: UpstreamTransport,
    pub accepted: Arc<AtomicUsize>,
    pub active: Arc<AtomicUsize>,
    pub queries: Arc<AtomicUsize>,
    pub replies: Arc<AtomicUsize>,
    pub inflight: Arc<AtomicUsize>,
    pub peak: Arc<AtomicUsize>,
    pub mode: Arc<AtomicU8>,
    pub pinned: tokio::sync::watch::Sender<Option<String>>,
    pub pin_release: tokio::sync::watch::Sender<bool>,
    task: JoinHandle<()>,
}
// Modes: 0 normal, 1 close after reply, 2 stall reply, 3 wrong ID,
// 4 truncated reply, 5 short frame, 6 stall handshake, 7 invalid DNS,
// 8 delayed successful reply, 9 close before reply.
struct Active(Arc<AtomicUsize>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
impl Mock {
    pub async fn start(mode: u8) -> Self {
        Self::with_expiry(mode, false).await
    }
    pub async fn start_pipelined(mode: u8) -> Self {
        Self::with_options(mode, false, true).await
    }
    pub async fn with_expiry(mode: u8, expired: bool) -> Self {
        Self::with_options(mode, expired, false).await
    }
    async fn with_options(mode: u8, expired: bool, pipeline: bool) -> Self {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["resolver.test".into()]).unwrap();
        if expired {
            params.not_after = rcgen::date_time_ymd(2020, 1, 1);
        }
        let cert = params.self_signed(&key).unwrap();
        let config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let queries = Arc::new(AtomicUsize::new(0));
        let mode = Arc::new(AtomicU8::new(mode));
        let replies = Arc::new(AtomicUsize::new(0));
        let inflight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let (pinned, _) = tokio::sync::watch::channel(None);
        let (pin_release, _) = tokio::sync::watch::channel(true);
        let task = {
            let (accepted, active, queries, mode) = (
                accepted.clone(),
                active.clone(),
                queries.clone(),
                mode.clone(),
            );
            let replies = replies.clone();
            let inflight = inflight.clone();
            let peak = peak.clone();
            let pinned = pinned.clone();
            let pin_release = pin_release.clone();
            tokio::spawn(async move {
                let mut tasks = JoinSet::new();
                loop {
                    tokio::select! {
                        Ok((socket, _)) = listener.accept() => {
                            accepted.fetch_add(1, Ordering::SeqCst);
                            active.fetch_add(1, Ordering::SeqCst);
                            let (acceptor, active, queries, mode) = (acceptor.clone(), active.clone(), queries.clone(), mode.clone());
                            let replies = replies.clone();
                            let inflight = inflight.clone();
                            let peak = peak.clone();
                            let pinned = pinned.clone();
                            let pin_release = pin_release.clone();
                            tasks.spawn(async move {
                                let _active = Active(active);
                                if mode.load(Ordering::SeqCst) == 6 {
                                    tokio::time::sleep(Duration::from_secs(5)).await;
                                    return;
                                }
                                socket.set_nodelay(true).unwrap();
                                let Ok(mut tls) = acceptor.accept(socket).await else { return };
                                if pipeline || mode.load(Ordering::SeqCst) >= 10 {
                                    pipelined(tls, [queries, replies, inflight, peak], mode, pinned, pin_release).await;
                                    return;
                                }
                                while let Ok(len) = tls.read_u16().await {
                                    let mut bytes = vec![0; len as usize];
                                    if tls.read_exact(&mut bytes).await.is_err() { break }
                                    let request = Message::from_vec(&bytes).unwrap();
                                    if request.queries[0].name().iter().next().is_some_and(|label| label.starts_with(b"retired-")) {
                                        pinned.send_replace(Some(request.queries[0].name().to_ascii()));
                                        let mut release = pin_release.subscribe();
                                        while !*release.borrow_and_update() {
                                            if release.changed().await.is_err() { return }
                                        }
                                    }
                                    queries.fetch_add(1, Ordering::SeqCst);
                                    let mode = mode.load(Ordering::SeqCst);
                                    if mode == 8 { tokio::time::sleep(Duration::from_millis(10)).await; }
                                    if mode == 2 {
                                        tokio::select! {
                                            _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                                            _ = async { while tls.read_u8().await.is_ok() {} } => return,
                                        }
                                    }
                                    if mode == 9 { break }
                                    if mode == 5 { let _ = tls.write_u16(1).await; let _ = tls.flush().await; break }
                                    if mode == 7 {
                                        let _ = tls.write_u16(12).await; let _ = tls.write_all(&[255;12]).await; let _ = tls.flush().await; break
                                    }
                                    let mut response = request.into_response();
                                    response.add_answer(Record::from_rdata(response.queries[0].name().clone(), 60,
                                        RData::A(A("192.0.2.1".parse().unwrap()))));
                                    if mode == 3 { response.metadata.id = response.metadata.id.wrapping_add(1); }
                                    if mode == 4 { response.metadata.truncation = true; }
                                    let bytes = response.to_vec().unwrap();
                                    if tls.write_u16(bytes.len() as u16).await.is_err() || tls.write_all(&bytes).await.is_err() || tls.flush().await.is_err() { break }
                                    if mode == 1 { let _ = tls.shutdown().await; break }
                                }
                            });
                        }
                        Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
                    }
                }
            })
        };
        Self {
            address,
            transport: UpstreamTransport::Tls {
                server_name: "resolver.test".into(),
                ca_pem: Some(cert.pem()),
                max_connections: 2,
            },
            accepted,
            active,
            queries,
            replies,
            inflight,
            peak,
            mode,
            pinned,
            pin_release,
            task,
        }
    }
    pub async fn wait_queries(&self, n: usize) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while self.queries.load(Ordering::SeqCst) < n {
                tokio::time::sleep(Duration::from_millis(1)).await
            }
        })
        .await
        .unwrap();
    }
    pub async fn wait_closed(&self) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while self.active.load(Ordering::SeqCst) != 0 {
                tokio::time::sleep(Duration::from_millis(1)).await
            }
        })
        .await
        .unwrap();
    }
}
impl Drop for Mock {
    fn drop(&mut self) {
        self.task.abort();
    }
}

// Concurrent fixture: 10 delays replies independently; 11 holds slow-* names;
// 12/13/14 hold all replies, then close/send an unknown ID/send malformed DNS.
async fn pipelined(
    tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    [queries, replies, inflight, peak]: [Arc<AtomicUsize>; 4],
    mode: Arc<AtomicU8>,
    pinned: tokio::sync::watch::Sender<Option<String>>,
    release: tokio::sync::watch::Sender<bool>,
) {
    let (mut reader, mut writer) = tokio::io::split(tls);
    let (send, mut receive) = tokio::sync::mpsc::channel(16);
    let read = async {
        while let Ok(len) = reader.read_u16().await {
            let mut bytes = vec![0; usize::from(len)];
            if reader.read_exact(&mut bytes).await.is_err() {
                return;
            }
            let query = Message::from_vec(&bytes).unwrap();
            if send.send(query).await.is_err() {
                return;
            }
        }
    };
    let write = async {
        let mut tasks = JoinSet::new();
        let mut ids = std::collections::HashSet::new();
        loop {
            tokio::select! {
                Some(query) = receive.recv(), if tasks.len() < 16 => {
                    assert!(ids.insert(query.metadata.id), "simultaneous duplicate DoT ID");
                    queries.fetch_add(1, Ordering::SeqCst);
                    peak.fetch_max(inflight.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
                    let active = Active(inflight.clone());
                    let current = mode.load(Ordering::SeqCst);
                    let pinned = pinned.clone();
                    let mut release = release.subscribe();
                    tasks.spawn(async move {
                        let _active = active;
                        let name = query.queries[0].name().to_ascii();
                        let retired = name.starts_with("retired-");
                        if retired { pinned.send_replace(Some(name.clone())); }
                        if retired || current >= 12 || (current == 11 && query.queries[0].name().to_ascii().starts_with("slow-")) {
                            while !*release.borrow_and_update() { if release.changed().await.is_err() { break; } }
                        }
                        if current == 2 { tokio::time::sleep(Duration::from_secs(5)).await; }
                        if current == 8 || current == 10 || (current == 11 && !query.queries[0].name().to_ascii().starts_with("slow-")) { tokio::time::sleep(Duration::from_millis(10)).await; }
                        let mut response = query.into_response();
                        response.add_answer(Record::from_rdata(response.queries[0].name().clone(), 60,
                            RData::A(A("192.0.2.1".parse().unwrap()))));
                        if current == 3 { response.metadata.id = response.metadata.id.wrapping_add(1); }
                        if current == 4 { response.metadata.truncation = true; }
                        (response, current)
                    });
                }
                Some(Ok((mut response, current))) = tasks.join_next(), if !tasks.is_empty() => {
                    ids.remove(&response.metadata.id);
                    if matches!(current, 9 | 12) { return; }
                    if current == 13 { response.metadata.id = response.metadata.id.wrapping_add(1000); }
                    let bytes = if current == 5 { vec![0] } else if matches!(current,7 | 14) { vec![255;12] } else { response.to_vec().unwrap() };
                    if writer.write_u16(bytes.len() as u16).await.is_err()
                        || writer.write_all(&bytes).await.is_err()
                        || writer.flush().await.is_err() { return; }
                    replies.fetch_add(1, Ordering::SeqCst);
                    if current == 1 { let _ = writer.shutdown().await; return; }
                }
            }
        }
    };
    tokio::select! { _ = read => {}, _ = write => {} }
}
