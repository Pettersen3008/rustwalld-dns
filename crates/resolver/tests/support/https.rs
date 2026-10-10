#![allow(clippy::unwrap_used, dead_code)]
use bytes::Bytes;
use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{
        Name, RData, Record,
        rdata::{A, SOA},
    },
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
    /// Most requests the server was processing at once, across connections.
    pub peak: Arc<AtomicUsize>,
    pub mode: Arc<AtomicU8>,
    pub disconnect: tokio::sync::watch::Sender<u64>,
    pub pinned: tokio::sync::watch::Sender<Option<String>>,
    pub pin_release: tokio::sync::watch::Sender<bool>,
    task: JoinHandle<()>,
}
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
    pub async fn with_expiry(mode: u8, expired: bool) -> Self {
        Self::configured(mode, expired, 1).await
    }
    /// A server advertising `streams` concurrent HTTP/2 streams per connection.
    #[allow(dead_code)]
    pub async fn with_streams(mode: u8, streams: u32) -> Self {
        Self::configured(mode, false, streams).await
    }
    async fn configured(mode: u8, expired: bool, streams: u32) -> Self {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["resolver.test".into()]).unwrap();
        if expired {
            params.not_after = rcgen::date_time_ymd(2020, 1, 1);
        }
        let cert = params.self_signed(&key).unwrap();
        let mut config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
            .unwrap();
        if mode != 15 {
            config.alpn_protocols = vec![b"h2".to_vec()];
        }
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let queries = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let inflight = Arc::new(AtomicUsize::new(0));
        let mode = Arc::new(AtomicU8::new(mode));
        let (disconnect, _) = tokio::sync::watch::channel(0);
        let (pinned, _) = tokio::sync::watch::channel(None);
        let (pin_release, _) = tokio::sync::watch::channel(true);
        let task = {
            let (accepted, active, queries, mode) = (
                accepted.clone(),
                active.clone(),
                queries.clone(),
                mode.clone(),
            );
            let (peak, inflight) = (peak.clone(), inflight.clone());
            let disconnect = disconnect.clone();
            let pinned = pinned.clone();
            let pin_release = pin_release.clone();
            tokio::spawn(async move {
                let mut connections = JoinSet::new();
                loop {
                    tokio::select! {
                        Ok((socket,_)) = listener.accept() => {
                            accepted.fetch_add(1, Ordering::SeqCst); active.fetch_add(1, Ordering::SeqCst);
                            let (acceptor, active, queries, mode) = (acceptor.clone(), active.clone(), queries.clone(), mode.clone());
                            let (peak, inflight) = (peak.clone(), inflight.clone());
                            let mut disconnect = disconnect.subscribe();
                            let pinned = pinned.clone();
                            let pin_release = pin_release.clone();
                            connections.spawn(async move {
                                let _active = Active(active);
                                if mode.load(Ordering::SeqCst) == 16 { tokio::time::sleep(Duration::from_secs(5)).await; return }
                                socket.set_nodelay(true).unwrap();
                                let Ok(tls) = acceptor.accept(socket).await else { return };
                                let Ok(mut connection) = h2::server::Builder::new().max_concurrent_streams(streams).handshake(tls).await else { return };
                                let mut requests = JoinSet::new();
                                loop {
                                    tokio::select! {
                                        _ = disconnect.changed() => break,
                                        request = connection.accept() => {
                                            let Some(Ok((mut request, mut respond))) = request else { break };
                                            let (queries, mode) = (queries.clone(), mode.clone());
                                            let (inflight, peak) = (inflight.clone(), peak.clone());
                                            let pinned = pinned.clone();
                                            let pin_release = pin_release.clone();
                                            requests.spawn(async move {
                                                assert_eq!(request.method(), "POST");
                                                assert_eq!(request.uri().path(), "/dns-query");
                                                assert!(request.uri().authority().unwrap().as_str().starts_with("resolver.test:"));
                                                assert_eq!(request.headers()[http::header::CONTENT_TYPE], "application/dns-message");
                                                assert_eq!(request.headers()[http::header::ACCEPT], "application/dns-message");
                                                let mut bytes = vec![];
                                                while let Some(data) = request.body_mut().data().await {
                                                    let Ok(data) = data else { return };
                                                    bytes.extend_from_slice(&data);
                                                    request.body_mut().flow_control().release_capacity(data.len()).unwrap();
                                                }
                                                let Ok(query) = Message::from_vec(&bytes) else { return };
                                                if query.queries[0].name().iter().next().is_some_and(|label| label.starts_with(b"retired-")) {
                                                    pinned.send_replace(Some(query.queries[0].name().to_ascii()));
                                                    let mut release = pin_release.subscribe();
                                                    while !*release.borrow_and_update() {
                                                        if release.changed().await.is_err() { return }
                                                    }
                                                }
                                                assert_eq!(query.metadata.id, 0);
                                                let served = queries.fetch_add(1, Ordering::SeqCst);
                                                let _inflight = Active(inflight.clone());
                                                peak.fetch_max(inflight.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
                                                let mode = mode.load(Ordering::SeqCst);
                                                // Refuse the first request only; it was never processed.
                                                if mode == 23 && served == 0 { respond.send_reset(h2::Reason::REFUSED_STREAM); return; }
                                                if mode == 22 { respond.send_reset(h2::Reason::INTERNAL_ERROR); return; }
                                                if mode == 9 { tokio::time::sleep(Duration::from_secs(5)).await; }
                                                if mode == 17 { tokio::time::sleep(Duration::from_millis(10)).await; }
                                                let mut answer = query.into_response();
                                                if matches!(mode,20|21) {
                                                    if mode == 20 { answer.metadata.response_code = ResponseCode::NXDomain; }
                                                    answer.add_authority(Record::from_rdata(Name::from_ascii("test.").unwrap(), 60, RData::SOA(SOA::new(Name::from_ascii("ns.test.").unwrap(), Name::from_ascii("hostmaster.test.").unwrap(), 1, 60, 60, 60, 30))));
                                                } else {
                                                    answer.add_answer(Record::from_rdata(answer.queries[0].name().clone(), 60, RData::A(A("192.0.2.1".parse().unwrap()))));
                                                }
                                                if mode == 11 { answer.queries[0].set_name(Name::from_ascii("wrong.test.").unwrap()); }
                                                if mode == 13 { answer.metadata.truncation = true; }
                                                if mode == 14 { answer.metadata.id = 12; }
                                                let bytes = if mode == 12 { vec![255;12] } else if matches!(mode,6|7) { vec![0;65536] } else { answer.to_vec().unwrap() };
                                                let mut response = http::Response::builder().status(if mode == 1 {503} else if mode == 2 {302} else {200})
                                                    .header(http::header::CONTENT_TYPE, if mode == 3 {"application/json"} else {"application/dns-message"});
                                                if mode != 7 { response = response.header(http::header::CONTENT_LENGTH, bytes.len()); }
                                                if mode == 2 { response = response.header(http::header::LOCATION,"https://redirect.test/dns-query"); }
                                                if mode == 4 { response = response.header(http::header::CONTENT_ENCODING,"gzip"); }
                                                if matches!(mode,5|20|21) { response = response.header(http::header::AGE,"10"); }
                                                if mode == 19 { response = response.header(http::header::AGE,"invalid"); }
                                                if mode == 8 { response = response.header("large-header", "x".repeat(20000)); }
                                                let Ok(mut stream) = respond.send_response(response.body(()).unwrap(), false) else { return };
                                                if mode == 10 { tokio::time::sleep(Duration::from_secs(5)).await; }
                                                let _ = stream.send_data(Bytes::from(bytes), true);
                                            });
                                        }
                                        Some(_) = requests.join_next(), if !requests.is_empty() => {}
                                    }
                                }
                            });
                        }
                        Some(_) = connections.join_next(), if !connections.is_empty() => {}
                    }
                }
            })
        };
        Self {
            address,
            transport: UpstreamTransport::Https {
                server_name: "resolver.test".into(),
                path: "/dns-query".into(),
                ca_pem: Some(cert.pem()),
                max_connections: 2,
            },
            accepted,
            active,
            queries,
            peak,
            mode,
            disconnect,
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
