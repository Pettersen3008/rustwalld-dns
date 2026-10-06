#![allow(clippy::unwrap_used)]
use policy::FilterSource;
use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
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

#[derive(Clone)]
pub struct Conditional {
    pub text: String,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub not_modified_headers: Option<String>,
    pub delay: std::time::Duration,
}
pub struct Fixture {
    pub address: SocketAddr,
    pub ca: String,
    pub requests: Arc<AtomicUsize>,
    pub open: Arc<AtomicUsize>,
    #[allow(dead_code)] // The stalled-I/O resilience example uses only the other fixture routes.
    pub conditional: Arc<Mutex<Conditional>>,
    #[allow(dead_code)] // Shared with examples that do not exercise conditional retrieval.
    pub conditional_requests: Arc<Mutex<Vec<String>>>,
    task: JoinHandle<()>,
}
struct Connection(Arc<AtomicUsize>);
impl Drop for Connection {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Fixture {
    pub async fn start() -> Self {
        Self::with_expiry(false).await
    }
    pub async fn with_expiry(expired: bool) -> Self {
        let signing_key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["lists.test".into()]).unwrap();
        if expired {
            params.not_after = rcgen::date_time_ymd(2020, 1, 1);
        }
        let cert = params.self_signed(&signing_key).unwrap();
        let tls = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let open = Arc::new(AtomicUsize::new(0));
        let conditional = Arc::new(Mutex::new(Conditional {
            text: "ads.test".into(),
            etag: Some("\"v1\"".into()),
            last_modified: Some("Sun, 06 Nov 1994 08:49:37 GMT".into()),
            not_modified_headers: None,
            delay: std::time::Duration::ZERO,
        }));
        let conditional_requests = Arc::new(Mutex::new(Vec::new()));
        let publisher = conditional.clone();
        let recorded = conditional_requests.clone();
        let count = requests.clone();
        let connections = open.clone();
        let task = tokio::spawn(async move {
            let mut children = JoinSet::new();
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        let (socket, _) = result.unwrap();
                        let acceptor = acceptor.clone(); let count = count.clone(); let open = connections.clone();
                        let publisher = publisher.clone(); let recorded = recorded.clone();
                        open.fetch_add(1, Ordering::SeqCst);
                        children.spawn(async move {
                            let _connection = Connection(open);
                            let Ok(mut stream) = acceptor.accept(socket).await else {return};
                            let mut request = Vec::new(); let mut byte = [0; 1];
                            while request.len() < 4096 && !request.ends_with(b"\r\n\r\n") {
                                if stream.read_exact(&mut byte).await.is_err() {return}; request.push(byte[0]);
                            }
                            let text = String::from_utf8(request).unwrap();
                            assert!(text.contains("Host: lists.test:") || text.contains("host: lists.test:"));
                            assert!(!text.to_lowercase().contains("authorization:"));
                            let path = text.split_whitespace().nth(1).unwrap();
                            count.fetch_add(1, Ordering::SeqCst);
                            if path == "/conditional" {
                                let publisher = publisher.lock().unwrap().clone();
                                { let mut records = recorded.lock().unwrap(); if records.len() < 128 {records.push(text.clone());} }
                                let field = |name: &str| text.lines().filter_map(|line|line.split_once(':'))
                                    .find(|(key,_)|key.eq_ignore_ascii_case(name)).map(|(_,value)|value.trim());
                                let unchanged = if let Some(tag) = field("if-none-match") {
                                    publisher.etag.as_ref().is_some_and(|current| tag.strip_prefix("W/").unwrap_or(tag) == current.strip_prefix("W/").unwrap_or(current))
                                } else { field("if-modified-since").zip(publisher.last_modified.as_deref()).is_some_and(|(since,date)|
                                    httpdate::parse_http_date(since).ok().zip(httpdate::parse_http_date(date).ok()).is_some_and(|(a,b)|a>=b)) };
                                let hints = format!("{}{}", publisher.etag.as_ref().map_or(String::new(), |v|format!("ETag: {v}\r\n")),
                                    publisher.last_modified.as_ref().map_or(String::new(), |v|format!("Last-Modified: {v}\r\n")));
                                tokio::time::sleep(publisher.delay).await;
                                let raw = if unchanged {format!("HTTP/1.1 304 Not Modified\r\n{}Content-Length: {}\r\n\r\n",
                                    publisher.not_modified_headers.unwrap_or(hints), publisher.text.len()).into_bytes()}
                                else {format!("HTTP/1.1 200 OK\r\n{hints}Content-Length: {}\r\n\r\n{}", publisher.text.len(),publisher.text).into_bytes()};
                                let _ = stream.write_all(&raw).await; let _ = stream.shutdown().await; return;
                            }
                            if path == "/slow" || path == "/stall" {
                                if path == "/stall" {
                                    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n").await;
                                    let mut sink = [0; 1]; let _ = stream.read(&mut sink).await; return;
                                }
                                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                            }
                            let raw = match path {
                                "/redirect" => b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/private\r\nContent-Length: 0\r\n\r\n".to_vec(),
                                "/notmodified" => b"HTTP/1.1 304 Not Modified\r\n\r\n".to_vec(),
                                "/oversize" => b"HTTP/1.1 200 OK\r\nContent-Length: 8388609\r\n\r\n".to_vec(),
                                "/truncated" => b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort".to_vec(),
                                "/gzip" => b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 1\r\n\r\nx".to_vec(),
                                "/html" => b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1\r\n\r\nx".to_vec(),
                                "/trailers" => b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n9\r\nads.test\n\r\n0\r\nX-Test: yes\r\n\r\n".to_vec(),
                                "/chunked" => b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n9\r\nads.test\n\r\n0\r\n\r\n".to_vec(),
                                "/manyheaders" => format!("HTTP/1.1 200 OK\r\n{}Content-Length: 0\r\n\r\n", "X-Test: x\r\n".repeat(40)).into_bytes(),
                                "/hugeheaders" => format!("HTTP/1.1 200 OK\r\nX-Test: {}\r\nContent-Length: 0\r\n\r\n", "x".repeat(70000)).into_bytes(),
                                "/streambig" => {let body = "x".repeat(policy::MAX_DOWNLOAD_BYTES + 1); format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n", body.len(), body).into_bytes()},
                                path => {
                                    let body: &[u8] = match path {
                                        "/empty" => b"", "/comments" => b"! comment\n# comment\n", "/invalid" => b"bad..test\n",
                                        "/utf8" => &[255], "/assertfail" => b"safe.test\n", _ => b"ads.test\n=downloaded.test\nads.test\n",
                                    };
                                    let mut raw = format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes(); raw.extend_from_slice(body); raw
                                }
                            };
                            let _ = stream.write_all(&raw).await; let _ = stream.shutdown().await;
                        });
                    }
                    _ = children.join_next(), if !children.is_empty() => {}
                }
            }
        });
        Self {
            address,
            ca: cert.pem(),
            requests,
            open,
            task,
            conditional,
            conditional_requests,
        }
    }
    pub fn source(&self, path: &str) -> FilterSource {
        FilterSource {
            policy: "default".into(),
            list: "test".into(),
            url: format!("https://lists.test:{}{path}", self.address.port()),
            bootstrap_ips: vec![self.address.ip()],
            ca_pem: Some(self.ca.clone()),
            download: None,
            refresh_interval_secs: None,
        }
    }
    pub async fn wait_requests(&self, count: usize) {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while self.requests.load(Ordering::SeqCst) < count {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }
    pub async fn wait_closed(&self) {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while self.open.load(Ordering::SeqCst) != 0 {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }
}
