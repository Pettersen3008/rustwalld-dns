//! Bounded authenticated HTTP/2 DoH. Only upstream DNS HTTP belongs here.
use crate::{FailureKind, ResolveError, UpstreamTransport, tls, validate};
use bytes::Bytes;
use hickory_proto::{
    op::{Message, ResponseCode},
    rr::RData,
    serialize::binary::{BinDecodable, BinDecoder},
};
use http::{HeaderMap, Request, StatusCode, Uri, header};
use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    net::TcpStream,
    sync::{Notify, OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
};
use tokio_rustls::{TlsConnector, client::TlsStream, rustls::pki_types::ServerName};
/// Largest DNS message, also the HTTP/2 flow-control window per stream.
const DNS_WINDOW: u32 = 65_535;
const DNS_LIMIT: usize = DNS_WINDOW as usize;
/// Concurrent DNS requests multiplexed on one connection (fewer when the
/// server advertises a lower `SETTINGS_MAX_CONCURRENT_STREAMS`).
const STREAMS_PER_CONNECTION: usize = 8;
/// A connection without requests for this long is closed.
const IDLE_LIMIT: Duration = Duration::from_secs(60);
/// Waiters recheck capacity at least this often, so a release that races a
/// cancelled connection attempt delays a request briefly instead of stranding it.
const RECHECK: Duration = Duration::from_millis(25);

pub(super) fn compile(
    addresses: &[SocketAddr],
    transport: &UpstreamTransport,
) -> Result<Vec<Arc<HttpsPool>>, ResolveError> {
    let UpstreamTransport::Https {
        server_name,
        path,
        ca_pem,
        max_connections,
    } = transport
    else {
        return Ok(vec![]);
    };
    let invalid = |reason: &str| ResolveError::Configuration(reason.into());
    if !(1..=8).contains(max_connections) {
        return Err(invalid(
            "HTTPS pool must contain 1..=8 connections per address",
        ));
    }
    if path.len() > 2048
        || !path.starts_with('/')
        || path.starts_with("//")
        || !path.is_ascii()
        || path.contains('#')
        || path
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err(invalid(
            "HTTPS path must be an ASCII absolute path/query of at most 2048 bytes",
        ));
    }
    let (name, config) = tls::client_config(server_name, ca_pem, vec![b"h2".to_vec()])?;
    let connector = TlsConnector::from(config);
    addresses
        .iter()
        .map(|address| {
            let uri: Uri = format!("https://{server_name}:{}{path}", address.port())
                .parse()
                .map_err(|_| invalid("invalid HTTPS endpoint"))?;
            Ok(Arc::new(HttpsPool {
                address: *address,
                name: name.clone(),
                connector: connector.clone(),
                uri,
                connections: Mutex::new(vec![]),
                capacity: Arc::new(Notify::new()),
                requests: Arc::new(Semaphore::new(*max_connections * STREAMS_PER_CONNECTION)),
                physical: Arc::new(Semaphore::new(*max_connections)),
            }))
        })
        .collect()
}

/// Bounded HTTP/2 connections to one address. Each connection carries up to
/// [`STREAMS_PER_CONNECTION`] concurrent requests; streams are independent, so
/// a cancelled or failed request resets only its own stream.
pub(super) struct HttpsPool {
    address: SocketAddr,
    name: ServerName<'static>,
    connector: TlsConnector,
    uri: Uri,
    connections: Mutex<Vec<Arc<Connection>>>,
    /// Signalled when stream or connection capacity may have become free.
    capacity: Arc<Notify>,
    requests: Arc<Semaphore>,
    physical: Arc<Semaphore>,
}
impl std::fmt::Debug for HttpsPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpsPool")
            .field("uri", &self.uri)
            .finish_non_exhaustive()
    }
}
struct Connection {
    sender: h2::client::SendRequest<Bytes>,
    driver: JoinHandle<()>,
    /// Requests currently using this connection.
    streams: AtomicUsize,
    last_used: Mutex<Instant>,
    /// A request was abandoned without an answer (deadline or failure). The
    /// server may be stuck on this connection, so new requests avoid it; its
    /// remaining streams finish and the socket closes after them.
    suspect: AtomicBool,
}
impl Connection {
    fn retired(&self, now: Instant) -> bool {
        self.driver.is_finished()
            || self.suspect.load(Ordering::Acquire)
            || (self.streams.load(Ordering::Acquire) == 0
                && now.saturating_duration_since(*lock(&self.last_used)) >= IDLE_LIMIT)
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.driver.abort();
    }
}
/// One request's claim on a connection's stream capacity.
struct Stream {
    connection: Arc<Connection>,
    capacity: Arc<Notify>,
    answered: bool,
}
impl Drop for Stream {
    fn drop(&mut self) {
        if !self.answered {
            self.connection.suspect.store(true, Ordering::Release);
        }
        *lock(&self.connection.last_used) = Instant::now();
        self.connection.streams.fetch_sub(1, Ordering::AcqRel);
        self.capacity.notify_one();
    }
}
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}
/// Owned by a connection's driver task, including when that task is cancelled
/// before its first poll. TLS disposal precedes releasing the physical slot,
/// which precedes waking a replacement owner.
struct PhysicalConnection {
    connection: Option<h2::client::Connection<TlsStream<TcpStream>, Bytes>>,
    permit: Option<OwnedSemaphorePermit>,
    capacity: Arc<Notify>,
}
impl Drop for PhysicalConnection {
    fn drop(&mut self) {
        drop(self.connection.take());
        drop(self.permit.take());
        self.capacity.notify_waiters();
    }
}
impl HttpsPool {
    /// Open a connection with an already reserved physical slot.
    async fn connect(&self, physical: OwnedSemaphorePermit) -> Result<Connection, ResolveError> {
        let socket = TcpStream::connect(self.address).await?;
        socket.set_nodelay(true)?;
        let stream = self.connector.connect(self.name.clone(), socket).await?;
        if stream.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
            return Err(ResolveError::Failure(FailureKind::TlsProtocol));
        }
        let (sender, connection) = h2::client::Builder::new()
            .initial_window_size(DNS_WINDOW)
            // Every stream may have a full DNS message in flight.
            .initial_connection_window_size(
                DNS_WINDOW.saturating_mul(u32::try_from(STREAMS_PER_CONNECTION).unwrap_or(1)),
            )
            .max_frame_size(16384)
            .max_header_list_size(16384)
            .header_table_size(4096)
            .max_concurrent_streams(0) // no server-initiated streams
            // Until the server's SETTINGS arrive, open one stream at a time;
            // h2 then adopts the advertised limit (capped by our stream claims).
            .initial_max_send_streams(1)
            .max_concurrent_reset_streams(8)
            .max_send_buffer_size(DNS_LIMIT)
            .enable_push(false)
            .handshake(stream)
            .await?;
        // This permit lives in the driver, so replacement must wait for a
        // cancelled driver's actual socket disposal, not just its caller.
        let owned = PhysicalConnection {
            connection: Some(connection),
            permit: Some(physical),
            capacity: self.capacity.clone(),
        };
        let driver = tokio::spawn(async move {
            // Move the complete guard, avoiding disjoint field captures.
            let mut owned = owned;
            if let Some(connection) = owned.connection.as_mut() {
                let _ = connection.await;
            }
        });
        Ok(Connection {
            sender,
            driver,
            streams: AtomicUsize::new(0),
            last_used: Mutex::new(Instant::now()),
            suspect: AtomicBool::new(false),
        })
    }
    /// Remove retired connections from the pool. Each closes once its last
    /// in-flight stream ends; the caller drops them outside the lock.
    fn prune(pool: &mut Vec<Arc<Connection>>) -> Vec<Arc<Connection>> {
        let now = Instant::now();
        let mut retired = Vec::new();
        pool.retain(|connection| {
            let keep = !connection.retired(now);
            if !keep {
                retired.push(connection.clone());
            }
            keep
        });
        retired
    }
    /// Claim a stream on the least-loaded live connection, if one has room.
    fn checkout(&self) -> Option<Stream> {
        let (stream, retired) = {
            let mut pool = lock(&self.connections);
            let retired = Self::prune(&mut pool);
            let stream = pool
                .iter()
                .filter(|c| c.streams.load(Ordering::Acquire) < STREAMS_PER_CONNECTION)
                .min_by_key(|c| c.streams.load(Ordering::Acquire))
                .map(|connection| {
                    connection.streams.fetch_add(1, Ordering::AcqRel);
                    Stream {
                        connection: connection.clone(),
                        capacity: self.capacity.clone(),
                        answered: false,
                    }
                });
            (stream, retired)
        };
        // Close retired connections outside the lock.
        drop(retired);
        stream
    }
    /// Open a new connection and claim its first stream.
    async fn open(&self, physical: OwnedSemaphorePermit) -> Result<Stream, ResolveError> {
        let connection = match self.connect(physical).await {
            Ok(connection) => Arc::new(connection),
            Err(error) => {
                // The slot was released with the failed attempt.
                self.capacity.notify_waiters();
                return Err(error);
            }
        };
        connection.streams.fetch_add(1, Ordering::AcqRel);
        lock(&self.connections).push(connection.clone());
        // Others may now share the new connection.
        self.capacity.notify_waiters();
        Ok(Stream {
            connection,
            capacity: self.capacity.clone(),
            answered: false,
        })
    }
    /// A stream on a shared connection, opening a connection while the
    /// physical cap allows. Returns whether the connection was reused.
    async fn stream(&self) -> Result<(Stream, bool), ResolveError> {
        loop {
            let notified = self.capacity.notified();
            tokio::pin!(notified);
            // Register before checking, so a release cannot be missed.
            notified.as_mut().enable();
            if let Some(stream) = self.checkout() {
                return Ok((stream, true));
            }
            if let Ok(physical) = self.physical.clone().try_acquire_owned() {
                return Ok((self.open(physical).await?, false));
            }
            let _ = tokio::time::timeout(RECHECK, notified).await;
        }
    }
    /// A physical slot for a fresh connection, waiting for one to close.
    async fn physical_slot(&self) -> OwnedSemaphorePermit {
        loop {
            let notified = self.capacity.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let retired = Self::prune(&mut lock(&self.connections));
            drop(retired);
            if let Ok(physical) = self.physical.clone().try_acquire_owned() {
                return physical;
            }
            let _ = tokio::time::timeout(RECHECK, notified).await;
        }
    }
    pub async fn exchange(&self, request: &Message) -> Result<Message, ResolveError> {
        // Bounds this address's concurrent requests to its stream capacity.
        let _request = self
            .requests
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| ResolveError::Unavailable)?;
        let mut query = request.clone();
        query.metadata.id = 0; // HTTP stream correlates each response (RFC 8484).
        let bytes = Bytes::from(query.to_vec().map_err(|_| ResolveError::Encoding)?);
        if bytes.len() > DNS_LIMIT {
            return Err(ResolveError::Encoding);
        }
        let (mut stream, reused) = self.stream().await?;
        let result = post(&stream.connection.sender, &self.uri, &query, bytes.clone()).await;
        let (refused, stale) = match &result {
            Err(ResolveError::Http2(crate::Http2Error(error))) => (
                error.reason() == Some(h2::Reason::REFUSED_STREAM),
                reused
                    && (error.is_io()
                        || (error.is_go_away() && error.reason() == Some(h2::Reason::NO_ERROR))),
            ),
            _ => (false, false),
        };
        // Any HTTP-level answer means the connection works; so does a refused
        // stream, which only reports the server's concurrency limit.
        stream.answered = refused || !transport_failure(&result);
        if !refused && !stale {
            return result;
        }
        drop(stream);
        // Retry once, within the original deadline. A refused stream was never
        // processed (RFC 9113 section 8.7) and may share another connection; a
        // stale reused connection is replaced. Invalid DNS content is never
        // retried.
        let mut stream = if refused {
            self.stream().await?.0
        } else {
            self.open(self.physical_slot().await).await?
        };
        let result = post(&stream.connection.sender, &self.uri, &query, bytes).await;
        stream.answered = !transport_failure(&result);
        result
    }
}
/// Whether a request failed below HTTP (connection, TLS or HTTP/2 framing).
fn transport_failure(result: &Result<Message, ResolveError>) -> bool {
    matches!(result, Err(ResolveError::Http2(_) | ResolveError::Io(_)))
}
async fn post(
    sender: &h2::client::SendRequest<Bytes>,
    uri: &Uri,
    query: &Message,
    bytes: Bytes,
) -> Result<Message, ResolveError> {
    // Each request uses its own handle, which waits for a free stream slot.
    let mut sender = sender.clone();
    std::future::poll_fn(|cx| sender.poll_ready(cx)).await?;
    let request = Request::builder()
        .method("POST")
        .uri(uri.clone())
        .header(header::CONTENT_TYPE, "application/dns-message")
        .header(header::ACCEPT, "application/dns-message")
        .header(header::CONTENT_LENGTH, bytes.len())
        .body(())
        .map_err(|_| ResolveError::Encoding)?;
    let (response, mut send) = sender.send_request(request, false)?;
    send.send_data(bytes, true)?;
    let mut response = response.await?;
    check_headers(response.status(), response.headers())?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.body_mut().data().await {
        let chunk = chunk?;
        if bytes.len().saturating_add(chunk.len()) > DNS_LIMIT {
            return Err(ResolveError::Failure(FailureKind::HttpEnvelope));
        }
        bytes.extend_from_slice(&chunk);
        response
            .body_mut()
            .flow_control()
            .release_capacity(chunk.len())?;
    }
    // Consume optional trailers within h2's header limit; they do not override
    // the initial envelope or TTL metadata.
    let _ = response.body_mut().trailers().await?;
    decode_response(query, response.status(), response.headers(), &bytes)
}
fn one_header(headers: &HeaderMap, key: header::HeaderName) -> Result<Option<&str>, ResolveError> {
    let mut values = headers.get_all(key).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(ResolveError::Failure(FailureKind::HttpEnvelope));
    }
    first
        .map(|value| {
            value
                .to_str()
                .map_err(|_| ResolveError::Failure(FailureKind::HttpEnvelope))
        })
        .transpose()
}
fn decimal(value: &str) -> Result<u32, ResolveError> {
    let value = value.trim();
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ResolveError::Failure(FailureKind::HttpEnvelope));
    }
    // RFC 9111 delta-seconds overflow must saturate. For Age this expires
    // every DNS TTL; for Content-Length it still exceeds the explicit body cap.
    Ok(value.bytes().fold(0_u32, |n, b| {
        n.saturating_mul(10).saturating_add(u32::from(b - b'0'))
    }))
}
fn check_headers(
    status: StatusCode,
    headers: &HeaderMap,
) -> Result<(u32, Option<usize>), ResolveError> {
    if !status.is_success() {
        return Err(ResolveError::Failure(FailureKind::HttpStatus));
    }
    if !one_header(headers, header::CONTENT_TYPE)?
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/dns-message"))
    {
        return Err(ResolveError::Failure(FailureKind::HttpEnvelope));
    }
    if one_header(headers, header::CONTENT_ENCODING)?
        .is_some_and(|v| !v.trim().eq_ignore_ascii_case("identity"))
    {
        return Err(ResolveError::Failure(FailureKind::HttpEnvelope));
    }
    let age = one_header(headers, header::AGE)?
        .map(decimal)
        .transpose()?
        .unwrap_or(0);
    let length = one_header(headers, header::CONTENT_LENGTH)?
        .map(decimal)
        .transpose()?
        .map(|len| len as usize);
    if length.is_some_and(|len| !(12..=DNS_LIMIT).contains(&len)) {
        return Err(ResolveError::Failure(FailureKind::HttpEnvelope));
    }
    Ok((age, length))
}
/// Pure bounded HTTP/DNS envelope decoding, also exposed to the fuzz harness.
/// Network callers enforce h2's 16 KiB header bound before reaching this function.
pub fn decode_response(
    query: &Message,
    status: StatusCode,
    headers: &HeaderMap,
    bytes: &[u8],
) -> Result<Message, ResolveError> {
    let (age, length) = check_headers(status, headers)?;
    if !(12..=DNS_LIMIT).contains(&bytes.len()) || length.is_some_and(|len| len != bytes.len()) {
        return Err(ResolveError::Failure(FailureKind::HttpEnvelope));
    }
    let mut decoder = BinDecoder::new(bytes);
    let mut response = Message::read(&mut decoder).map_err(|_| ResolveError::InvalidResponse)?;
    if !decoder.is_empty() {
        return Err(ResolveError::InvalidResponse);
    }
    validate(query, &response)?;
    if response.metadata.truncation {
        return Err(ResolveError::InvalidResponse);
    }
    // RFC 2308 negative lifetime is min(SOA TTL, MINIMUM); clamp before Age so
    // a smaller MINIMUM cannot accidentally regain lifetime in the DNS cache.
    if response.metadata.response_code == ResponseCode::NXDomain || response.answers.is_empty() {
        for record in &mut response.authorities {
            if let RData::SOA(soa) = &record.data {
                record.ttl = record.ttl.min(soa.minimum);
            }
        }
    }
    for record in response
        .answers
        .iter_mut()
        .chain(&mut response.authorities)
        .chain(&mut response.additionals)
    {
        record.ttl = record.ttl.saturating_sub(age);
    }
    Ok(response)
}
