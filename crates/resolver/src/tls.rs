//! Strict DNS-over-TLS. Trust/identity are compiled before snapshot publication.
use crate::{FailureKind, ResolveError, tcp_frame, validate};
use hickory_proto::{
    op::{Message, MessageType},
    serialize::binary::{BinDecodable, BinDecoder},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot},
    task::JoinHandle,
};
use tokio_rustls::{
    TlsConnector,
    client::TlsStream,
    rustls::{
        ClientConfig, RootCertStore,
        crypto::ring,
        pki_types::{CertificateDer, ServerName, pem::PemObject},
    },
};

/// How a profile reaches its upstream addresses.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum UpstreamTransport {
    /// UDP with TCP fallback on a validated truncated response.
    #[default]
    Udp,
    /// Every address in the profile uses this authenticated DNS server identity.
    Tls {
        /// DNS name the server's certificate must present (no root dot).
        server_name: String,
        /// When present, replaces bundled public roots (private resolvers).
        #[serde(default)]
        ca_pem: Option<String>,
        /// Connections per address, 1..=8 (default 2).
        #[serde(default = "pool_size")]
        max_connections: usize,
    },
    /// Strict HTTP/2 DNS over HTTPS, POST wire format only.
    Https {
        /// DNS name the server's certificate must present (no root dot).
        server_name: String,
        /// Absolute request path and query (default `/dns-query`).
        #[serde(default = "doh_path")]
        path: String,
        /// When present, replaces bundled public roots (private resolvers).
        #[serde(default)]
        ca_pem: Option<String>,
        /// Connections per address, 1..=8 (default 2).
        #[serde(default = "pool_size")]
        max_connections: usize,
    },
}
fn doh_path() -> String {
    "/dns-query".into()
}
fn pool_size() -> usize {
    2
}
impl UpstreamTransport {
    /// Whether this is the default plain-DNS transport.
    pub fn is_udp(&self) -> bool {
        matches!(self, Self::Udp)
    }
}

pub(super) fn compile(
    addresses: &[SocketAddr],
    transport: &UpstreamTransport,
) -> Result<Vec<Arc<TlsPool>>, ResolveError> {
    let UpstreamTransport::Tls {
        server_name,
        ca_pem,
        max_connections,
    } = transport
    else {
        return Ok(vec![]);
    };
    let invalid = |reason: &str| ResolveError::Configuration(reason.into());
    if !(1..=8).contains(max_connections) {
        return Err(invalid(
            "TLS pool must contain 1..=8 connections per address",
        ));
    }
    let (name, config) = client_config(server_name, ca_pem, vec![])?;
    let connector = TlsConnector::from(config);
    Ok(addresses
        .iter()
        .map(|address| {
            Arc::new(TlsPool {
                address: *address,
                name: name.clone(),
                connector: connector.clone(),
                connections: Mutex::new(Vec::new()),
                capacity: Arc::new(Notify::new()),
                requests: Arc::new(Semaphore::new(*max_connections * PENDING_LIMIT)),
                physical: Arc::new(Semaphore::new(*max_connections)),
            })
        })
        .collect())
}

/// Trust/identity construction is control-plane work, shared by DoT and DoH.
pub(super) fn client_config(
    server_name: &str,
    ca_pem: &Option<String>,
    alpn: Vec<Vec<u8>>,
) -> Result<(ServerName<'static>, Arc<ClientConfig>), ResolveError> {
    let invalid = |reason: &str| ResolveError::Configuration(reason.into());
    // Require an explicit DNS authentication name, not an IP or implicit lookup.
    let name = ServerName::try_from(server_name.to_owned())
        .map_err(|_| invalid("invalid TLS server name"))?;
    if !matches!(name, ServerName::DnsName(_)) || server_name.ends_with('.') {
        return Err(invalid(
            "TLS server name must be a DNS name without a root dot",
        ));
    }
    let mut roots = RootCertStore::empty();
    if let Some(pem) = ca_pem {
        if pem.is_empty() || pem.len() > 65536 {
            return Err(invalid("TLS CA PEM must contain 1..=65536 bytes"));
        }
        let certs = CertificateDer::pem_slice_iter(pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid("invalid TLS CA PEM"))?;
        if certs.is_empty() || certs.len() > 32 {
            return Err(invalid("TLS CA PEM must contain 1..=32 certificates"));
        }
        for cert in certs {
            roots
                .add(cert)
                .map_err(|_| invalid("invalid TLS CA certificate"))?;
        }
    } else {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    let config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|_| invalid("TLS protocol configuration failed"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut config = config;
    config.alpn_protocols = alpn;
    Ok((name, Arc::new(config)))
}

/// Each connection pipelines at most eight pending requests. Physical permits
/// stay with the driver until both halves of its TLS socket have been dropped.
const PENDING_LIMIT: usize = 8;
const IDLE_LIMIT: Duration = Duration::from_secs(60);
const RECHECK: Duration = Duration::from_millis(25);

pub(super) struct TlsPool {
    address: SocketAddr,
    name: ServerName<'static>,
    connector: TlsConnector,
    connections: Mutex<Vec<Arc<Connection>>>,
    capacity: Arc<Notify>,
    requests: Arc<Semaphore>,
    physical: Arc<Semaphore>,
}
impl std::fmt::Debug for TlsPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsPool")
            .field("address", &self.address)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}
struct Waiter {
    request: Message,
    reply: oneshot::Sender<Result<Message, FailureKind>>,
}
struct Queries {
    pending: HashMap<u16, Waiter>,
    // IDs are never reused in a connection's lifetime. A bounded set distinguishes
    // cancelled queries' late replies from unsolicited or duplicate responses.
    cancelled: HashSet<u16>,
    first_id: u16,
    issued: u32,
    suspect: bool,
    closed: bool,
    last_used: Instant,
}
struct State {
    queries: Mutex<Queries>,
    capacity: Arc<Notify>,
    changed: Notify,
}
impl State {
    fn fail(&self, kind: FailureKind) {
        let pending = {
            let mut queries = lock(&self.queries);
            queries.closed = true;
            std::mem::take(&mut queries.pending)
        };
        for (_, waiter) in pending {
            let _ = waiter.reply.send(Err(kind));
        }
        self.capacity.notify_waiters();
    }
    async fn drained(&self) {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let drained = {
                let queries = lock(&self.queries);
                queries.suspect && queries.pending.is_empty()
            };
            if drained {
                return;
            }
            notified.await;
        }
    }
}
struct Frame {
    id: u16,
    bytes: Vec<u8>,
}
struct Connection {
    state: Arc<State>,
    send: mpsc::Sender<Frame>,
    driver: JoinHandle<()>,
}
impl Connection {
    fn retired(&self, now: Instant) -> bool {
        let queries = lock(&self.state.queries);
        queries.closed
            || queries.suspect
            || queries.issued == 65_536
            || (queries.pending.is_empty()
                && now.saturating_duration_since(queries.last_used) >= IDLE_LIMIT)
    }
    fn claim(self: &Arc<Self>, request: &Message) -> Option<(Pending, Message)> {
        let mut queries = lock(&self.state.queries);
        if queries.closed
            || queries.suspect
            || queries.issued == 65_536
            || queries.pending.len() >= PENDING_LIMIT
        {
            return None;
        }
        // Conversion is checked even though the lifetime bound keeps it in range.
        let offset = u16::try_from(queries.issued).ok()?;
        let id = queries.first_id.wrapping_add(offset);
        queries.issued += 1;
        let mut query = request.clone();
        query.metadata.id = id;
        let (reply, receive) = oneshot::channel();
        queries.pending.insert(
            id,
            Waiter {
                request: query.clone(),
                reply,
            },
        );
        if queries.issued == 65_536 {
            queries.suspect = true;
        }
        Some((
            Pending {
                connection: self.clone(),
                id,
                receive,
            },
            query,
        ))
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.driver.abort();
    }
}
struct Pending {
    connection: Arc<Connection>,
    id: u16,
    receive: oneshot::Receiver<Result<Message, FailureKind>>,
}
impl Drop for Pending {
    fn drop(&mut self) {
        let state = &self.connection.state;
        {
            let mut queries = lock(&state.queries);
            if queries.pending.remove(&self.id).is_some() {
                queries.cancelled.insert(self.id);
                queries.suspect = true;
            }
            queries.last_used = Instant::now();
        }
        state.changed.notify_one();
        state.capacity.notify_one();
    }
}
/// A guard captured whole by the driver, so cancellation before its first poll
/// still drops the socket before releasing its physical permit.
struct PhysicalConnection {
    reader: Option<tokio::io::ReadHalf<TlsStream<TcpStream>>>,
    writer: Option<tokio::io::WriteHalf<TlsStream<TcpStream>>>,
    permit: Option<OwnedSemaphorePermit>,
    state: Arc<State>,
}
impl Drop for PhysicalConnection {
    fn drop(&mut self) {
        drop(self.reader.take());
        drop(self.writer.take());
        self.state.fail(FailureKind::Connection);
        drop(self.permit.take());
        self.state.capacity.notify_waiters();
    }
}
impl TlsPool {
    async fn connect(&self, permit: OwnedSemaphorePermit) -> Result<Arc<Connection>, ResolveError> {
        let socket = TcpStream::connect(self.address).await?;
        socket.set_nodelay(true)?;
        let stream = self.connector.connect(self.name.clone(), socket).await?;
        let state = Arc::new(State {
            queries: Mutex::new(Queries {
                pending: HashMap::with_capacity(PENDING_LIMIT),
                cancelled: HashSet::with_capacity(PENDING_LIMIT),
                first_id: rand::random(),
                issued: 0,
                suspect: false,
                closed: false,
                last_used: Instant::now(),
            }),
            capacity: self.capacity.clone(),
            changed: Notify::new(),
        });
        let (reader, writer) = tokio::io::split(stream);
        let owned = PhysicalConnection {
            reader: Some(reader),
            writer: Some(writer),
            permit: Some(permit),
            state: state.clone(),
        };
        let (send, receive) = mpsc::channel(PENDING_LIMIT);
        let driver = tokio::spawn(async move {
            let mut owned = owned;
            if let (Some(reader), Some(writer)) = (owned.reader.as_mut(), owned.writer.as_mut()) {
                let result = tokio::select! {
                    result = read_replies(reader, &owned.state) => result,
                    result = write_queries(writer, receive, &owned.state) => result,
                    _ = owned.state.drained() => Ok(()),
                };
                if let Err(error) = result {
                    owned.state.fail(error.failure_kind());
                }
            }
        });
        Ok(Arc::new(Connection {
            state,
            send,
            driver,
        }))
    }
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
    fn checkout(&self, request: &Message) -> Option<(Pending, Message)> {
        let (claim, retired) = {
            let mut pool = lock(&self.connections);
            let retired = Self::prune(&mut pool);
            let claim = pool
                .iter()
                .min_by_key(|c| lock(&c.state.queries).pending.len())
                .and_then(|connection| connection.claim(request));
            (claim, retired)
        };
        drop(retired);
        claim
    }
    async fn open(
        &self,
        permit: OwnedSemaphorePermit,
        request: &Message,
    ) -> Result<(Pending, Message), ResolveError> {
        let connection = match self.connect(permit).await {
            Ok(connection) => connection,
            Err(error) => {
                self.capacity.notify_waiters();
                return Err(error);
            }
        };
        let claim = connection.claim(request).ok_or(ResolveError::Unavailable)?;
        lock(&self.connections).push(connection);
        self.capacity.notify_waiters();
        Ok(claim)
    }
    async fn claim(&self, request: &Message) -> Result<(Pending, Message, bool), ResolveError> {
        loop {
            let notified = self.capacity.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some((pending, query)) = self.checkout(request) {
                return Ok((pending, query, true));
            }
            if let Ok(permit) = self.physical.clone().try_acquire_owned() {
                let (pending, query) = self.open(permit, request).await?;
                return Ok((pending, query, false));
            }
            let _ = tokio::time::timeout(RECHECK, notified).await;
        }
    }
    pub async fn exchange(&self, request: &Message) -> Result<Message, ResolveError> {
        // The forwarder's deadline also includes request and physical admission.
        let _request = self
            .requests
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| ResolveError::Unavailable)?;
        let (pending, query, reused) = self.claim(request).await?;
        let result = send_query(pending, query).await;
        if reused
            && result
                .as_ref()
                .is_err_and(|e| e.failure_kind() == FailureKind::Connection)
        {
            // Retry a stale/closed reused connection once under the same deadline.
            // Malformed content is never retried; claim prunes the closed socket.
            let (pending, query, _) = self.claim(request).await?;
            return send_query(pending, query).await;
        }
        result
    }
}
async fn send_query(mut pending: Pending, query: Message) -> Result<Message, ResolveError> {
    let bytes = tcp_frame(&query.to_vec().map_err(|_| ResolveError::Encoding)?)?;
    pending
        .connection
        .send
        .send(Frame {
            id: pending.id,
            bytes,
        })
        .await
        .map_err(|_| ResolveError::Failure(FailureKind::Connection))?;
    (&mut pending.receive)
        .await
        .map_err(|_| ResolveError::Failure(FailureKind::Connection))?
        .map_err(ResolveError::Failure)
}
async fn write_queries(
    writer: &mut tokio::io::WriteHalf<TlsStream<TcpStream>>,
    mut receive: mpsc::Receiver<Frame>,
    state: &State,
) -> Result<(), ResolveError> {
    while let Some(frame) = receive.recv().await {
        // Cancellation before writing leaves no query on the wire. A cancellation
        // racing this check is safe: the reader recognizes its tombstone.
        if !lock(&state.queries).pending.contains_key(&frame.id) {
            continue;
        }
        writer.write_all(&frame.bytes).await?;
        writer.flush().await?;
    }
    Ok(())
}
async fn read_replies(
    reader: &mut tokio::io::ReadHalf<TlsStream<TcpStream>>,
    state: &State,
) -> Result<(), ResolveError> {
    loop {
        let len = usize::from(reader.read_u16().await?);
        if len < 12 {
            return Err(ResolveError::InvalidResponse);
        }
        let mut bytes = vec![0; len];
        reader.read_exact(&mut bytes).await?;
        let response = decode_frame(&bytes)?;
        let waiter = {
            let mut queries = lock(&state.queries);
            if queries.cancelled.remove(&response.metadata.id) {
                continue;
            }
            let waiter = queries
                .pending
                .remove(&response.metadata.id)
                .ok_or(ResolveError::InvalidResponse)?;
            if let Err(error) = validate(&waiter.request, &response) {
                // Keep this waiter in the set so connection failure reaches it too.
                queries.pending.insert(response.metadata.id, waiter);
                return Err(error);
            }
            queries.last_used = Instant::now();
            waiter
        };
        let _ = waiter.reply.send(Ok(response));
        state.capacity.notify_one();
        state.changed.notify_one();
    }
}
/// Strict, bounded DoT DNS payload decoding, shared with the fuzz harness.
pub fn decode_frame(bytes: &[u8]) -> Result<Message, ResolveError> {
    if !(12..=65_535).contains(&bytes.len()) {
        return Err(ResolveError::InvalidResponse);
    }
    let mut decoder = BinDecoder::new(bytes);
    let response = Message::read(&mut decoder).map_err(|_| ResolveError::InvalidResponse)?;
    if !decoder.is_empty()
        || response.metadata.truncation
        || response.metadata.message_type != MessageType::Response
        || response.signature.is_some()
    {
        return Err(ResolveError::InvalidResponse);
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[tokio::test]
    async fn a_connection_never_reuses_an_id_even_after_wraparound() {
        let state = Arc::new(State {
            queries: Mutex::new(Queries {
                pending: HashMap::new(),
                cancelled: HashSet::new(),
                first_id: 65_532,
                issued: 0,
                suspect: false,
                closed: false,
                last_used: Instant::now(),
            }),
            capacity: Arc::new(Notify::new()),
            changed: Notify::new(),
        });
        let (send, _receive) = mpsc::channel(PENDING_LIMIT);
        let connection = Arc::new(Connection {
            state,
            send,
            driver: tokio::spawn(std::future::pending()),
        });
        let mut seen = HashSet::new();
        for _ in 0..65_536 {
            let (pending, query) = connection.claim(&Message::query()).unwrap();
            assert!(seen.insert(query.metadata.id));
            // Simulate a completed response before reserving the next ID.
            let waiter = lock(&connection.state.queries)
                .pending
                .remove(&pending.id)
                .unwrap();
            let _ = waiter.reply.send(Ok(query.into_response()));
            drop(pending);
        }
        assert_eq!(seen.len(), 65_536);
        assert!(connection.retired(Instant::now()));
        assert!(connection.claim(&Message::query()).is_none());
    }
}
