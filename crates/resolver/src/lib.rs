#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
use hickory_proto::op::{Message, MessageType, ResponseCode};
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
};

/// Why a forwarding attempt or configuration failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ResolveError {
    /// Every upstream failed, was backing off, or admission/shutdown refused work.
    #[error("no upstream completed a validated DNS exchange")]
    Unavailable,
    /// A reply failed validation (ID, opcode, question, size or truncation).
    #[error("invalid upstream response")]
    InvalidResponse,
    /// The request could not be wire-encoded, or had no question.
    #[error("DNS wire encoding failed")]
    Encoding,
    /// Socket or TLS failure.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Invalid forwarder or transport settings.
    #[error("invalid upstream transport configuration: {0}")]
    Configuration(String),
    /// HTTP/2 protocol failure on a DNS-over-HTTPS connection.
    #[error(transparent)]
    Http2(#[from] Http2Error),
    /// A classified failure of an otherwise completed exchange.
    #[error("upstream failure: {0:?}")]
    Failure(FailureKind),
}
/// HTTP/2 failure. Opaque so that `h2` is not part of this crate's public API;
/// the underlying error remains available through [`std::error::Error::source`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct Http2Error(pub(crate) h2::Error);
impl From<h2::Error> for ResolveError {
    fn from(error: h2::Error) -> Self {
        Self::Http2(Http2Error(error))
    }
}

impl ResolveError {
    /// Classification used for upstream health counters and backoff.
    pub fn failure_kind(&self) -> FailureKind {
        match self {
            Self::Failure(kind) => *kind,
            Self::InvalidResponse => FailureKind::DnsResponse,
            Self::Io(error) => io_failure(error),
            Self::Http2(Http2Error(error)) => error
                .get_io()
                .map(io_failure)
                .unwrap_or(FailureKind::HttpProtocol),
            Self::Unavailable | Self::Encoding | Self::Configuration(_) => FailureKind::LocalError,
        }
    }
}
fn io_failure(error: &io::Error) -> FailureKind {
    match error
        .get_ref()
        .and_then(|e| e.downcast_ref::<tokio_rustls::rustls::Error>())
    {
        Some(
            tokio_rustls::rustls::Error::InvalidCertificate(_)
            | tokio_rustls::rustls::Error::NoCertificatesPresented,
        ) => FailureKind::TlsAuthentication,
        Some(_) => FailureKind::TlsProtocol,
        None => FailureKind::Connection,
    }
}

/// Content identity of an upstream profile: its ordered addresses and transport
/// trust/identity settings, but not timeouts or pool sizes. Response caching and
/// coalescing are keyed by this identity rather than by policy generation, so a
/// publication that keeps a profile unchanged keeps its cached answers, while any
/// change that could alter upstream content selects a disjoint cache partition.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct UpstreamId(u128);
impl UpstreamId {
    fn new(addresses: &[SocketAddr], transport: &UpstreamTransport) -> Self {
        // Length-prefixed fields make the encoding unambiguous; a truncated
        // SHA-256 digest keeps keys small without accidental collisions.
        fn field(out: &mut Vec<u8>, bytes: &[u8]) {
            out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        let mut encoded = Vec::new();
        for address in addresses {
            match address {
                SocketAddr::V4(v4) => {
                    encoded.push(4);
                    encoded.extend_from_slice(&v4.ip().octets());
                }
                SocketAddr::V6(v6) => {
                    encoded.push(6);
                    encoded.extend_from_slice(&v6.ip().octets());
                    encoded.extend_from_slice(&v6.scope_id().to_be_bytes());
                }
            }
            encoded.extend_from_slice(&address.port().to_be_bytes());
        }
        match transport {
            UpstreamTransport::Udp => encoded.push(0),
            UpstreamTransport::Tls {
                server_name,
                ca_pem,
                max_connections: _,
            } => {
                encoded.push(1);
                field(&mut encoded, server_name.as_bytes());
                field(
                    &mut encoded,
                    ca_pem.as_deref().unwrap_or_default().as_bytes(),
                );
            }
            UpstreamTransport::Https {
                server_name,
                path,
                ca_pem,
                max_connections: _,
            } => {
                encoded.push(2);
                field(&mut encoded, server_name.as_bytes());
                field(&mut encoded, path.as_bytes());
                field(
                    &mut encoded,
                    ca_pem.as_deref().unwrap_or_default().as_bytes(),
                );
            }
        }
        let digest = ring::digest::digest(&ring::digest::SHA256, &encoded);
        let mut prefix = [0; 16];
        prefix.copy_from_slice(&digest.as_ref()[..16]);
        Self(u128::from_be_bytes(prefix))
    }
}

/// One upstream address with its compiled transport.
#[derive(Clone, Debug)]
enum Endpoint {
    Udp(SocketAddr),
    Tls(Arc<tls::TlsPool>),
    Https(Arc<https::HttpsPool>),
}

/// Sequential failover across up to eight upstream addresses sharing one transport.
#[derive(Clone, Debug)]
pub struct Forwarder {
    addresses: Vec<SocketAddr>,
    endpoints: Vec<Endpoint>,
    timeout: Duration,
    id: UpstreamId,
    health: Arc<Vec<UpstreamHealth>>,
}
impl Forwarder {
    /// Plain UDP (with TCP fallback) to `upstreams`, each attempt bounded by
    /// `timeout`.
    ///
    /// # Errors
    ///
    /// [`ResolveError::Configuration`] for 0 or more than 8 addresses or a zero
    /// timeout.
    pub fn new(upstreams: Vec<SocketAddr>, timeout: Duration) -> Result<Self, ResolveError> {
        Self::with_transport(upstreams, timeout, &UpstreamTransport::Udp)
    }
    /// `upstreams` over `transport`, compiling TLS trust and pools now.
    ///
    /// # Errors
    ///
    /// [`ResolveError::Configuration`] for invalid limits, server names, paths
    /// or CA certificates.
    pub fn with_transport(
        upstreams: Vec<SocketAddr>,
        timeout: Duration,
        transport: &UpstreamTransport,
    ) -> Result<Self, ResolveError> {
        if upstreams.is_empty() || upstreams.len() > 8 {
            return Err(ResolveError::Configuration(
                "an upstream profile needs 1..=8 addresses".into(),
            ));
        }
        if timeout.is_zero() {
            return Err(ResolveError::Configuration(
                "upstream timeout must be positive".into(),
            ));
        }
        let endpoints = match transport {
            UpstreamTransport::Udp => upstreams.iter().copied().map(Endpoint::Udp).collect(),
            UpstreamTransport::Tls { .. } => tls::compile(&upstreams, transport)?
                .into_iter()
                .map(Endpoint::Tls)
                .collect(),
            UpstreamTransport::Https { .. } => https::compile(&upstreams, transport)?
                .into_iter()
                .map(Endpoint::Https)
                .collect(),
        };
        let health = Arc::new(
            upstreams
                .iter()
                .map(|address| UpstreamHealth::new(*address))
                .collect(),
        );
        Ok(Self {
            id: UpstreamId::new(&upstreams, transport),
            addresses: upstreams,
            endpoints,
            timeout,
            health,
        })
    }
    /// Upstream addresses in failover order.
    pub fn upstreams(&self) -> &[SocketAddr] {
        &self.addresses
    }
    /// Per-address counters and admission state, in address order.
    #[inline]
    pub fn health(&self) -> &[UpstreamHealth] {
        &self.health
    }
    /// Content identity used to partition caches and coalesced work.
    #[inline]
    pub fn id(&self) -> UpstreamId {
        self.id
    }
    /// Try each admitted address in order until one returns a validated reply
    /// other than SERVFAIL/REFUSED. No caching or coalescing; see [`Resolver`].
    ///
    /// # Errors
    ///
    /// [`ResolveError::Unavailable`] when every address failed or was cooling
    /// down.
    pub async fn resolve(&self, request: &Message) -> Result<Message, ResolveError> {
        for (endpoint, health) in self.endpoints.iter().zip(self.health.iter()) {
            let Some(attempt) = health.start() else {
                continue;
            };
            let result = timeout(self.timeout, async {
                match endpoint {
                    Endpoint::Udp(address) => exchange(*address, request).await,
                    Endpoint::Tls(pool) => pool.exchange(request).await,
                    Endpoint::Https(pool) => pool.exchange(request).await,
                }
            })
            .await;
            match result {
                Ok(Ok(response)) => {
                    match response.metadata.response_code {
                        ResponseCode::ServFail => {
                            attempt.failure(FailureKind::Servfail);
                            continue;
                        }
                        ResponseCode::Refused => {
                            attempt.failure(FailureKind::Refused);
                            continue;
                        }
                        _ => {}
                    }
                    attempt.success();
                    return Ok(response);
                }
                Ok(Err(error)) => attempt.failure(error.failure_kind()),
                Err(_) => attempt.failure(FailureKind::Deadline),
            }
        }
        Err(ResolveError::Unavailable)
    }
}

fn validate(request: &Message, response: &Message) -> Result<(), ResolveError> {
    if response.metadata.id != request.metadata.id
        || response.metadata.message_type != MessageType::Response
        || response.metadata.op_code != request.metadata.op_code
        || response.queries != request.queries
        || response.signature.is_some()
    {
        return Err(ResolveError::InvalidResponse);
    }
    Ok(())
}
async fn exchange(upstream: SocketAddr, request: &Message) -> Result<Message, ResolveError> {
    let mut request = request.clone();
    request.metadata.id = rand::random();
    let bytes = request.to_vec().map_err(|_| ResolveError::Encoding)?;
    let bind = if upstream.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(upstream).await?;
    socket.send(&bytes).await?;
    // A compliant reply fits the advertised payload size. One spare byte detects
    // an oversized datagram, which the kernel would otherwise truncate silently.
    let limit = usize::from(request.max_payload().max(512));
    let mut buffer = vec![0; limit + 1];
    // Ignore spoofed or malformed packets until the enclosing timeout expires.
    loop {
        let len = socket.recv(&mut buffer).await?;
        if len > limit {
            // Cannot be validated from a truncated copy; TCP has no size cap.
            return exchange_tcp(upstream, &request, &bytes).await;
        }
        let Ok(response) = Message::from_vec(&buffer[..len]) else {
            continue;
        };
        if validate(&request, &response).is_err() {
            continue;
        }
        if response.metadata.truncation {
            return exchange_tcp(upstream, &request, &bytes).await;
        }
        return Ok(response);
    }
}
/// Prefix a DNS message with its RFC 1035 TCP length, so it leaves in one write.
fn tcp_frame(bytes: &[u8]) -> Result<Vec<u8>, ResolveError> {
    let len = u16::try_from(bytes.len()).map_err(|_| ResolveError::Encoding)?;
    let mut frame = Vec::with_capacity(bytes.len() + 2);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(bytes);
    Ok(frame)
}
async fn exchange_tcp(
    upstream: SocketAddr,
    request: &Message,
    bytes: &[u8],
) -> Result<Message, ResolveError> {
    let frame = tcp_frame(bytes)?;
    let mut stream = TcpStream::connect(upstream).await?;
    // Small request frames must not wait for a delayed ACK (Nagle).
    stream.set_nodelay(true)?;
    stream.write_all(&frame).await?;
    let len = usize::from(stream.read_u16().await?);
    if len < 12 {
        return Err(ResolveError::InvalidResponse);
    }
    let mut buffer = vec![0; len];
    stream.read_exact(&mut buffer).await?;
    let response = Message::from_vec(&buffer).map_err(|_| ResolveError::InvalidResponse)?;
    validate(request, &response)?;
    if response.metadata.truncation {
        return Err(ResolveError::InvalidResponse);
    }
    Ok(response)
}

/// Strict DNS-over-HTTPS (HTTP/2) forwarding.
pub mod https;
mod tls;
pub use tls::UpstreamTransport;
/// Decode a bounded DNS-over-TLS payload, rejecting trailing or malformed data.
pub use tls::decode_frame as decode_dot_frame;

/// Bounded CLOCK caches shared by response and decision caching.
pub mod cache;
mod inflight;
/// TTL-aware response cache keyed by question, upstream identity and DO/CD.
pub mod response_cache;
pub use inflight::{Lookup, Resolution, ResolutionSource, Resolver, ResolverMetrics};

mod admission;
mod health;
pub use admission::AdmissionStatus;
pub use health::{FailureKind, UpstreamHealth};

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn id(addresses: &[&str], transport: &UpstreamTransport, timeout_ms: u64) -> UpstreamId {
        Forwarder::with_transport(
            addresses.iter().map(|a| a.parse().unwrap()).collect(),
            Duration::from_millis(timeout_ms),
            transport,
        )
        .unwrap()
        .id()
    }
    fn tls(server_name: &str, max_connections: usize) -> UpstreamTransport {
        UpstreamTransport::Tls {
            server_name: server_name.into(),
            ca_pem: None,
            max_connections,
        }
    }

    #[test]
    fn upstream_identity_tracks_content_but_not_tuning() {
        let udp = UpstreamTransport::Udp;
        let base = id(&["192.0.2.1:53"], &udp, 1000);
        // Timeouts and pool sizes cannot change answers.
        assert_eq!(base, id(&["192.0.2.1:53"], &udp, 5000));
        assert_eq!(
            id(&["192.0.2.1:853"], &tls("dns.test", 1), 1000),
            id(&["192.0.2.1:853"], &tls("dns.test", 8), 1000)
        );
        // Addresses, their order and every trust/identity field can.
        for other in [
            id(&["192.0.2.2:53"], &udp, 1000),
            id(&["192.0.2.1:54"], &udp, 1000),
            id(&["192.0.2.1:53", "192.0.2.2:53"], &udp, 1000),
            id(&["[2001:db8::1]:53"], &udp, 1000),
            id(&["192.0.2.1:53"], &tls("dns.test", 1), 1000),
        ] {
            assert_ne!(base, other);
        }
        assert_ne!(
            id(&["192.0.2.1:53", "192.0.2.2:53"], &udp, 1000),
            id(&["192.0.2.2:53", "192.0.2.1:53"], &udp, 1000)
        );
        assert_ne!(
            id(&["192.0.2.1:853"], &tls("a.test", 1), 1000),
            id(&["192.0.2.1:853"], &tls("b.test", 1), 1000)
        );
        let https = |path: &str| UpstreamTransport::Https {
            server_name: "dns.test".into(),
            path: path.into(),
            ca_pem: None,
            max_connections: 2,
        };
        assert_ne!(
            id(&["192.0.2.1:443"], &https("/dns-query"), 1000),
            id(&["192.0.2.1:443"], &https("/other"), 1000)
        );
    }

    #[test]
    fn invalid_forwarder_limits_are_configuration_errors() {
        for (addresses, timeout) in [
            (vec![], Duration::from_secs(1)),
            (
                vec!["192.0.2.1:53".parse().unwrap(); 9],
                Duration::from_secs(1),
            ),
            (vec!["192.0.2.1:53".parse().unwrap()], Duration::ZERO),
        ] {
            assert!(matches!(
                Forwarder::new(addresses, timeout),
                Err(ResolveError::Configuration(_))
            ));
        }
    }
}

#[cfg(test)]
extern crate self as rustwalld_dns_resolver;
#[cfg(test)]
mod pool_properties;
