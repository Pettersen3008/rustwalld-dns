#![doc = include_str!("../README.md")]
use hickory_proto::op::{Message, MessageType};
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
};

#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("no upstream completed a validated DNS exchange")]
    Unavailable,
    #[error("invalid upstream response")]
    InvalidResponse,
    #[error("DNS wire encoding failed")]
    Encoding,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("invalid upstream transport configuration: {0}")]
    Configuration(String),
    #[error(transparent)]
    Http2(#[from] h2::Error),
    #[error("upstream failure: {0:?}")]
    Failure(FailureKind),
}

impl ResolveError {
    pub fn failure_kind(&self) -> FailureKind {
        match self {
            Self::Failure(kind) => *kind,
            Self::InvalidResponse => FailureKind::DnsResponse,
            Self::Io(error) => io_failure(error),
            Self::Http2(error) => error
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

#[derive(Clone, Debug)]
pub struct Forwarder {
    upstreams: Vec<SocketAddr>,
    timeout: Duration,
    tls: Vec<Arc<tls::TlsPool>>,
    https: Vec<Arc<https::HttpsPool>>,
    pub health: Arc<Vec<UpstreamHealth>>,
}
impl Forwarder {
    pub fn new(upstreams: Vec<SocketAddr>, timeout: Duration) -> Result<Self, ResolveError> {
        Self::with_transport(upstreams, timeout, &UpstreamTransport::Udp)
    }
    pub fn with_transport(
        upstreams: Vec<SocketAddr>,
        timeout: Duration,
        transport: &UpstreamTransport,
    ) -> Result<Self, ResolveError> {
        if upstreams.is_empty() || upstreams.len() > 8 || timeout.is_zero() {
            return Err(ResolveError::Unavailable);
        }
        let tls = tls::compile(&upstreams, transport)?;
        let https = https::compile(&upstreams, transport)?;
        let health = Arc::new(
            upstreams
                .iter()
                .map(|address| UpstreamHealth::new(*address))
                .collect(),
        );
        Ok(Self {
            upstreams,
            timeout,
            health,
            tls,
            https,
        })
    }
    pub fn upstreams(&self) -> &[SocketAddr] {
        &self.upstreams
    }
    pub async fn resolve(&self, request: &Message) -> Result<Message, ResolveError> {
        for (index, upstream) in self.upstreams.iter().enumerate() {
            let Some(attempt) = self.health[index].start() else {
                continue;
            };
            let result = timeout(self.timeout, async {
                if let Some(pool) = self.tls.get(index) {
                    pool.exchange(request).await
                } else if let Some(pool) = self.https.get(index) {
                    pool.exchange(request).await
                } else {
                    exchange(*upstream, request).await
                }
            })
            .await;
            match result {
                Ok(Ok(response)) => {
                    match response.metadata.response_code {
                        hickory_proto::op::ResponseCode::ServFail => {
                            attempt.failure(FailureKind::Servfail);
                            continue;
                        }
                        hickory_proto::op::ResponseCode::Refused => {
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

pub mod https;
mod tls;
pub use tls::UpstreamTransport;

pub mod cache;
mod inflight;
pub mod response_cache;
pub use inflight::{Resolution, ResolutionSource, Resolver, ResolverMetrics};

mod admission;
mod health;
pub use admission::AdmissionStatus;
pub use health::{FailureKind, UpstreamHealth};
