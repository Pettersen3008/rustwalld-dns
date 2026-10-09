//! Strict DNS-over-TLS. Trust/identity are compiled before snapshot publication.
use crate::{ResolveError, tcp_frame, validate};
use hickory_proto::op::Message;
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Semaphore,
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

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum UpstreamTransport {
    /// UDP with TCP fallback on a validated truncated response.
    #[default]
    Udp,
    /// Every address in the profile uses this authenticated DNS server identity.
    Tls {
        server_name: String,
        /// When present, replaces bundled public roots (private resolvers).
        #[serde(default)]
        ca_pem: Option<String>,
        #[serde(default = "pool_size")]
        max_connections: usize,
    },
    /// Strict HTTP/2 DNS over HTTPS, POST wire format only.
    Https {
        server_name: String,
        #[serde(default = "doh_path")]
        path: String,
        #[serde(default)]
        ca_pem: Option<String>,
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
                idle: Mutex::new(Vec::new()),
                slots: Arc::new(Semaphore::new(*max_connections)),
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

pub(super) struct TlsPool {
    address: SocketAddr,
    name: ServerName<'static>,
    connector: TlsConnector,
    idle: Mutex<Vec<(TlsStream<TcpStream>, Instant)>>,
    slots: Arc<Semaphore>,
}
impl std::fmt::Debug for TlsPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsPool")
            .field("address", &self.address)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}
impl TlsPool {
    async fn connect(&self) -> Result<TlsStream<TcpStream>, ResolveError> {
        let socket = TcpStream::connect(self.address).await?;
        socket.set_nodelay(true)?;
        Ok(self.connector.connect(self.name.clone(), socket).await?)
    }
    pub async fn exchange(&self, request: &Message) -> Result<Message, ResolveError> {
        // Forwarder's deadline includes admission, connect, handshake and exchange.
        // Resolver's global inflight admission bounds the number of pool waiters.
        let _permit = self
            .slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| ResolveError::Unavailable)?;
        let reused = loop {
            // Take at most one socket per permit. Moving all expired sockets out
            // together could temporarily exceed the physical connection cap while
            // other admitted requests create replacements. Close outside the lock.
            let candidate = self.idle.lock().unwrap_or_else(|e| e.into_inner()).pop();
            match candidate {
                Some((stream, used)) if used.elapsed() < Duration::from_secs(60) => {
                    break Some(stream);
                }
                Some((stream, _)) => drop(stream),
                None => break None,
            }
        };
        let was_reused = reused.is_some();
        let mut stream = match reused {
            Some(stream) => stream,
            None => self.connect().await?,
        };
        let mut query = request.clone();
        query.metadata.id = rand::random();
        let frame = tcp_frame(&query.to_vec().map_err(|_| ResolveError::Encoding)?)?;
        let result = framed_exchange(&mut stream, &query, &frame).await;
        let response = match result {
            // A server may close an idle connection. Retry that endpoint once, still
            // within the original deadline; never reconnect on invalid DNS content.
            Err(ResolveError::Io(_)) if was_reused => {
                drop(stream);
                stream = self.connect().await?;
                framed_exchange(&mut stream, &query, &frame).await?
            }
            result => result?,
        };
        // Ownership stays local across awaits. Cancellation/error drops the socket,
        // so a late reply can never contaminate another request's pooled connection.
        self.idle
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((stream, Instant::now()));
        Ok(response)
    }
}
async fn framed_exchange(
    stream: &mut TlsStream<TcpStream>,
    request: &Message,
    frame: &[u8],
) -> Result<Message, ResolveError> {
    // One write produces one TLS record for the length and message.
    stream.write_all(frame).await?;
    // rustls may buffer a small write; flush before awaiting the server.
    stream.flush().await?;
    let len = usize::from(stream.read_u16().await?);
    if len < 12 {
        return Err(ResolveError::InvalidResponse);
    }
    let mut bytes = vec![0; len];
    stream.read_exact(&mut bytes).await?;
    let response = Message::from_vec(&bytes).map_err(|_| ResolveError::InvalidResponse)?;
    validate(request, &response)?;
    if response.metadata.truncation {
        return Err(ResolveError::InvalidResponse);
    }
    Ok(response)
}
