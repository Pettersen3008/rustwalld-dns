//! Certificate loading and bounded TLS handshakes, outside DNS workers.
use crate::listener::{Activity, ManagedStream};
use axum::{
    extract::connect_info::Connected,
    serve::{IncomingStream, Listener},
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde::{Deserialize, Serialize};
use std::{
    io::{self, Read},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet};
use tokio_rustls::{TlsAcceptor, rustls, server::TlsStream};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Certificate {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    /// Explicit additional HTTP hostnames. IP literals and localhost are also accepted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hostnames: Vec<String>,
}
impl Certificate {
    pub fn validate(&self) -> Result<(), String> {
        if self.hostnames.len() > 16
            || self.hostnames.iter().any(|name| {
                !name.is_ascii()
                    || rustwalld_dns_filter::normalize(name).is_err()
                    || name.ends_with('.')
                    || name.contains('*')
                    || name.contains(':')
            })
        {
            return Err("TLS hostnames must be at most 16 explicit ASCII DNS names without ports/wildcards/root dots".into());
        }
        Ok(())
    }
    /// Call on the bounded startup control worker before binding any listener.
    pub fn load(&self, http: bool) -> Result<TlsAcceptor, String> {
        self.validate()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if std::fs::metadata(&self.key_file)
                .map_err(|_| "Cannot inspect TLS private key")?
                .permissions()
                .mode()
                & 0o007
                != 0
            {
                return Err("TLS private key must not be accessible to other users (use 0600 or service-group 0640)".into());
            }
        }
        let cert = read(&self.cert_file, 256 * 1024)?;
        let key = read(&self.key_file, 16 * 1024)?;
        from_pem(&cert, &key, http)
    }
}
/// Parse bounded certificate/key bytes without filesystem or network access.
/// Server key compatibility is checked; clients still validate trust/validity.
pub fn from_pem(cert_pem: &[u8], key_pem: &[u8], http: bool) -> Result<TlsAcceptor, String> {
    if cert_pem.is_empty()
        || cert_pem.len() > 256 * 1024
        || key_pem.is_empty()
        || key_pem.len() > 16 * 1024
    {
        return Err("TLS PEM input exceeds its size bounds".into());
    }
    let certificates = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "Invalid certificate PEM")?;
    if certificates.is_empty() || certificates.len() > 8 {
        return Err("TLS certificate chain needs 1..8 certificates".into());
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|_| "Invalid private key PEM")?;
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| "TLS versions unavailable")?
    .with_no_client_auth()
    .with_single_cert(certificates, key)
    .map_err(|_| "Invalid or mismatched TLS certificate/key")?;
    config.alpn_protocols = if http {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"dot".to_vec()]
    };
    config.session_storage = rustls::server::ServerSessionMemoryCache::new(128);
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn read(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(limit as u64 + 1).read_to_end(&mut bytes))
        .map_err(|_| "Cannot read TLS certificate/key")?;
    if bytes.is_empty() || bytes.len() > limit {
        return Err("TLS certificate/key is empty or exceeds its size limit".into());
    }
    Ok(bytes)
}
fn connections() -> usize {
    64
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsListener {
    pub listen: std::net::SocketAddr,
    pub certificate: Certificate,
    #[serde(default = "connections")]
    pub max_connections: usize,
}
impl DnsListener {
    pub fn validate(&self) -> Result<(), String> {
        self.certificate.validate()?;
        if !(1..=256).contains(&self.max_connections) {
            return Err("encrypted listener max_connections must be 1..256".into());
        }
        Ok(())
    }
}
type Connection = (
    ManagedStream<TlsStream<tokio::net::TcpStream>>,
    std::net::SocketAddr,
);
/// Source admission checked before a slot or TLS handshake is spent.
pub type Admission = Arc<dyn Fn(std::net::IpAddr) -> bool + Send + Sync>;
/// Handshakes proceed concurrently; one slow TLS peer cannot stall all accepts.
pub struct SecureListener {
    inner: TcpListener,
    acceptor: TlsAcceptor,
    slots: Arc<Semaphore>,
    pending: JoinSet<Option<Connection>>,
    admission: Option<Admission>,
}
impl SecureListener {
    pub fn new(inner: TcpListener, acceptor: TlsAcceptor, connections: usize) -> Self {
        Self {
            inner,
            acceptor,
            slots: Arc::new(Semaphore::new(connections)),
            pending: JoinSet::new(),
            admission: None,
        }
    }
    /// Close peers the predicate rejects at accept, before any handshake.
    /// Use only for DNS ingress; management access has its own authentication.
    #[must_use]
    pub fn with_admission(mut self, admission: Admission) -> Self {
        self.admission = Some(admission);
        self
    }
}
impl Listener for SecureListener {
    type Io = ManagedStream<TlsStream<tokio::net::TcpStream>>;
    type Addr = std::net::SocketAddr;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            tokio::select! {
                result=self.pending.join_next(),if !self.pending.is_empty()=>{if let Some(Ok(Some(connection)))=result{return connection;}},
                incoming=self.inner.accept(),if self.slots.available_permits()>0=>{
                    let Ok((stream,address))=incoming else {tokio::time::sleep(Duration::from_millis(100)).await;continue;};
                    if self.admission.as_ref().is_some_and(|admits| !admits(address.ip())) {continue;}
                    let Ok(permit)=self.slots.clone().try_acquire_owned() else {continue;};let acceptor=self.acceptor.clone();
                    self.pending.spawn(async move {
                        let stream=tokio::time::timeout(Duration::from_secs(5),acceptor.accept(stream)).await.ok()?.ok()?;
                        Some((ManagedStream::new(stream,permit,Duration::from_secs(30),address).secured(),address))
                    });
                },
                permit=self.slots.clone().acquire_owned(),if self.slots.available_permits()==0 && self.pending.is_empty()=>{drop(permit);}
            }
        }
    }
    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}
impl Connected<IncomingStream<'_, SecureListener>> for Activity {
    fn connect_info(stream: IncomingStream<'_, SecureListener>) -> Self {
        stream.io().activity().clone()
    }
}
