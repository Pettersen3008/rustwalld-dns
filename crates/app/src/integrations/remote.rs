//! Pinned, authenticated one-use HTTPS connections; no redirects or DNS lookup.
use super::Remote;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::{Request, StatusCode, client::conn::http1, header};
use hyper_util::rt::TokioIo;
use std::{io::Read, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::TcpStream, task::JoinHandle};
use tokio_rustls::{
    TlsConnector,
    rustls::{
        ClientConfig, RootCertStore,
        crypto::ring,
        pki_types::{CertificateDer, ServerName, pem::PemObject},
    },
};
use url::{Host, Position, Url};
use zeroize::Zeroizing;
#[derive(Clone, Copy)]
pub(super) enum Auth {
    ApiKey,
    Basic,
    Bearer,
}
pub(super) struct Client {
    url: Url,
    ips: Vec<std::net::IpAddr>,
    name: ServerName<'static>,
    tls: Arc<ClientConfig>,
    secret: Zeroizing<String>,
    auth: Auth,
}
impl Client {
    pub fn load(config: &Remote, auth: Auth) -> Result<Self, String> {
        if config.url.len() > 2048
            || config.url.chars().any(char::is_control)
            || !(1..=8).contains(&config.bootstrap_ips.len())
        {
            return Err("integration URL/IP counts outside bounds".into());
        }
        let url = Url::parse(&config.url).map_err(|_| "invalid integration URL")?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || url.query().is_some()
            || !matches!(url.path(), "" | "/")
            || url.port_or_known_default() == Some(0)
        {
            return Err(
                "integration URL requires HTTPS origin without credentials/path/query".into(),
            );
        }
        let host = match url.host().ok_or("integration URL requires host")? {
            Host::Domain(name) if !name.ends_with('.') => name.into(),
            Host::Ipv4(ip) => ip.to_string(),
            Host::Ipv6(ip) => ip.to_string(),
            _ => return Err("invalid integration hostname".into()),
        };
        if !config
            .bootstrap_ips
            .iter()
            .all(|ip| rustwalld_dns_policy::is_unicast_destination(*ip))
        {
            return Err("integration bootstrap must be unicast".into());
        }
        if let Ok(ip) = host.parse::<std::net::IpAddr>()
            && config
                .bootstrap_ips
                .iter()
                .any(|pin| pin.to_canonical() != ip.to_canonical())
        {
            return Err("literal integration host must match bootstrap IPs".into());
        }
        let name = ServerName::try_from(host).map_err(|_| "invalid integration TLS name")?;
        let mut roots = RootCertStore::empty();
        if let Some(pem) = &config.ca_pem {
            if pem.is_empty() || pem.len() > 65536 {
                return Err("integration CA exceeds bounds".into());
            }
            let certs = CertificateDer::pem_slice_iter(pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| "invalid integration CA")?;
            if !(1..=32).contains(&certs.len()) {
                return Err("integration CA count outside bounds".into());
            }
            for cert in certs {
                roots.add(cert).map_err(|_| "invalid integration CA")?;
            }
        } else {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        let mut tls = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|_| "integration TLS configuration failed")?
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let file = std::fs::File::open(&config.token_file)
            .map_err(|_| "integration secret file unavailable")?;
        let metadata = file
            .metadata()
            .map_err(|_| "integration secret metadata unavailable")?;
        if !metadata.is_file() {
            return Err("integration secret must be a regular file".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err("integration secret requires private 0600 permissions".into());
            }
        }
        let mut secret = Zeroizing::new(String::new());
        file.take(4097)
            .read_to_string(&mut secret)
            .map_err(|_| "integration secret unreadable")?;
        if secret.len() > 4096 {
            return Err("integration secret exceeds 4 KiB".into());
        }
        *secret = secret.trim_end_matches(['\r', '\n']).to_owned();
        if secret.len() < 16
            || secret
                .bytes()
                .any(|b| b.is_ascii_control() || !b.is_ascii())
        {
            return Err("integration secret invalid".into());
        }
        if matches!(auth, Auth::Basic) && !secret.contains(':') {
            return Err("OPNsense secret must contain key:secret".into());
        }
        Ok(Self {
            url,
            ips: config.bootstrap_ips.clone(),
            name,
            tls: Arc::new(tls),
            secret,
            auth,
        })
    }
    pub async fn get(&self, path: &str, max: usize) -> Result<Vec<u8>, String> {
        let connector = TlsConnector::from(self.tls.clone());
        let port = self
            .url
            .port_or_known_default()
            .ok_or("integration port missing")?;
        let mut stream = None;
        for ip in &self.ips {
            let result = tokio::time::timeout(Duration::from_secs(3), async {
                let socket = TcpStream::connect(SocketAddr::new(*ip, port)).await?;
                connector.connect(self.name.clone(), socket).await
            })
            .await;
            if let Ok(Ok(connected)) = result {
                stream = Some(connected);
                break;
            }
        }
        let stream = stream.ok_or("integration connection or certificate validation failed")?;
        let mut builder = http1::Builder::new();
        builder.max_headers(32).max_buf_size(32768);
        let (mut sender, connection) = builder
            .handshake(TokioIo::new(stream))
            .await
            .map_err(|_| "integration HTTP handshake failed")?;
        let _driver = Driver(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let mut request = Request::builder()
            .method("GET")
            .uri(path)
            .header(
                header::HOST,
                &self.url[Position::BeforeHost..Position::AfterPort],
            )
            .header(header::ACCEPT, "application/json")
            .header(header::ACCEPT_ENCODING, "identity")
            .header(header::CONNECTION, "close");
        let value = match self.auth {
            Auth::ApiKey => Zeroizing::new(self.secret.to_string()),
            Auth::Bearer => Zeroizing::new(format!("Bearer {}", self.secret.as_str())),
            Auth::Basic => {
                use base64::Engine as _;
                Zeroizing::new(format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(self.secret.as_bytes())
                ))
            }
        };
        let key = if matches!(self.auth, Auth::ApiKey) {
            "X-API-Key"
        } else {
            "Authorization"
        };
        let mut credential =
            header::HeaderValue::from_str(&value).map_err(|_| "invalid integration credential")?;
        credential.set_sensitive(true);
        request = request.header(key, credential);
        let response = sender
            .send_request(
                request
                    .body(Empty::<Bytes>::new())
                    .map_err(|_| "integration request failed")?,
            )
            .await
            .map_err(|_| "integration response failed")?;
        if response.status() != StatusCode::OK {
            return Err(format!(
                "integration requires HTTP 200 (received {})",
                response.status().as_u16()
            ));
        }
        if response
            .headers()
            .get(header::CONTENT_ENCODING)
            .is_some_and(|value| value != "identity")
        {
            return Err("integration compression forbidden".into());
        }
        if !response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case("application/json")
            })
        {
            return Err("integration requires JSON".into());
        }
        if let Some(value) = response.headers().get(header::CONTENT_LENGTH)
            && value
                .to_str()
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .is_none_or(|length| length > max)
        {
            return Err("integration body exceeds bounds".into());
        }
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| "incomplete integration response")?;
            let data = frame.data_ref().ok_or("integration trailers forbidden")?;
            if data.len() > max.saturating_sub(bytes.len()) {
                return Err("integration body exceeds bounds".into());
            }
            bytes.extend_from_slice(data);
        }
        Ok(bytes)
    }
}
struct Driver(JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}
