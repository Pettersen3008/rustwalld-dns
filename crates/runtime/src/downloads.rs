//! Bounded control-plane downloads. This module is never used by DNS workers.
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::{Request, StatusCode, client::conn::http1, header};
use hyper_util::rt::TokioIo;
use ring::digest;
use rustwalld_dns_policy::{DownloadStamp, FilterSource, MAX_DOWNLOAD_BYTES, PolicyConfigSet};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpStream, task::JoinHandle, time::timeout};
use tokio_rustls::{
    TlsConnector,
    rustls::{
        ClientConfig, RootCertStore,
        crypto::ring as crypto,
        pki_types::{CertificateDer, ServerName, pem::PemObject},
    },
};
use url::{Host, Position, Url};

pub const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(15);
pub const MAX_CONFIG_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct Validators {
    etag: Option<String>,
    last_modified: Option<String>,
}
impl Validators {
    pub fn from_headers(headers: &hyper::HeaderMap) -> Self {
        fn single(headers: &hyper::HeaderMap, name: header::HeaderName) -> Option<&str> {
            let mut values = headers.get_all(name).iter();
            let value = values.next()?.to_str().ok()?;
            if values.next().is_some() {
                return None;
            }
            Some(value)
        }
        let etag = single(headers, header::ETAG)
            .filter(|tag| valid_etag(tag))
            .map(str::to_owned);
        let last_modified = single(headers, header::LAST_MODIFIED)
            .filter(|date| date.len() <= 128)
            .and_then(|date| httpdate::parse_http_date(date).ok())
            .map(httpdate::fmt_http_date);
        Self {
            etag,
            last_modified,
        }
    }
    pub fn usable(&self) -> bool {
        self.etag.is_some() || self.last_modified.is_some()
    }
    fn refreshed(&self, headers: &hyper::HeaderMap) -> Result<Self, String> {
        let next = Self::from_headers(headers);
        if (headers.contains_key(header::ETAG) && next.etag.is_none())
            || (headers.contains_key(header::LAST_MODIFIED) && next.last_modified.is_none())
        {
            return Err("invalid validators in HTTP 304".into());
        }
        if let (Some(old), Some(new)) = (&self.etag, &next.etag)
            && opaque_tag(old) != opaque_tag(new)
        {
            return Err("HTTP 304 entity tag contradicts the request".into());
        }
        if self.etag.is_none()
            && let (Some(old), Some(new)) = (&self.last_modified, &next.last_modified)
            && httpdate::parse_http_date(new).ok() > httpdate::parse_http_date(old).ok()
        {
            return Err("HTTP 304 modification date contradicts the request".into());
        }
        Ok(Self {
            etag: next.etag.or_else(|| self.etag.clone()),
            last_modified: next.last_modified.or_else(|| self.last_modified.clone()),
        })
    }
}
fn opaque_tag(tag: &str) -> &str {
    tag.strip_prefix("W/").unwrap_or(tag)
}
fn valid_etag(tag: &str) -> bool {
    let bytes = opaque_tag(tag).as_bytes();
    tag.len() <= 512
        && bytes.len() >= 2
        && bytes.first() == Some(&b'"')
        && bytes.last() == Some(&b'"')
        && bytes[1..bytes.len() - 1]
            .iter()
            .all(|byte| *byte == 0x21 || (0x23..=0x7e).contains(byte))
}
pub enum Fetch {
    Modified {
        text: String,
        stamp: DownloadStamp,
        validators: Validators,
    },
    NotModified {
        validators: Validators,
    },
}

// Stop at the API limit without allocating a second serialized configuration.
/// Validate that a reviewed configuration fits the management envelope.
pub fn validate_size(config: &PolicyConfigSet) -> Result<(), String> {
    struct LimitedSize(usize);
    impl std::io::Write for LimitedSize {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > MAX_CONFIG_BYTES.saturating_sub(self.0) {
                return Err(std::io::Error::other("configuration size limit"));
            }
            self.0 += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(LimitedSize(0), config)
        .map_err(|_| "downloaded candidate exceeds 16 MiB configuration API limit".into())
}

pub fn sha256(bytes: &[u8]) -> String {
    digest::digest(&digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn validate_config(config: &PolicyConfigSet) -> Result<(), String> {
    if config.filter_sources.len() > 64 {
        return Err("too many downloaded-list sources".into());
    }
    if config
        .filter_sources
        .iter()
        .any(|source| source.refresh_interval_secs.is_some())
    {
        validate_size(config)?;
    }
    for source in &config.filter_sources {
        if source.refresh_interval_secs.is_some_and(|interval| {
            !(rustwalld_dns_policy::MIN_REFRESH_INTERVAL
                ..=rustwalld_dns_policy::MAX_REFRESH_INTERVAL)
                .contains(&interval)
        }) {
            return Err("refresh interval must be 300 seconds through 30 days".into());
        }
        transport(source)?;
        let list = config
            .policies
            .iter()
            .find(|policy| policy.name == source.policy)
            .and_then(|policy| policy.lists.iter().find(|list| list.name == source.list))
            .ok_or("download source refers to a missing policy/list")?;
        if let Some(stamp) = &source.download
            && (stamp.bytes != list.rules.len() || stamp.sha256 != sha256(list.rules.as_bytes()))
        {
            return Err("download provenance does not match list text; clear the stamp before manual editing".into());
        }
    }
    Ok(())
}
pub(crate) fn validate_candidate(
    snapshot: &rustwalld_dns_policy::PolicySnapshot,
    index: usize,
) -> Result<(), String> {
    let source = snapshot
        .config()
        .filter_sources
        .get(index)
        .ok_or("unknown refresh source")?;
    let stats = snapshot
        .policies()
        .iter()
        .find(|policy| policy.name() == source.policy)
        .and_then(|policy| {
            policy
                .filters()
                .stats
                .iter()
                .find(|stats| stats.name == source.list)
        })
        .ok_or("compiled refresh target missing")?;
    if stats.raw == 0 {
        return Err("downloaded list has no rules".into());
    }
    validate_size(snapshot.config())?;
    Ok(())
}

fn transport(
    source: &FilterSource,
) -> Result<(Url, ServerName<'static>, Arc<ClientConfig>), String> {
    if source.url.len() > 2048
        || source.url.chars().any(char::is_control)
        || !(1..=8).contains(&source.bootstrap_ips.len())
    {
        return Err("source URL/IP counts outside bounds".into());
    }
    let url = Url::parse(&source.url).map_err(|_| "invalid source URL")?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port_or_known_default() == Some(0)
    {
        return Err("source requires HTTPS without user info or fragment".into());
    }
    let host = match url.host().ok_or("source URL requires a host")? {
        Host::Domain(name) => {
            if name.ends_with('.') {
                return Err("source host must not have a trailing root dot".into());
            }
            name.to_owned()
        }
        Host::Ipv4(ip) => ip.to_string(),
        Host::Ipv6(ip) => ip.to_string(),
    };
    if source.bootstrap_ips.iter().any(|ip| {
        let ip = ip.to_canonical();
        ip.is_unspecified()
            || ip.is_multicast()
            || matches!(ip, std::net::IpAddr::V4(ip) if ip.is_broadcast())
    }) {
        return Err("source bootstrap IP must be unicast".into());
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>()
        && source
            .bootstrap_ips
            .iter()
            .any(|pin| pin.to_canonical() != ip.to_canonical())
    {
        return Err("literal source IP must match every bootstrap IP".into());
    }
    let name = ServerName::try_from(host).map_err(|_| "invalid HTTPS authentication name")?;
    let mut roots = RootCertStore::empty();
    if let Some(pem) = &source.ca_pem {
        if pem.is_empty() || pem.len() > 65536 {
            return Err("source CA PEM outside bounds".into());
        }
        let certificates = CertificateDer::pem_slice_iter(pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "invalid source CA PEM")?;
        if !(1..=32).contains(&certificates.len()) {
            return Err("source CA certificate count outside bounds".into());
        }
        for certificate in certificates {
            roots
                .add(certificate)
                .map_err(|_| "invalid source CA certificate")?;
        }
    } else {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    let mut tls = ClientConfig::builder_with_provider(Arc::new(crypto::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|_| "TLS protocol configuration failed")?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok((url, name, Arc::new(tls)))
}

struct Driver(JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub async fn fetch(source: &FilterSource) -> Result<(String, DownloadStamp), String> {
    match fetch_conditional(source, None).await? {
        Fetch::Modified { text, stamp, .. } => Ok((text, stamp)),
        Fetch::NotModified { .. } => Err("unsolicited HTTP 304".into()),
    }
}
pub async fn fetch_conditional(
    source: &FilterSource,
    validators: Option<&Validators>,
) -> Result<Fetch, String> {
    let (url, name, tls) = transport(source)?;
    timeout(DOWNLOAD_TIMEOUT, async {
        let port = url.port_or_known_default().ok_or("invalid source port")?;
        let connector = TlsConnector::from(tls);
        let mut stream = None;
        for ip in &source.bootstrap_ips {
            let attempt = timeout(Duration::from_secs(3), async {
                let socket = TcpStream::connect(SocketAddr::new(*ip, port)).await?;
                connector.connect(name.clone(), socket).await
            })
            .await;
            if let Ok(Ok(connected)) = attempt {
                stream = Some(connected);
                break;
            }
        }
        let stream = stream.ok_or("HTTPS connection or certificate validation failed")?;
        let (mut sender, connection) = http1::Builder::new()
            .max_headers(32)
            .max_buf_size(65536)
            .handshake(TokioIo::new(stream))
            .await
            .map_err(|_| "invalid HTTP connection")?;
        let _driver = Driver(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let mut request = Request::builder()
            .method("GET")
            .uri(&url[Position::BeforePath..Position::AfterQuery])
            .header(
                header::HOST,
                &url[Position::BeforeHost..Position::AfterPort],
            )
            .header(header::ACCEPT, "text/plain, application/octet-stream")
            .header(header::ACCEPT_ENCODING, "identity")
            .header(header::CONNECTION, "close")
            .header(header::USER_AGENT, "rustwalld-dns/0.1.0");
        if let Some(etag) = validators.and_then(|values| values.etag.as_ref()) {
            request = request.header(header::IF_NONE_MATCH, etag);
        } else if let Some(date) = validators.and_then(|values| values.last_modified.as_ref()) {
            request = request.header(header::IF_MODIFIED_SINCE, date);
        }
        let request = request
            .body(Empty::<Bytes>::new())
            .map_err(|_| "invalid HTTP request")?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| "invalid HTTP response")?;
        if response.status() == StatusCode::NOT_MODIFIED {
            let previous = validators
                .filter(|values| values.usable())
                .ok_or("unsolicited HTTP 304")?;
            // RFC 9110: a 304 has no content. Content-Length can describe the
            // representation, not a body to read. Close this one-use connection.
            return Ok(Fetch::NotModified {
                validators: previous.refreshed(response.headers())?,
            });
        }
        if response.status() != StatusCode::OK {
            return Err(format!(
                "download requires HTTP 200; received {}",
                response.status().as_u16()
            ));
        }
        if response
            .headers()
            .get(header::CONTENT_ENCODING)
            .is_some_and(|value| value != "identity")
        {
            return Err("compressed downloads are not supported".into());
        }
        if let Some(content_type) = response.headers().get(header::CONTENT_TYPE) {
            let media = content_type
                .to_str()
                .map_err(|_| "invalid content type")?
                .split(';')
                .next()
                .unwrap_or("")
                .trim();
            if !media.eq_ignore_ascii_case("text/plain")
                && !media.eq_ignore_ascii_case("application/octet-stream")
            {
                return Err("download must be plain UTF-8 list text".into());
            }
        }
        if let Some(length) = response.headers().get(header::CONTENT_LENGTH) {
            let length = length
                .to_str()
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or("invalid content length")?;
            if length > MAX_DOWNLOAD_BYTES as u64 {
                return Err("download exceeds 8 MiB".into());
            }
        }
        let validators = Validators::from_headers(response.headers());
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| "incomplete HTTP body")?;
            if let Some(data) = frame.data_ref() {
                if data.len() > MAX_DOWNLOAD_BYTES.saturating_sub(bytes.len()) {
                    return Err("download exceeds 8 MiB".into());
                }
                bytes.extend_from_slice(data);
            } else {
                return Err("HTTP trailers are not supported".into());
            }
        }
        if bytes.is_empty() {
            return Err("downloaded list is empty".into());
        }
        let stamp = DownloadStamp {
            retrieved_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "system clock before Unix epoch")?
                .as_secs(),
            sha256: sha256(&bytes),
            bytes: bytes.len(),
        };
        let text = String::from_utf8(bytes).map_err(|_| "downloaded list is not UTF-8")?;
        Ok(Fetch::Modified {
            text,
            stamp,
            validators,
        })
    })
    .await
    .map_err(|_| "download deadline exceeded".to_string())?
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    fn config() -> PolicyConfigSet {
        let mut config = PolicyConfigSet::default();
        config.policies[0].lists = vec![rustwalld_dns_filter::ListInput {
            name: "remote".into(),
            action: rustwalld_dns_filter::Action::Block,
            rules: "ads.test\n".into(),
        }];
        config.filter_sources = vec![FilterSource {
            policy: "default".into(),
            list: "remote".into(),
            url: "https://lists.test/domains.txt".into(),
            bootstrap_ips: vec!["127.0.0.1".parse().unwrap()],
            ca_pem: None,
            refresh_interval_secs: None,
            download: Some(DownloadStamp {
                retrieved_at: 1,
                bytes: 9,
                sha256: sha256(b"ads.test\n"),
            }),
        }];
        config
    }
    fn headers(etag: Option<&str>, date: Option<&str>) -> hyper::HeaderMap {
        let mut headers = hyper::HeaderMap::new();
        if let Some(value) = etag {
            headers.insert(header::ETAG, value.parse().unwrap());
        }
        if let Some(value) = date {
            headers.insert(header::LAST_MODIFIED, value.parse().unwrap());
        }
        headers
    }
    #[test]
    fn validators_are_bounded_single_fields_and_dates_are_canonical() {
        for tag in ["\"\"", "\"v1\"", "W/\"v1\"", "\"a,b\\c!~\""] {
            let values = Validators::from_headers(&headers(Some(tag), None));
            assert_eq!(values.etag.as_deref(), Some(tag));
        }
        for tag in [
            "*",
            "v1",
            "w/\"v1\"",
            "\"a\", \"b\"",
            "\"a b\"",
            "\"a\"b\"",
            "\"a\" ",
            "W/W/\"v1\"",
        ] {
            assert!(
                !Validators::from_headers(&headers(Some(tag), None)).usable(),
                "{tag}"
            );
        }
        assert!(
            Validators::from_headers(&headers(Some(&format!("\"{}\"", "x".repeat(510))), None))
                .usable()
        );
        assert!(
            !Validators::from_headers(&headers(Some(&format!("\"{}\"", "x".repeat(511))), None))
                .usable()
        );
        let mut map = headers(Some("\"one\""), None);
        map.append(header::ETAG, "\"two\"".parse().unwrap());
        assert!(!Validators::from_headers(&map).usable());
        map.clear();
        map.insert(
            header::ETAG,
            hyper::header::HeaderValue::from_bytes(b"\"\xff\"").unwrap(),
        );
        assert!(!Validators::from_headers(&map).usable());
        for date in [
            "Sun, 06 Nov 1994 08:49:37 GMT",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
        ] {
            let value = Validators::from_headers(&headers(None, Some(date)));
            assert_eq!(
                value.last_modified.as_deref(),
                Some("Sun, 06 Nov 1994 08:49:37 GMT")
            );
        }
        for date in [
            "nonsense",
            "Sun, 06 Nov 1994 08:49:60 GMT",
            "Mon, 06 Nov 1994 08:49:37 GMT",
            "Wed, 31 Dec 1969 23:59:59 GMT",
            "Fri, 31 Dec 10000 23:59:59 GMT",
            "Sun, 31 Feb 1994 08:49:37 GMT",
        ] {
            assert!(
                !Validators::from_headers(&headers(None, Some(date))).usable(),
                "{date}"
            );
        }
        assert!(
            Validators::from_headers(&headers(None, Some("Fri, 31 Dec 9999 23:59:59 GMT")))
                .usable()
        );
        let mut dates = headers(None, Some("Sun, 06 Nov 1994 08:49:37 GMT"));
        dates.append(
            header::LAST_MODIFIED,
            "Sun, 06 Nov 1994 08:49:37 GMT".parse().unwrap(),
        );
        assert!(!Validators::from_headers(&dates).usable());
    }
    #[test]
    fn not_modified_validation_uses_weak_tags_and_rejects_contradictions() {
        let old = Validators::from_headers(&headers(
            Some("\"v1\""),
            Some("Sun, 06 Nov 1994 08:49:37 GMT"),
        ));
        assert_eq!(old.refreshed(&hyper::HeaderMap::new()).unwrap(), old);
        assert_eq!(
            old.refreshed(&headers(Some("W/\"v1\""), None))
                .unwrap()
                .etag
                .as_deref(),
            Some("W/\"v1\"")
        );
        for tag in ["\"v2\"", "bad", "*", "\"a\",\"b\""] {
            assert!(old.refreshed(&headers(Some(tag), None)).is_err());
        }
        let mut duplicates = headers(Some("\"v1\""), None);
        duplicates.append(header::ETAG, "\"v1\"".parse().unwrap());
        assert!(old.refreshed(&duplicates).is_err());
        assert!(old.refreshed(&headers(None, Some("invalid"))).is_err());
        let date = Validators::from_headers(&headers(None, Some("Sun, 06 Nov 1994 08:49:37 GMT")));
        assert!(
            date.refreshed(&headers(None, Some("Sun, 06 Nov 1994 08:49:38 GMT")))
                .is_err()
        );
        // If-None-Match is authoritative even if Last-Modified moves forward.
        assert!(
            old.refreshed(&headers(None, Some("Sun, 06 Nov 1994 08:49:38 GMT")))
                .is_ok()
        );
        assert!(date.refreshed(&headers(Some("\"new\""), None)).is_ok());
    }
    #[test]
    fn source_url_pins_trust_fingerprints_counts_and_legacy_shape_are_validated() {
        let original = config();
        assert!(validate_config(&original).is_ok());
        assert!(rustwalld_dns_policy::PolicySnapshot::compile(original.clone(), 1).is_ok());
        for url in [
            "http://lists.test/a",
            "file:///etc/passwd",
            "https://user:pass@lists.test/a",
            "https://lists.test/a#fragment",
            "https://lists.test:0/a",
            "https://127.0.0.2/a",
            "https://lists.test./a",
            "https://lists.test/\n",
        ] {
            let mut config = original.clone();
            config.filter_sources[0].url = url.into();
            assert!(validate_config(&config).is_err(), "{url}");
        }
        for ip in [
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "ff02::1",
            "::ffff:0.0.0.0",
            "::ffff:224.0.0.1",
        ] {
            let mut config = original.clone();
            config.filter_sources[0].bootstrap_ips = vec![ip.parse().unwrap()];
            assert!(validate_config(&config).is_err(), "{ip}");
        }
        let mut config = original.clone();
        config.filter_sources[0].ca_pem = Some("not a certificate".into());
        assert!(validate_config(&config).is_err());
        let mut config = original.clone();
        config.policies[0].lists[0].rules.push_str("edited.test\n");
        assert!(validate_config(&config).is_err());
        config.filter_sources[0].download = None;
        assert!(validate_config(&config).is_ok());
        let mut config = original.clone();
        config.filter_sources.push(config.filter_sources[0].clone());
        assert!(rustwalld_dns_policy::PolicySnapshot::compile(config, 1).is_err());
        let mut config = original.clone();
        config.filter_sources[0].list = "missing".into();
        assert!(validate_config(&config).is_err());
        assert!(rustwalld_dns_policy::PolicySnapshot::compile(config, 1).is_err());
        let mut config = original.clone();
        config.filter_sources[0].bootstrap_ips = vec![];
        assert!(validate_config(&config).is_err());
        let mut config = original.clone();
        config.filter_sources[0].bootstrap_ips = vec!["127.0.0.1".parse().unwrap(); 9];
        assert!(validate_config(&config).is_err());
        let mut config = original.clone();
        config.filter_sources[0]
            .bootstrap_ips
            .push("::ffff:127.0.0.1".parse().unwrap());
        assert!(rustwalld_dns_policy::PolicySnapshot::compile(config, 1).is_err());
        let mut config = original.clone();
        config.filter_sources = vec![config.filter_sources[0].clone(); 65];
        assert!(validate_config(&config).is_err());
        assert!(rustwalld_dns_policy::PolicySnapshot::compile(config, 1).is_err());
        let value = serde_json::to_value(PolicyConfigSet::default()).unwrap();
        assert!(value.get("filter_sources").is_none());
        for interval in [
            0,
            299,
            300,
            86400,
            rustwalld_dns_policy::MAX_REFRESH_INTERVAL,
            rustwalld_dns_policy::MAX_REFRESH_INTERVAL + 1,
            u64::MAX,
        ] {
            let mut config = original.clone();
            config.filter_sources[0].refresh_interval_secs = Some(interval);
            let valid = (rustwalld_dns_policy::MIN_REFRESH_INTERVAL
                ..=rustwalld_dns_policy::MAX_REFRESH_INTERVAL)
                .contains(&interval);
            assert_eq!(validate_config(&config).is_ok(), valid);
            assert_eq!(
                rustwalld_dns_policy::PolicySnapshot::compile(config, 1).is_ok(),
                valid
            );
        }
        assert!(
            serde_json::to_value(&original).unwrap()["filter_sources"][0]
                .get("refresh_interval_secs")
                .is_none()
        );
    }

    #[test]
    fn scheduled_configs_reject_json_amplification_before_compilation() {
        let mut config = config();
        config.filter_sources[0].download = None;
        // An otherwise-small source can expand sixfold when JSON escaped.
        config.policies[0].lists[0].rules =
            format!("#{}\nads.test\n", "\0".repeat(3 * 1024 * 1024));
        assert!(config.policies[0].lists[0].rules.len() < MAX_DOWNLOAD_BYTES);
        assert!(validate_config(&config).is_ok()); // Legacy manual-only file configuration.
        config.filter_sources[0].refresh_interval_secs = Some(300);
        assert!(validate_config(&config).unwrap_err().contains("16 MiB"));
    }
}
