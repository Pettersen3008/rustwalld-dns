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
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    net::TcpStream,
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
};
use tokio_rustls::{TlsConnector, client::TlsStream, rustls::pki_types::ServerName};
const DNS_LIMIT: usize = 65535;

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
                idle: Mutex::new(vec![]),
                requests: Arc::new(Semaphore::new(*max_connections)),
                physical: Arc::new(Semaphore::new(*max_connections)),
            }))
        })
        .collect()
}

pub(super) struct HttpsPool {
    address: SocketAddr,
    name: ServerName<'static>,
    connector: TlsConnector,
    uri: Uri,
    idle: Mutex<Vec<(Connection, Instant)>>,
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
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.driver.abort();
    }
}
// Rust drops struct fields in declaration order, including task cancellation
// before its first poll. TLS disposal must precede waking a replacement owner.
struct PhysicalConnection {
    connection: h2::client::Connection<TlsStream<TcpStream>, Bytes>,
    _permit: OwnedSemaphorePermit,
}
impl HttpsPool {
    async fn connect(&self) -> Result<Connection, ResolveError> {
        // This permit lives in the driver, so replacement must wait for a cancelled
        // driver's actual socket disposal, not just cancellation of its caller.
        let physical = self
            .physical
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| ResolveError::Unavailable)?;
        let socket = TcpStream::connect(self.address).await?;
        socket.set_nodelay(true)?;
        let stream = self.connector.connect(self.name.clone(), socket).await?;
        if stream.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
            return Err(ResolveError::Failure(FailureKind::TlsProtocol));
        }
        let (sender, connection) = h2::client::Builder::new()
            .initial_window_size(DNS_LIMIT as u32)
            .initial_connection_window_size(DNS_LIMIT as u32)
            .max_frame_size(16384)
            .max_header_list_size(16384)
            .header_table_size(4096)
            .max_concurrent_streams(0) // no server-initiated streams
            .initial_max_send_streams(1)
            .max_concurrent_reset_streams(8)
            .max_send_buffer_size(DNS_LIMIT)
            .enable_push(false)
            .handshake(stream)
            .await?;
        let owned = PhysicalConnection {
            connection,
            _permit: physical,
        };
        let driver = tokio::spawn(async move {
            // Move the complete guard, avoiding disjoint field captures.
            let mut owned = owned;
            let _ = (&mut owned.connection).await;
        });
        Ok(Connection { sender, driver })
    }
    pub async fn exchange(&self, request: &Message) -> Result<Message, ResolveError> {
        let _request = self
            .requests
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| ResolveError::Unavailable)?;
        let reused = loop {
            let candidate = self.idle.lock().unwrap_or_else(|e| e.into_inner()).pop();
            match candidate {
                Some((connection, used))
                    if used.elapsed() < Duration::from_secs(60)
                        && !connection.driver.is_finished() =>
                {
                    break Some(connection);
                }
                Some((connection, _)) => drop(connection),
                None => break None,
            }
        };
        let was_reused = reused.is_some();
        let mut connection = match reused {
            Some(c) => c,
            None => self.connect().await?,
        };
        let mut query = request.clone();
        query.metadata.id = 0; // HTTP stream correlates each response (RFC 8484).
        let bytes = Bytes::from(query.to_vec().map_err(|_| ResolveError::Encoding)?);
        if bytes.len() > DNS_LIMIT {
            return Err(ResolveError::Encoding);
        }
        let result = post(&mut connection, &self.uri, &query, bytes.clone()).await;
        let response = match result {
            Err(ResolveError::Http2(ref error))
                if was_reused
                    && (error.is_io()
                        || (error.is_go_away()
                            && error.reason() == Some(h2::Reason::NO_ERROR))) =>
            {
                drop(connection);
                connection = self.connect().await?;
                post(&mut connection, &self.uri, &query, bytes).await?
            }
            result => result?,
        };
        self.idle
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((connection, Instant::now()));
        Ok(response)
    }
}
async fn post(
    connection: &mut Connection,
    uri: &Uri,
    query: &Message,
    bytes: Bytes,
) -> Result<Message, ResolveError> {
    std::future::poll_fn(|cx| connection.sender.poll_ready(cx)).await?;
    let request = Request::builder()
        .method("POST")
        .uri(uri.clone())
        .header(header::CONTENT_TYPE, "application/dns-message")
        .header(header::ACCEPT, "application/dns-message")
        .header(header::CONTENT_LENGTH, bytes.len())
        .body(())
        .map_err(|_| ResolveError::Encoding)?;
    let (response, mut send) = connection.sender.send_request(request, false)?;
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
