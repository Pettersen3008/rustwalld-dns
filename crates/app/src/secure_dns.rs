//! DoT/DoH adapters. HTTP/TLS handling stays off the dedicated DNS executor.
use crate::{listener::Activity, tls::SecureListener};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{ConnectInfo, State},
    http::{Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
    serve::Listener,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rustwalld_dns_core::{Engine, Transport};
use std::{net::IpAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
#[derive(Clone)]
pub struct SecureDns {
    engine: Arc<Engine>,
    executor: tokio::runtime::Handle,
    slots: Arc<Semaphore>,
    hosts: Vec<String>,
}
impl SecureDns {
    pub fn new(
        engine: Arc<Engine>,
        executor: tokio::runtime::Handle,
        requests: usize,
        hosts: Vec<String>,
    ) -> Self {
        Self {
            engine,
            executor,
            slots: Arc::new(Semaphore::new(requests.clamp(1, 512))),
            hosts,
        }
    }
    pub fn with_hostnames(mut self, hosts: Vec<String>) -> Self {
        self.hosts = hosts;
        self
    }
    async fn answer(
        &self,
        bytes: Vec<u8>,
        client: IpAddr,
        permit: OwnedSemaphorePermit,
    ) -> Option<Wire> {
        let engine = self.engine.clone();
        // A disconnected HTTP/TLS client cannot free this permit while a DNS
        // task still owns packet/cache/upstream work on the other executor.
        tokio::time::timeout(
            Duration::from_secs(30),
            self.executor.spawn(async move {
                engine
                    .answer(&bytes, client, Transport::Tcp)
                    .await
                    .map(|bytes| Wire {
                        bytes,
                        _permit: permit,
                    })
            }),
        )
        .await
        .ok()?
        .ok()?
    }
}
struct Wire {
    bytes: Vec<u8>,
    _permit: OwnedSemaphorePermit,
}
impl AsRef<[u8]> for Wire {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
pub fn doh_router(state: SecureDns) -> Router {
    Router::new()
        .route("/dns-query", get(doh).post(doh))
        .with_state(state)
}
async fn doh(
    State(state): State<SecureDns>,
    ConnectInfo(activity): ConnectInfo<Activity>,
    request: Request<Body>,
) -> Response {
    let Some(peer) = activity.peer() else {
        return StatusCode::FORBIDDEN.into_response();
    };
    if !state.engine.snapshot().permits(peer.ip()) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .or_else(|| {
            request
                .uri()
                .authority()
                .map(|authority| authority.as_str())
        });
    if !host.is_some_and(|host| crate::api::host_allowed(host, &state.hosts)) {
        return StatusCode::MISDIRECTED_REQUEST.into_response();
    }
    let Ok(permit) = state.slots.clone().try_acquire_owned() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    if request
        .headers()
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| !accepts_dns(value))
    {
        return StatusCode::NOT_ACCEPTABLE.into_response();
    }
    let bytes = if request.method() == axum::http::Method::GET {
        if request.uri().query().is_none_or(|query| query.len() > 8192) {
            return StatusCode::BAD_REQUEST.into_response();
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Parameters {
            dns: String,
        }
        let Ok(axum::extract::Query(parameters)) =
            axum::extract::Query::<Parameters>::try_from_uri(request.uri())
        else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        match URL_SAFE_NO_PAD.decode(parameters.dns) {
            Ok(bytes) => bytes,
            Err(_) => return StatusCode::BAD_REQUEST.into_response(),
        }
    } else if request.method() == axum::http::Method::POST {
        if !request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("application/dns-message"))
        {
            return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
        }
        match tokio::time::timeout(
            Duration::from_secs(5),
            axum::body::to_bytes(request.into_body(), 65535),
        )
        .await
        {
            Ok(Ok(bytes)) => bytes.to_vec(),
            Ok(Err(_)) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
            Err(_) => return StatusCode::REQUEST_TIMEOUT.into_response(),
        }
    } else {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    };
    if bytes.len() < 12 {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let _busy = activity.enter();
    let Some(wire) = state.answer(bytes, peer.ip(), permit).await else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    (
        [
            (header::CONTENT_TYPE, "application/dns-message"),
            (header::CACHE_CONTROL, "no-store"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        Bytes::from_owner(wire),
    )
        .into_response()
}
// RFC 9110: a more specific media range overrides a wildcard, including q=0.
fn accepts_dns(value: &str) -> bool {
    let mut selected: Option<(u8, f32)> = None;
    for range in value.split(',') {
        let mut parts = range.split(';');
        let media = parts.next().unwrap_or("").trim();
        let rank = if media.eq_ignore_ascii_case("application/dns-message") {
            2
        } else if media.eq_ignore_ascii_case("application/*") {
            1
        } else if media == "*/*" {
            0
        } else {
            continue;
        };
        let mut quality = 1.0;
        let mut seen = false;
        for part in parts {
            if let Some((name, value)) = part.trim().split_once('=')
                && name.eq_ignore_ascii_case("q")
            {
                if seen
                    || value.len() > 5
                    || value.bytes().any(|b| !b.is_ascii_digit() && b != b'.')
                {
                    return false;
                }
                seen = true;
                let Ok(parsed) = value.parse::<f32>() else {
                    return false;
                };
                if !(0.0..=1.0).contains(&parsed) {
                    return false;
                }
                quality = parsed;
            }
        }
        if selected.is_none_or(|(old_rank, old_q)| {
            rank > old_rank || (rank == old_rank && quality > old_q)
        }) {
            selected = Some((rank, quality));
        }
    }
    selected.is_some_and(|(_, quality)| quality > 0.0)
}

pub async fn run_dot(
    mut listener: SecureListener,
    state: SecureDns,
    stop: CancellationToken,
) -> std::io::Result<()> {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            _=stop.cancelled()=>break,
            _=tasks.join_next(),if !tasks.is_empty()=>{},
            (mut stream,peer)=listener.accept()=>{
                if !state.engine.snapshot().permits(peer.ip()) {continue;}
                let state=state.clone();let cancel=stop.clone();
                tasks.spawn(async move {
                    // Both connection lifetime and frame completion are bounded.
                    let work=async {
                        for _ in 0..4096 {
                            let length=match tokio::time::timeout(Duration::from_secs(30),stream.read_u16()).await {Ok(Ok(length)) if length>=12=>length,_=>break};
                            let Ok(permit)=state.slots.clone().try_acquire_owned() else {break;};
                            let mut bytes=vec![0u8;usize::from(length)];
                            if !matches!(tokio::time::timeout(Duration::from_secs(5),stream.read_exact(&mut bytes)).await,Ok(Ok(_))) {break;}
                            let _busy=stream.activity().enter();
                            let Some(wire)=state.answer(bytes,peer.ip(),permit).await else {break;};
                            let Ok(length)=u16::try_from(wire.bytes.len()) else {break;};
                            if !matches!(tokio::time::timeout(Duration::from_secs(5),async {stream.write_u16(length).await?;stream.write_all(&wire.bytes).await}).await,Ok(Ok(()))) {break;}
                        }
                    };
                    tokio::select! {_=cancel.cancelled()=>{},_=tokio::time::timeout(Duration::from_secs(600),work)=>{}}
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[cfg(test)]
mod accept_tests {
    #[test]
    fn explicit_refusal_overrides_wildcard() {
        for value in [
            "application/dns-message;q=0, */*;q=1",
            "text/html",
            "application/dns-message;q=NaN",
            "application/dns-message;q=1.1",
        ] {
            assert!(!super::accepts_dns(value));
        }
        for value in [
            "application/dns-message",
            "APPLICATION/DNS-MESSAGE;q=0.5",
            "text/html, application/*;q=0.2",
            "*/*",
        ] {
            assert!(super::accepts_dns(value));
        }
    }
}
