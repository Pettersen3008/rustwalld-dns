//! HTTP admission and rendering around the reusable durable control service.
mod authentication;
mod diagnostics;
mod downloads;
mod history;
mod migration;
mod privacy;
mod read;
mod revisions;
mod setup;
mod temporary;
use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, FromRequest, FromRequestParts, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, get, post},
};
use diagnostics::{explain, metrics, upstreams};
use downloads::{preview_download, queue_refresh, refresh_status};
use read::{
    clients, filter_sources, filters, health, policies, queries, status, temporary_exceptions,
};
use revisions::{
    clear_shadow, config, promote, promote_shadow, revision, revisions, rollback, shadow,
    shadow_config, test,
};
use rustwalld_dns_core::PolicyVersion;
use rustwalld_dns_runtime::{ControlError, ControlService};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;
pub use setup::Setup;
use std::{net::IpAddr, sync::Arc};
use subtle::ConstantTimeEq;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Request bodies (configurations, previews) are bounded before parsing.
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
/// Concurrent management requests.
const API_SLOTS: usize = 32;
/// Concurrent requests that clone, serialize or compile a whole configuration.
/// Configurations carry list text (up to 256 MiB), so this bounds the memory
/// the management API can add to the DNS process.
const HEAVY_SLOTS: usize = 2;

pub struct AppState {
    pub control: Arc<ControlService>,
    api_slots: Arc<Semaphore>,
    heavy_slots: Arc<Semaphore>,
    /// SHA-256 of the bearer token. Comparing fixed-size digests in constant
    /// time reveals neither the token's content nor its length.
    token: ring::digest::Digest,
    hostnames: Vec<String>,
    identity: Option<Arc<crate::auth::Identity>>,
    integration_stop: tokio_util::sync::CancellationToken,
    setup: Setup,
    integrations: Vec<Arc<crate::integrations::Adapter>>,
    login_budget: std::sync::Mutex<authentication::LoginBudget>,
}
impl AppState {
    pub fn new(control: Arc<ControlService>, token: &str) -> Self {
        Self {
            control,
            api_slots: Arc::new(Semaphore::new(API_SLOTS)),
            heavy_slots: Arc::new(Semaphore::new(HEAVY_SLOTS)),
            token: digest(token.as_bytes()),
            hostnames: vec![],
            identity: None,
            integration_stop: tokio_util::sync::CancellationToken::new(),
            setup: Setup::default(),
            integrations: vec![],
            login_budget: std::sync::Mutex::new(authentication::LoginBudget::default()),
        }
    }
    pub fn with_hostnames(mut self, hostnames: Vec<String>) -> Self {
        self.hostnames = hostnames;
        self
    }
    pub fn with_identity(mut self, identity: Option<Arc<crate::auth::Identity>>) -> Self {
        self.identity = identity;
        self
    }
    pub fn with_shutdown(mut self, stop: tokio_util::sync::CancellationToken) -> Self {
        self.integration_stop = stop;
        self
    }
    pub fn with_setup(mut self, setup: Setup) -> Self {
        self.setup = setup;
        self
    }
    pub fn with_integrations(
        mut self,
        integrations: Vec<Arc<crate::integrations::Adapter>>,
    ) -> Self {
        self.integrations = integrations;
        self
    }
    /// Admission for configuration-sized work; never waits.
    fn heavy(&self) -> Result<OwnedSemaphorePermit, ApiError> {
        self.heavy_slots.clone().try_acquire_owned().map_err(|_| {
            ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                "configuration request limit".into(),
            )
        })
    }
}
fn digest(bytes: &[u8]) -> ring::digest::Digest {
    ring::digest::digest(&ring::digest::SHA256, bytes)
}

#[derive(Debug)]
pub struct ApiError(pub StatusCode, pub String);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error": self.1}))).into_response()
    }
}
impl From<ControlError> for ApiError {
    fn from(error: ControlError) -> Self {
        let code = match &error {
            ControlError::Invalid(_) => StatusCode::UNPROCESSABLE_ENTITY,
            ControlError::Conflict(_) => StatusCode::CONFLICT,
            ControlError::Stale => StatusCode::PRECONDITION_FAILED,
            ControlError::MissingRevision => StatusCode::NOT_FOUND,
            ControlError::Upstream(_) => StatusCode::BAD_GATEWAY,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        };
        Self(code, error.to_string())
    }
}
fn invalid(error: impl ToString) -> ApiError {
    ApiError(StatusCode::UNPROCESSABLE_ENTITY, error.to_string())
}
fn unavailable(error: impl ToString) -> ApiError {
    ApiError(StatusCode::SERVICE_UNAVAILABLE, error.to_string())
}

/// `axum::Json` whose rejections use this API's `{"error": ...}` shape.
pub(crate) struct ApiJson<T>(pub T);
impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for ApiJson<T> {
    type Rejection = ApiError;
    async fn from_request(request: Request, state: &S) -> Result<Self, ApiError> {
        Json::<T>::from_request(request, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(|rejection| ApiError(rejection.status(), rejection.body_text()))
    }
}
/// `axum::extract::Path` with JSON rejections.
pub(crate) struct ApiPath<T>(pub T);
impl<S: Send + Sync, T: DeserializeOwned + Send> FromRequestParts<S> for ApiPath<T> {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        axum::extract::Path::<T>::from_request_parts(parts, state)
            .await
            .map(|axum::extract::Path(value)| Self(value))
            .map_err(|rejection| ApiError(rejection.status(), rejection.body_text()))
    }
}
/// `axum::extract::Query` with JSON rejections.
pub(crate) struct ApiQuery<T>(pub T);
impl<S: Send + Sync, T: DeserializeOwned> FromRequestParts<S> for ApiQuery<T> {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        axum::extract::Query::<T>::from_request_parts(parts, state)
            .await
            .map(|axum::extract::Query(value)| Self(value))
            .map_err(|rejection| ApiError(rejection.status(), rejection.body_text()))
    }
}

/// Serialize a possibly configuration-sized body on a blocking thread, straight
/// from borrowed data: no clone and no intermediate `serde_json::Value` tree.
async fn json_body<T: Serialize + Send + 'static>(
    status: StatusCode,
    tag: Option<String>,
    value: T,
    permit: Option<OwnedSemaphorePermit>,
) -> Result<Response, ApiError> {
    json_body_inner(status, tag, value, permit, None).await
}
async fn json_body_guard<T: Serialize + Send + 'static>(
    status: StatusCode,
    tag: Option<String>,
    value: T,
    guard: Arc<crate::integrations::Work>,
) -> Result<Response, ApiError> {
    json_body_inner(status, tag, value, None, Some(guard)).await
}
async fn json_body_inner<T: Serialize + Send + 'static>(
    status: StatusCode,
    tag: Option<String>,
    value: T,
    permit: Option<OwnedSemaphorePermit>,
    guard: Option<Arc<dyn Send + Sync>>,
) -> Result<Response, ApiError> {
    let bytes = tokio::task::spawn_blocking(move || {
        serde_json::to_vec(&value).map(|bytes| AdmittedJson {
            bytes,
            _permit: permit,
            _guard: guard,
        })
    })
    .await
    .map_err(unavailable)?
    .map_err(unavailable)?;
    let mut response = (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        Bytes::from_owner(bytes),
    )
        .into_response();
    if let Some(tag) = tag.and_then(|tag| HeaderValue::from_str(&tag).ok()) {
        response.headers_mut().insert(header::ETAG, tag);
    }
    Ok(response)
}

// The permit follows serialized bytes through cancellation and slow writes,
// including any shared Bytes clones held by HTTP. Dropping a handler cannot
// admit another large response while a blocking serializer or socket holds it.
struct AdmittedJson {
    bytes: Vec<u8>,
    _permit: Option<OwnedSemaphorePermit>,
    _guard: Option<Arc<dyn Send + Sync>>,
}
impl AsRef<[u8]> for AdmittedJson {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// The version a mutation expects, from its required `If-Match` tag.
fn required_version(headers: &HeaderMap) -> Result<PolicyVersion, ApiError> {
    let value = headers.get(header::IF_MATCH).ok_or_else(|| {
        ApiError(
            StatusCode::PRECONDITION_REQUIRED,
            "If-Match with the current configuration ETag is required".into(),
        )
    })?;
    Ok(value
        .to_str()
        .ok()
        .and_then(revisions::parse_tag)
        // An unparseable tag can never match; report it as stale.
        .unwrap_or(PolicyVersion {
            active: 0,
            shadow: None,
        }))
}

pub fn router(state: Arc<AppState>) -> Router {
    router_with_ui(state, None)
}
pub fn router_with_ui(state: Arc<AppState>, web_root: Option<std::path::PathBuf>) -> Router {
    let protected = Router::new()
        .route(
            "/api/v1/privacy",
            get(privacy::get)
                .put(privacy::change)
                .layer(DefaultBodyLimit::max(4096)),
        )
        .route("/api/v1/auth/session", get(authentication::session))
        .route("/api/v1/auth/logout", post(authentication::logout))
        .route(
            "/api/v1/auth/tokens",
            get(authentication::tokens)
                .post(authentication::create_token)
                .layer(DefaultBodyLimit::max(4096)),
        )
        .route(
            "/api/v1/auth/tokens/{id}",
            axum::routing::delete(authentication::revoke_token),
        )
        .route("/api/v1/auth/recover", post(authentication::recover))
        .route("/api/v1/setup", get(setup::setup))
        .route("/api/v1/integrations", get(setup::inventory))
        .route("/api/v1/integrations/{name}/refresh", post(setup::refresh))
        .route("/api/v1/integrations/{name}/preview", post(setup::peer))
        .route("/api/v1/queries", get(queries))
        .route("/api/v1/queries/{id}/explain", get(history::explain))
        .route("/api/v1/clients", get(clients))
        .route("/api/v1/policies", get(policies))
        .route("/api/v1/service-catalog", get(read::service_catalog))
        .route("/api/v1/temporary-exceptions", get(temporary_exceptions))
        .route("/api/v1/temporary-actions", post(temporary::action))
        .route("/api/v1/filter-lists", get(filters))
        .route("/api/v1/filter-sources", get(filter_sources))
        .route("/api/v1/filter-sources/preview", post(preview_download))
        .route("/api/v1/filter-refreshes", get(refresh_status))
        .route("/api/v1/filter-refreshes/check", post(queue_refresh))
        .route("/api/v1/upstreams", get(upstreams))
        .route("/api/v1/config", get(config).put(promote))
        .route("/api/v1/migrations/preview", post(migration::preview))
        .route("/api/v1/policy/test", post(test))
        .route("/api/v1/explain", get(explain))
        .route(
            "/api/v1/shadow",
            get(shadow_config).post(shadow).delete(clear_shadow),
        )
        .route("/api/v1/shadow/promote", post(promote_shadow))
        .route("/api/v1/revisions", get(revisions))
        .route("/api/v1/revisions/{id}", get(revision))
        .route("/api/v1/revisions/{id}/rollback", post(rollback))
        .route("/api/v1/{*path}", any(|| async { StatusCode::NOT_FOUND }))
        // Bodies are buffered only after authentication.
        .route_layer(middleware::from_fn(track_activity))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            migration::admit,
        ))
        .route_layer(middleware::from_fn_with_state(state.clone(), authenticate));
    let admitted = Router::new()
        .merge(protected)
        .route("/api/v1/auth/info", get(authentication::info))
        .route("/api/v1/auth/login", post(authentication::login))
        .route("/metrics", get(metrics))
        .route("/api/v1/status", get(status))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn_with_state(state.clone(), admit));
    // Liveness must answer even when every management slot is busy, or a
    // supervisor could restart a healthy DNS service.
    let router = Router::new()
        .merge(admitted)
        .route("/healthz", get(health))
        .with_state(state.clone());
    let router = match web_root {
        Some(root) => {
            // Explicit document routes preserve asset/API 404s and support
            // browser refreshes/bookmarks without hiding missing chunk errors.
            let index = tower_http::services::ServeFile::new(root.join("index.html"));
            let mut router = router;
            for path in [
                "/overview",
                "/queries",
                "/policies",
                "/clients",
                "/filters",
                "/upstreams",
                "/history",
                "/security",
                "/setup",
            ] {
                router = router.route_service(path, index.clone());
            }
            router.fallback_service(tower_http::services::ServeDir::new(root))
        }
        None => router,
    };
    router
        .layer(middleware::from_fn(response_headers))
        .layer(middleware::from_fn_with_state(state, check_host))
}
async fn response_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    // Configuration, credentials and telemetry must not enter shared browser caches.
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
/// DNS rebinding defense. The API listens on loopback only, so a browser can
/// reach it from another origin only through a hostname the attacker controls.
/// Accept IP literals and `localhost`; reject every other `Host`.
async fn check_host(State(state): State<Arc<AppState>>, request: Request, next: Next) -> Response {
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
    if host.is_some_and(|host| host_allowed(host, &state.hostnames)) {
        next.run(request).await
    } else {
        ApiError(
            StatusCode::MISDIRECTED_REQUEST,
            "Host must be an IP address or localhost".into(),
        )
        .into_response()
    }
}
pub(crate) fn host_allowed(host: &str, names: &[String]) -> bool {
    if local_host(host) {
        return true;
    }
    let name = if let Some((name, port)) = host.rsplit_once(':') {
        if !valid_port(port) {
            return false;
        }
        name
    } else {
        host
    };
    names
        .iter()
        .any(|allowed| name.eq_ignore_ascii_case(allowed))
}
fn local_host(host: &str) -> bool {
    let name = if let Some(rest) = host.strip_prefix('[') {
        // [IPv6] with an optional port.
        let Some((address, port)) = rest.split_once(']') else {
            return false;
        };
        if !(port.is_empty() || port.strip_prefix(':').is_some_and(valid_port)) {
            return false;
        }
        return address.parse::<std::net::Ipv6Addr>().is_ok();
    } else if let Some((name, port)) = host.rsplit_once(':') {
        if !valid_port(port) {
            return false;
        }
        name
    } else {
        host
    };
    name.eq_ignore_ascii_case("localhost") || name.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv4())
}
fn valid_port(port: &str) -> bool {
    !port.is_empty() && port.parse::<u16>().is_ok()
}
async fn authenticate(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    let master = token.is_some_and(|token| {
        bool::from(
            digest(token.as_bytes())
                .as_ref()
                .ct_eq(state.token.as_ref()),
        )
    });
    let authorization = if master {
        Some(authentication::Authorization {
            role: crate::auth::Role::Administrator,
            csrf: None,
        })
    } else if let Some(token) = token {
        state
            .identity
            .as_ref()
            .and_then(|identity| identity.token_role(token))
            .map(|role| authentication::Authorization { role, csrf: None })
    } else if !request.headers().contains_key(header::AUTHORIZATION)
        && request
            .extensions()
            .get::<axum::extract::ConnectInfo<crate::listener::Activity>>()
            .is_some_and(|info| info.0.secure())
    {
        state
            .identity
            .as_ref()
            .and_then(|identity| {
                authentication::cookie(request.headers())
                    .and_then(|cookie| identity.session(&cookie))
            })
            .map(|session| authentication::Authorization {
                role: session.role,
                csrf: Some(session.csrf),
            })
    } else {
        None
    };
    let Some(authorization) = authorization else {
        let mut response =
            ApiError(StatusCode::UNAUTHORIZED, "bearer token required".into()).into_response();
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"rustwalld\""),
        );
        return response;
    };
    if !authentication::role_allowed(authorization.role, request.method(), request.uri().path()) {
        return ApiError(
            StatusCode::FORBIDDEN,
            "Credential scope does not permit this action".into(),
        )
        .into_response();
    }
    if !matches!(
        *request.method(),
        axum::http::Method::GET | axum::http::Method::HEAD
    ) && let Some(csrf) = &authorization.csrf
        && !authentication::csrf_valid(&request, csrf)
    {
        return ApiError(
            StatusCode::FORBIDDEN,
            "Valid session CSRF token and origin required".into(),
        )
        .into_response();
    }
    request.extensions_mut().insert(authorization);
    next.run(request).await
}
async fn admit(State(state): State<Arc<AppState>>, request: Request, next: Next) -> Response {
    let Ok(_permit) = state.api_slots.clone().try_acquire_owned() else {
        return ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "management request limit".into(),
        )
        .into_response();
    };
    next.run(request).await
}
/// Read the whole body under the connection's idle timeout, then mark the
/// connection busy while the handler runs, so a long compile or commit is not
/// mistaken for an idle client. Only connections from `ManagementListener`
/// carry an activity marker.
async fn track_activity(request: Request, next: Next) -> Response {
    let Some(activity) = request
        .extensions()
        .get::<axum::extract::ConnectInfo<crate::listener::Activity>>()
        .map(|info| info.0.clone())
    else {
        return next.run(request).await;
    };
    let (parts, body) = request.into_parts();
    let deadline = if parts.uri.path() == "/api/v1/migrations/preview" {
        std::time::Duration::from_secs(10)
    } else {
        std::time::Duration::from_secs(30)
    };
    let limit =
        if parts.uri.path().starts_with("/api/v1/auth/") || parts.uri.path() == "/api/v1/privacy" {
            4096
        } else {
            MAX_BODY_BYTES
        };
    let body = match tokio::time::timeout(deadline, axum::body::to_bytes(body, limit)).await {
        Ok(Ok(body)) => body,
        Ok(Err(error)) => {
            return ApiError(StatusCode::PAYLOAD_TOO_LARGE, error.to_string()).into_response();
        }
        Err(_) => {
            return ApiError(
                StatusCode::REQUEST_TIMEOUT,
                "management upload deadline".into(),
            )
            .into_response();
        }
    };
    let _busy = activity.enter();
    next.run(Request::from_parts(parts, Body::from(body))).await
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::{local_host, track_activity};
    use crate::listener::{Activity, ManagementListener};
    use axum::{Router, middleware, routing::post};
    use std::time::Duration;

    async fn serve(tracked: bool) -> reqwest::Result<reqwest::StatusCode> {
        // Processing takes four idle windows; the body arrives at once.
        let slow = Router::new().route(
            "/slow",
            post(|body: String| async move {
                tokio::time::sleep(Duration::from_millis(400)).await;
                body
            }),
        );
        let router = if tracked {
            slow.layer(middleware::from_fn(track_activity))
        } else {
            slow
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                ManagementListener::new(listener, 4, Duration::from_millis(100)),
                router.into_make_service_with_connect_info::<Activity>(),
            )
            .await
        });
        let response = reqwest::Client::new()
            .post(format!("http://{address}/slow"))
            .body("payload")
            .send()
            .await
            .map(|response| response.status());
        server.abort();
        response
    }

    #[tokio::test]
    async fn processing_longer_than_the_idle_timeout_completes() {
        assert_eq!(serve(true).await.unwrap(), reqwest::StatusCode::OK);
        // Without the activity marker the idle timer resets the connection.
        assert!(serve(false).await.is_err());
    }
    #[tokio::test]
    async fn large_response_admission_follows_body_and_shared_bytes() {
        let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let permit = slots.clone().try_acquire_owned().unwrap();
        let response = super::json_body(axum::http::StatusCode::OK, None, "payload", Some(permit))
            .await
            .unwrap();
        assert!(slots.clone().try_acquire_owned().is_err());
        let bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(bytes.as_ref(), b"\"payload\"");
        let shared = bytes.clone();
        drop(bytes);
        assert!(slots.clone().try_acquire_owned().is_err());
        drop(shared);
        assert_eq!(slots.available_permits(), 1);
        let permit = slots.clone().try_acquire_owned().unwrap();
        let response = super::json_body(axum::http::StatusCode::OK, None, (), Some(permit))
            .await
            .unwrap();
        drop(response);
        assert_eq!(slots.available_permits(), 1);
    }
    #[tokio::test]
    async fn cancelled_serialization_keeps_admission_until_blocking_work_finishes() {
        struct Gated {
            started: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
            release: std::sync::mpsc::Receiver<()>,
        }
        impl serde::Serialize for Gated {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                self.started
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap()
                    .send(())
                    .unwrap();
                self.release.recv().unwrap();
                serializer.serialize_str("finished")
            }
        }
        let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let permit = slots.clone().try_acquire_owned().unwrap();
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, receive) = std::sync::mpsc::channel();
        let task = tokio::spawn(super::json_body(
            axum::http::StatusCode::OK,
            None,
            Gated {
                started: std::sync::Mutex::new(Some(started)),
                release: receive,
            },
            Some(permit),
        ));
        ready.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(slots.clone().try_acquire_owned().is_err());
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while slots.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    #[test]
    fn only_ip_literals_and_localhost_are_local_hosts() {
        for host in [
            "127.0.0.1",
            "127.0.0.1:8080",
            "localhost",
            "LOCALHOST:8080",
            "[::1]",
            "[::1]:8080",
            "192.0.2.1:80",
        ] {
            assert!(local_host(host), "{host}");
        }
        for host in [
            "",
            "evil.example",
            "evil.example:8080",
            "localhost.evil.example",
            "127.0.0.1.nip.io",
            "[::1",
            "[::1]x",
            "[::1]:",
            "127.0.0.1:",
            "127.0.0.1:99999",
            "localhost:port",
            "::1",
        ] {
            assert!(!local_host(host), "{host}");
        }
    }
}
