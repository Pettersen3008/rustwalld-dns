//! HTTP admission and rendering around the reusable durable control service.
mod diagnostics;
mod downloads;
mod read;
mod revisions;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
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
use serde_json::{Value, json};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;

pub struct AppState {
    pub control: Arc<rustwalld_dns_runtime::ControlService>,
    pub api_slots: Arc<Semaphore>,
    pub token: String,
}
type ApiResult = Result<Json<Value>, ApiError>;
pub struct ApiError(pub StatusCode, pub String);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error":self.1}))).into_response()
    }
}
impl From<rustwalld_dns_runtime::ControlError> for ApiError {
    fn from(error: rustwalld_dns_runtime::ControlError) -> Self {
        use rustwalld_dns_runtime::ControlError;
        let code = match &error {
            ControlError::Invalid(_) => StatusCode::UNPROCESSABLE_ENTITY,
            ControlError::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            ControlError::Conflict(_) => StatusCode::CONFLICT,
            ControlError::Stale => StatusCode::PRECONDITION_FAILED,
            ControlError::MissingRevision => StatusCode::NOT_FOUND,
        };
        Self(code, error.to_string())
    }
}
fn expected_version(headers: &HeaderMap) -> Option<rustwalld_dns_core::PolicyVersion> {
    headers.get(header::IF_MATCH).map(|value| {
        let invalid = rustwalld_dns_core::PolicyVersion {
            active: 0,
            shadow: None,
        };
        let Some(tag) = value.to_str().ok() else {
            return invalid;
        };
        let Some((active, shadow)) = tag
            .strip_prefix("\"g")
            .and_then(|s| s.strip_suffix('"'))
            .and_then(|s| s.split_once("-s"))
        else {
            return invalid;
        };
        let (Ok(active), Ok(shadow)) = (active.parse::<u64>(), shadow.parse::<u64>()) else {
            return invalid;
        };
        let version = rustwalld_dns_core::PolicyVersion {
            active,
            shadow: (shadow != 0).then_some(shadow),
        };
        if revisions::revision_tag(version.active, version.shadow) == tag {
            version
        } else {
            invalid
        }
    })
}
fn invalid(error: impl ToString) -> ApiError {
    ApiError(StatusCode::UNPROCESSABLE_ENTITY, error.to_string())
}
fn unavailable(error: impl ToString) -> ApiError {
    ApiError(StatusCode::SERVICE_UNAVAILABLE, error.to_string())
}
pub fn router(state: Arc<AppState>) -> Router {
    router_with_ui(state, None)
}
pub fn router_with_ui(state: Arc<AppState>, web_root: Option<std::path::PathBuf>) -> Router {
    let protected = Router::new()
        .route("/api/v1/queries", get(queries))
        .route("/api/v1/clients", get(clients))
        .route("/api/v1/policies", get(policies))
        .route("/api/v1/temporary-exceptions", get(temporary_exceptions))
        .route("/api/v1/filter-lists", get(filters))
        .route("/api/v1/filter-sources", get(filter_sources))
        .route("/api/v1/filter-sources/preview", post(preview_download))
        .route("/api/v1/filter-refreshes", get(refresh_status))
        .route("/api/v1/filter-refreshes/check", post(queue_refresh))
        .route("/api/v1/upstreams", get(upstreams))
        .route("/api/v1/config", get(config).put(promote))
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
        .route_layer(middleware::from_fn_with_state(state.clone(), authenticate));
    let router = Router::new()
        .merge(protected)
        .route("/healthz", get(health))
        .route("/metrics", get(metrics))
        .route("/api/v1/status", get(status))
        .layer(DefaultBodyLimit::max(16 * 1024 * 1024))
        .layer(middleware::from_fn_with_state(state.clone(), admit))
        .with_state(state);
    let router = match web_root {
        Some(root) => router.fallback_service(tower_http::services::ServeDir::new(root)),
        None => router,
    };
    router.layer(middleware::from_fn(response_headers))
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
async fn authenticate(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    if !token.is_some_and(|token| bool::from(token.as_bytes().ct_eq(state.token.as_bytes()))) {
        return ApiError(StatusCode::UNAUTHORIZED, "bearer token required".into()).into_response();
    }
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
