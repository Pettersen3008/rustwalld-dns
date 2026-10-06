use crate::{
    config::validate_policy,
    store::{Operation, Store},
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, get, post},
};
use dns_core::{Engine, telemetry::LATENCY_US};
use policy::{PolicyConfigSet, PolicySnapshot};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;

pub struct AppState {
    pub engine: Arc<Engine>,
    pub store: Store,
    pub listen: std::net::SocketAddr,
    pub next_generation: AtomicU64,
    pub mutation: Arc<Semaphore>,
    pub api_slots: Arc<Semaphore>,
    pub downloads: Arc<Semaphore>,
    pub refreshes: Arc<crate::refreshes::Refresher>,
    pub token: String,
}
type ApiResult = Result<Json<Value>, ApiError>;
pub struct ApiError(pub StatusCode, pub String);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error":self.1}))).into_response()
    }
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
async fn health() -> StatusCode {
    StatusCode::OK
}
async fn status(State(state): State<Arc<AppState>>) -> Json<Value> {
    let snapshot = state.engine.active.load();
    Json(
        json!({"version":env!("CARGO_PKG_VERSION"),"generation":snapshot.generation,"shadow_generation":state.engine.shadow.load().as_ref().map(|s|s.generation),"policies":snapshot.policies.len(),"cache_entries":state.engine.resolver.cache.len(),"inflight":state.engine.resolver.inflight(),"dns_listen":state.listen}),
    )
}
#[derive(Deserialize)]
struct HistoryQuery {
    #[serde(default = "default_limit")]
    limit: usize,
}
fn default_limit() -> usize {
    100
}
async fn queries(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HistoryQuery>,
) -> ApiResult {
    Ok(Json(
        state
            .store
            .call(Operation::Queries { limit: query.limit })
            .await
            .map_err(unavailable)?,
    ))
}
async fn clients(State(state): State<Arc<AppState>>) -> Json<Value> {
    let snapshot = state.engine.active.load();
    Json(
        json!({"generation":snapshot.generation,"default_policy":snapshot.config.default_policy,"bindings":snapshot.config.bindings,"allowed_clients":snapshot.config.allowed_clients}),
    )
}
async fn policies(State(state): State<Arc<AppState>>) -> Json<Value> {
    let snapshot = state.engine.active.load();
    Json(json!(snapshot.policies.iter().map(|p|json!({"id":p.id,"name":p.name,"upstream":snapshot.config.upstreams[p.upstream].name,"effective_rules":p.filters.effective_rules()})).collect::<Vec<_>>()))
}
async fn filters(State(state): State<Arc<AppState>>) -> Json<Value> {
    let snapshot = state.engine.active.load();
    Json(json!(snapshot.policies.iter().map(|p|json!({"policy":p.name,"generation":snapshot.generation,"lists":p.filters.stats,"effective_rules":p.filters.effective_rules(),"payload_bytes_estimate":p.filters.payload_bytes()})).collect::<Vec<_>>()))
}
async fn temporary_exceptions(State(state): State<Arc<AppState>>) -> Json<Value> {
    let snapshot = state.engine.active.load_full();
    let now = std::time::Instant::now();
    let entries = snapshot.config.policies.iter().enumerate().flat_map(|(policy, config)| {
        let snapshot = &snapshot;
        config.temporary_exceptions.iter().enumerate().map(move |(index, exception)| {
            let domain = filtering::normalize(&exception.domain).unwrap_or_default();
            let active = snapshot.policies[policy].temporary_allow(&domain, now).is_some();
            json!({"policy":config.name,"index":index,"name":exception.name,"domain":domain,"configured_domain":exception.domain,"expires_at":exception.expires_at,"active":active})
        })
    }).collect::<Vec<_>>();
    Json(json!({"generation":snapshot.generation,"exceptions":entries}))
}

async fn filter_sources(State(state): State<Arc<AppState>>) -> Json<Value> {
    let snapshot = state.engine.active.load_full();
    Json(json!({"generation": snapshot.generation, "sources": snapshot.config.filter_sources}))
}

async fn refresh_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<crate::refreshes::Status>, ApiError> {
    let mut status = state
        .refreshes
        .status(&state.engine.active.load())
        .map_err(unavailable)?;
    status.paused = if state.engine.shadow.load().is_some() {
        Some("shadow_review")
    } else if state.mutation.available_permits() == 0 {
        Some("policy_mutation")
    } else {
        None
    };
    Ok(Json(status))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RefreshRequest {
    source: usize,
}
async fn queue_refresh(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<RefreshRequest>,
) -> Result<Response, ApiError> {
    if !headers.contains_key(header::IF_MATCH) {
        return Err(ApiError(
            StatusCode::PRECONDITION_REQUIRED,
            "scheduled check requires If-Match".into(),
        ));
    }
    let _guard = state.mutation.clone().try_acquire_owned().map_err(|_| {
        ApiError(
            StatusCode::CONFLICT,
            "policy mutation already running".into(),
        )
    })?;
    check_revision(&state, &headers)?;
    if state.engine.shadow.load().is_some() || state.downloads.available_permits() == 0 {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "review the existing shadow or wait for the running download".into(),
        ));
    }
    let snapshot = state.engine.active.load_full();
    if snapshot
        .config
        .filter_sources
        .get(request.source)
        .is_none_or(|source| source.refresh_interval_secs.is_none())
    {
        return Err(invalid("source has no active refresh schedule"));
    }
    state
        .refreshes
        .enqueue(&snapshot, request.source)
        .map_err(|error| ApiError(StatusCode::CONFLICT, error))?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"queued":true,"generation":snapshot.generation,"source":request.source})),
    )
        .into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DownloadPreview {
    config: PolicyConfigSet,
    source: usize,
}

async fn preview_download(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(input): Json<DownloadPreview>,
) -> Result<Response, ApiError> {
    if !headers.contains_key(header::IF_MATCH) {
        return Err(ApiError(
            StatusCode::PRECONDITION_REQUIRED,
            "download preview requires If-Match".into(),
        ));
    }
    check_revision(&state, &headers)?;
    // Capture the caller's checked tag, never a newer tag from a second load.
    let tag = headers
        .get(header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| invalid("invalid download revision tag"))?
        .to_owned();
    let download = state
        .downloads
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError(StatusCode::CONFLICT, "list download already running".into()))?;
    let listen = state.listen;
    // Move admission into blocking jobs, so cancellation cannot release their
    // slots early. Fetch itself remains cancellable; its driver guard closes I/O.
    let (mut config, download) = tokio::task::spawn_blocking(move || {
        validate_policy(&input.config, listen).map_err(invalid)?;
        if input.source >= input.config.filter_sources.len() {
            return Err(invalid("unknown source index"));
        }
        Ok::<_, ApiError>((input.config, download))
    })
    .await
    .map_err(unavailable)??;
    let source = config
        .filter_sources
        .get(input.source)
        .ok_or_else(|| invalid("unknown source index"))?;
    let target_policy = source.policy.clone();
    let target_list = source.list.clone();
    let (text, stamp) = crate::downloads::fetch(source)
        .await
        .map_err(|error| ApiError(StatusCode::BAD_GATEWAY, error))?;
    let list = config
        .policies
        .iter_mut()
        .find(|policy| policy.name == target_policy)
        .and_then(|policy| {
            policy
                .lists
                .iter_mut()
                .find(|list| list.name == target_list)
        })
        .ok_or_else(|| invalid("source target missing"))?;
    let changed = list.rules != text;
    list.rules = text;
    config.filter_sources[input.source].download = Some(stamp);
    let guard = state.mutation.clone().try_acquire_owned().map_err(|_| {
        ApiError(
            StatusCode::CONFLICT,
            "policy compilation already running".into(),
        )
    })?;
    if current_tag(&state) != tag {
        return Err(ApiError(
            StatusCode::PRECONDITION_FAILED,
            "configuration changed during download; inspect the current revision before retrying"
                .into(),
        ));
    }
    let (config, report) = tokio::task::spawn_blocking(move || {
        let _guard = guard;
        let _download = download;
        validate_policy(&config, listen).map_err(invalid)?;
        let report = PolicySnapshot::check(config.clone()).map_err(invalid)?;
        if !report.valid {
            return Ok::<_, ApiError>((config, report));
        }
        let stats = report
            .list_stats
            .iter()
            .find(|policy| policy.policy == target_policy)
            .and_then(|policy| policy.lists.iter().find(|stats| stats.name == target_list))
            .ok_or_else(|| invalid("compiled download target missing"))?;
        if stats.raw == 0 {
            return Err(invalid("downloaded list has no rules"));
        }
        crate::downloads::validate_size(&config).map_err(invalid)?;
        Ok((config, report))
    })
    .await
    .map_err(unavailable)??;
    if !report.valid {
        return Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(
                json!({"error":"downloaded candidate failed required assertions", "report":report}),
            ),
        )
            .into_response());
    }
    Ok((
        [(header::ETAG, tag)],
        Json(json!({"config":config,"report":report,"changed":changed})),
    )
        .into_response())
}
async fn upstreams(State(state): State<Arc<AppState>>) -> Json<Value> {
    let snapshot = state.engine.active.load();
    let profiles = snapshot
        .upstreams
        .iter()
        .enumerate()
        .map(|(i, upstream)| {
            let config = &snapshot.config.upstreams[i];
            let (transport, server_name, path) = match &config.transport {
                policy::UpstreamTransport::Udp => ("udp", None, None),
                policy::UpstreamTransport::Tls { server_name, .. } => {
                    ("tls", Some(server_name), None)
                }
                policy::UpstreamTransport::Https {
                    server_name, path, ..
                } => ("https", Some(server_name), Some(path)),
            };
            let servers = upstream
                .health
                .iter()
                .map(|health| {
                    let failures = resolver::FailureKind::ALL
                        .into_iter()
                        .map(|kind| (kind, health.failure_count(kind)))
                        .collect::<std::collections::BTreeMap<_, _>>();
                    json!({
                        "address": health.address,
                        "attempts": health.attempts.load(Ordering::Relaxed),
                        "successes": health.successes.load(Ordering::Relaxed),
                        "inflight": health.inflight.load(Ordering::Relaxed),
                        "ewma_us": health.ewma_us.load(Ordering::Relaxed),
                        "failures": failures,
                        "backoff_skips": health.backoff_skips.load(Ordering::Relaxed),
                        "recovery_probes": health.recovery_probes.load(Ordering::Relaxed),
                        "admission": health.admission_status(),
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "generation": snapshot.generation, "name": config.name,
                "transport": transport, "server_name": server_name,
                "path": path, "servers": servers,
            })
        })
        .collect::<Vec<_>>();
    Json(json!(profiles))
}

fn revision_tag(active: u64, shadow: Option<u64>) -> String {
    format!("\"g{active}-s{}\"", shadow.unwrap_or(0))
}
fn current_tag(state: &AppState) -> String {
    revision_tag(
        state.engine.active.load().generation,
        state.engine.shadow.load().as_ref().map(|s| s.generation),
    )
}
fn check_revision(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    if let Some(expected) = headers.get(header::IF_MATCH)
        && expected.to_str().ok() != Some(current_tag(state).as_str())
    {
        return Err(ApiError(
            StatusCode::PRECONDITION_FAILED,
            "configuration changed; inspect the current revision before retrying".into(),
        ));
    }
    Ok(())
}
async fn config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let active = state.engine.active.load_full();
    let tag = revision_tag(
        active.generation,
        state.engine.shadow.load().as_ref().map(|s| s.generation),
    );
    ([(header::ETAG, tag)], Json(active.config.clone()))
}
async fn shadow_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let shadow = state.engine.shadow.load_full();
    let tag = revision_tag(
        state.engine.active.load().generation,
        shadow.as_ref().map(|s| s.generation),
    );
    (
        [(header::ETAG, tag)],
        Json(json!({
            "generation":shadow.as_ref().map(|s|s.generation),
            "config":shadow.as_ref().map(|s| &s.config)
        })),
    )
}
#[derive(Deserialize)]
struct ExplainQuery {
    client: IpAddr,
    domain: String,
}
async fn explain(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ExplainQuery>,
) -> ApiResult {
    let snapshot = state.engine.active.load();
    let explanation = snapshot
        .explain(query.client, &query.domain)
        .map_err(invalid)?;
    Ok(Json(
        serde_json::to_value(explanation).map_err(unavailable)?,
    ))
}
async fn test(
    State(state): State<Arc<AppState>>,
    Json(config): Json<PolicyConfigSet>,
) -> Result<Response, ApiError> {
    let guard = state.mutation.clone().try_acquire_owned().map_err(|_| {
        ApiError(
            StatusCode::CONFLICT,
            "policy compilation already running".into(),
        )
    })?;
    tokio::spawn(async move {
        let _guard = guard;
        let report = tokio::task::spawn_blocking(move || {
            validate_policy(&config, state.listen).map_err(policy::PolicyError::Invalid)?;
            PolicySnapshot::check(config)
        })
            .await.map_err(unavailable)?.map_err(invalid)?;
        if report.valid {
            Ok(Json(report).into_response())
        } else {
            Ok((StatusCode::UNPROCESSABLE_ENTITY, Json(json!({
                "error": format!("required policy assertions failed: {} of {}", report.failed, report.assertions),
                "report": report,
            }))).into_response())
        }
    }).await.map_err(unavailable)?
}
async fn promote(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(config): Json<PolicyConfigSet>,
) -> Result<Response, ApiError> {
    stage(state, Candidate::Config(config), headers, false, "api").await
}
async fn shadow(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(config): Json<PolicyConfigSet>,
) -> Result<Response, ApiError> {
    stage(
        state,
        Candidate::Config(config),
        headers,
        true,
        "api-shadow",
    )
    .await
}
enum Candidate {
    Config(PolicyConfigSet),
    Shadow,
    Refresh {
        config: PolicyConfigSet,
        source: usize,
    },
}
pub(crate) async fn stage_refresh(
    state: Arc<AppState>,
    config: PolicyConfigSet,
    source: usize,
    generation: u64,
) -> Result<(), ApiError> {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::IF_MATCH,
        HeaderValue::from_str(&revision_tag(generation, None)).map_err(invalid)?,
    );
    stage(
        state,
        Candidate::Refresh { config, source },
        headers,
        true,
        "scheduled-refresh",
    )
    .await?;
    Ok(())
}
async fn stage(
    state: Arc<AppState>,
    candidate: Candidate,
    headers: HeaderMap,
    shadow: bool,
    actor: &'static str,
) -> Result<Response, ApiError> {
    let guard = state.mutation.clone().try_acquire_owned().map_err(|_| {
        ApiError(
            StatusCode::CONFLICT,
            "policy compilation already running".into(),
        )
    })?;
    check_revision(&state, &headers)?;
    // Candidate capture and precondition checks share the mutation admission guard.
    let (config, refresh_source) = match candidate {
        Candidate::Config(config) => (config, None),
        Candidate::Refresh { config, source } => (config, Some(source)),
        Candidate::Shadow => (
            state
                .engine
                .shadow
                .load_full()
                .ok_or_else(|| invalid("no shadow revision"))?
                .config
                .clone(),
            None,
        ),
    };
    let id = state.next_generation.fetch_add(1, Ordering::Relaxed);
    if id > i64::MAX as u64 {
        return Err(unavailable("revision ID exhausted"));
    }
    // HTTP cancellation cannot interrupt a durable commit before publication.
    tokio::spawn(async move {
        let _guard = guard;
        let old = state.engine.active.load_full();
        let listen = state.listen;
        let snapshot = tokio::task::spawn_blocking(move || {
            validate_policy(&config, listen).map_err(policy::PolicyError::Invalid)?;
            let snapshot = PolicySnapshot::compile(config, id)?;
            if let Some(source) = refresh_source {
                crate::downloads::validate_candidate(&snapshot, source)
                    .map_err(policy::PolicyError::Invalid)?;
            }
            Ok::<_, policy::PolicyError>(snapshot)
        })
        .await
        .map_err(unavailable)?
        .map_err(invalid)?;
        let content = serde_json::to_string(&snapshot.config).map_err(unavailable)?;
        let diff = configuration_diff(&old.config, &snapshot.config);
        let result = state
            .store
            .call(Operation::Commit {
                id,
                config: content,
                mode: if shadow { "shadow" } else { "promoted" }.into(),
                actor: actor.into(),
                diff,
            })
            .await
            .map_err(unavailable)?;
        if shadow {
            state.engine.shadow.store(Some(Arc::new(snapshot)));
        } else {
            state.engine.active.store(Arc::new(snapshot));
            state.engine.shadow.store(None);
        }
        tracing::info!(generation = id, shadow, "policy revision published");
        Ok(([(header::ETAG, current_tag(&state))], Json(result)).into_response())
    })
    .await
    .map_err(unavailable)?
}
fn configuration_diff(old: &PolicyConfigSet, new: &PolicyConfigSet) -> String {
    let old = serde_json::to_value(old).unwrap_or(Value::Null);
    let new = serde_json::to_value(new).unwrap_or(Value::Null);
    let fields = [
        "default_policy",
        "policies",
        "upstreams",
        "bindings",
        "allowed_clients",
        "assertions",
        "filter_sources",
    ];
    fields
        .iter()
        .filter(|field| old.get(**field) != new.get(**field))
        .copied()
        .collect::<Vec<_>>()
        .join(", ")
}
async fn promote_shadow(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    stage(state, Candidate::Shadow, headers, false, "shadow-promote").await
}
async fn clear_shadow(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let guard = state.mutation.clone().try_acquire_owned().map_err(|_| {
        ApiError(
            StatusCode::CONFLICT,
            "policy mutation already running".into(),
        )
    })?;
    check_revision(&state, &headers)?;
    tokio::spawn(async move {
        let _guard = guard;
        let result = state
            .store
            .call(Operation::ClearShadow)
            .await
            .map_err(unavailable)?;
        state.engine.shadow.store(None);
        Ok(([(header::ETAG, current_tag(&state))], Json(result)).into_response())
    })
    .await
    .map_err(unavailable)?
}
async fn revisions(State(state): State<Arc<AppState>>) -> ApiResult {
    Ok(Json(
        state
            .store
            .call(Operation::Revisions)
            .await
            .map_err(unavailable)?,
    ))
}
async fn revision(State(state): State<Arc<AppState>>, Path(id): Path<u64>) -> ApiResult {
    Ok(Json(read_revision(&state.store, id).await?))
}
async fn read_revision(store: &Store, id: u64) -> Result<Value, ApiError> {
    if id > i64::MAX as u64 {
        return Err(ApiError(StatusCode::NOT_FOUND, "revision not found".into()));
    }
    let revision = store
        .call(Operation::Revision { id })
        .await
        .map_err(unavailable)?;
    if revision.is_null() {
        return Err(ApiError(StatusCode::NOT_FOUND, "revision not found".into()));
    }
    Ok(revision)
}
async fn rollback(
    State(state): State<Arc<AppState>>,
    Path(id): Path<u64>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let revision = read_revision(&state.store, id).await?;
    let config = serde_json::from_value(revision["config"].clone()).map_err(invalid)?;
    stage(state, Candidate::Config(config), headers, false, "rollback").await
}
async fn metrics(State(state): State<Arc<AppState>>) -> String {
    use std::fmt::Write;
    let m = &state.engine.telemetry.metrics;
    let r = &state.engine.resolver.metrics;
    let db = &state.store.metrics;
    let mut output = String::new();
    for (name, value) in [
        ("requests", &m.requests),
        ("blocked", &m.blocked),
        ("temporary_allows", &m.temporary_allows),
        ("rewrites", &m.rewrites),
        ("failures", &m.failures),
        ("decision_cache_hits", &m.decision_hits),
        ("events_dropped", &m.dropped_events),
        ("shadow_differences", &m.shadow_differences),
        ("dns_cache_hits", &r.cache_hits),
        ("coalesced", &r.coalesced),
        ("upstream_lookups", &r.upstream_lookups),
        ("inflight_overloads", &r.overloads),
        ("history_write_failures", &db.write_failures),
        ("history_events", &db.persisted_events),
    ] {
        let _ = writeln!(
            output,
            "# TYPE rustwalld_{name}_total counter\nrustwalld_{name}_total {}",
            value.load(Ordering::Relaxed)
        );
    }
    let _ = writeln!(
        output,
        "# TYPE rustwalld_query_latency_microseconds histogram"
    );
    let mut count = 0u64;
    for (index, bound) in LATENCY_US.iter().enumerate() {
        count += m.latency_buckets[index].load(Ordering::Relaxed);
        let label = if *bound == u64::MAX {
            "+Inf".into()
        } else {
            bound.to_string()
        };
        let _ = writeln!(
            output,
            "rustwalld_query_latency_microseconds_bucket{{le=\"{label}\"}} {count}"
        );
    }
    let _ = writeln!(output, "rustwalld_query_latency_microseconds_count {count}");
    let _ = writeln!(
        output,
        "rustwalld_query_latency_microseconds_sum {}",
        m.latency_sum_us.load(Ordering::Relaxed)
    );
    output
}
