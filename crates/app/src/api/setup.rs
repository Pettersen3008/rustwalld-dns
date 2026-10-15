use super::{ApiError, ApiPath, AppState, json_body, required_version, unavailable};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::Serialize;
use std::{net::SocketAddr, sync::Arc, time::Duration};
#[derive(Clone, Default, Serialize)]
pub struct Setup {
    pub dns: Option<SocketAddr>,
    pub administration: Option<SocketAddr>,
    pub https: bool,
    pub dot: Option<SocketAddr>,
    pub doh: Option<SocketAddr>,
    pub password_login: bool,
    pub limits: Limits,
}
#[derive(Clone, Default, Serialize)]
pub struct Limits {
    pub response_cache: usize,
    pub decision_cache: usize,
    pub inflight: usize,
    pub udp_queries: usize,
    pub tcp_connections: usize,
    pub event_queue: usize,
}
impl Setup {
    pub fn from_config(config: &crate::config::Config) -> Self {
        Self {
            dns: Some(config.dns_listen),
            administration: Some(config.api_listen),
            https: config.api_tls.is_some(),
            dot: config.dot.as_ref().map(|listener| listener.listen),
            doh: config.doh.as_ref().map(|listener| listener.listen),
            password_login: config.auth_file.is_some(),
            limits: Limits {
                response_cache: config.dns_cache_entries,
                decision_cache: config.decision_cache_entries,
                inflight: config.max_inflight,
                udp_queries: config.max_udp_queries,
                tcp_connections: config.max_tcp_connections,
                event_queue: config.event_queue,
            },
        }
    }
}
pub(super) async fn setup(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let snapshot = state.control.engine().active();
    let policy = snapshot.config();
    Json(
        serde_json::json!({"process":state.setup,"generation":snapshot.generation(),"admitted_networks":policy.allowed_clients,"bindings":policy.bindings.len(),"policies":policy.policies.len(),"filters":policy.policies.iter().map(|policy|policy.lists.len()).sum::<usize>(),"local_records":policy.policies.iter().map(|policy|policy.dns_records.len()+policy.rewrites.len()).sum::<usize>(),"assertions":policy.assertions.len(),"totp":state.identity.as_ref().is_some_and(|identity|identity.requires_totp()),"dnssec":"delegated_to_upstream_not_verified_by_this_engine"}),
    )
}
#[derive(Serialize)]
struct IntegrationView {
    name: String,
    kind: &'static str,
    inventory: Arc<crate::integrations::Inventory>,
}
pub(super) async fn inventory(State(state): State<Arc<AppState>>) -> Result<Response, ApiError> {
    let permit = state.heavy()?;
    let views = state
        .integrations
        .iter()
        .map(|adapter| IntegrationView {
            name: adapter.name.clone(),
            kind: adapter.kind(),
            inventory: adapter.inventory.load_full(),
        })
        .collect::<Vec<_>>();
    json_body(StatusCode::OK, None, views, Some(permit)).await
}
fn adapter(state: &AppState, name: &str) -> Result<Arc<crate::integrations::Adapter>, ApiError> {
    state
        .integrations
        .iter()
        .find(|adapter| adapter.name == name)
        .cloned()
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "Integration not configured".into()))
}
pub(super) async fn refresh(
    State(state): State<Arc<AppState>>,
    ApiPath(name): ApiPath<String>,
) -> Result<Response, ApiError> {
    let adapter = adapter(&state, &name)?;
    if adapter.peer() {
        return Err(super::invalid("Policy peers use reviewed preview"));
    }
    let global = state.heavy()?;
    let source = adapter.slot.clone().try_acquire_owned().map_err(|_| {
        ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "Integration refresh already running".into(),
        )
    })?;
    let work = Arc::new(crate::integrations::Work::new(global, source));
    // Detached work owns admission and updates last-good state even if the browser leaves.
    tokio::spawn(async move {
        let result = tokio::select! {
            _=state.integration_stop.cancelled()=>Err("Integration cancelled during shutdown".to_owned()),
            result=tokio::time::timeout(Duration::from_secs(15), adapter.fetch(work.clone()))=>result.map_err(|_|"Integration refresh deadline exceeded".to_owned()).and_then(|result|result),
        };
        let value = match result {
            Ok(devices) => crate::integrations::Inventory {
                devices,
                refreshed_at: Some(crate::integrations::now().map_err(unavailable)?),
                error: None,
            },
            Err(error) => {
                let old = adapter.inventory.load();
                crate::integrations::Inventory {
                    devices: old.devices.clone(),
                    refreshed_at: old.refreshed_at,
                    error: Some(error),
                }
            }
        };
        let value = Arc::new(value);
        adapter.inventory.store(value.clone());
        super::json_body_guard(StatusCode::OK, None, value, work).await
    })
    .await
    .map_err(unavailable)?
}
pub(super) async fn peer(
    State(state): State<Arc<AppState>>,
    ApiPath(name): ApiPath<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let expected = required_version(&headers)?;
    let pinned = super::revisions::pinned(&state)?;
    if expected != pinned.version {
        return Err(ApiError(
            StatusCode::PRECONDITION_FAILED,
            "Local configuration changed".into(),
        ));
    }
    let adapter = adapter(&state, &name)?;
    if !adapter.peer() {
        return Err(super::invalid("Integration is not a policy peer"));
    }
    let global = state.heavy()?;
    let source = adapter.slot.clone().try_acquire_owned().map_err(|_| {
        ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "Peer preview already running".into(),
        )
    })?;
    tokio::spawn(async move {
        let work = Arc::new(crate::integrations::Work::new(global, source));
        let bytes = tokio::select! {
            _=state.integration_stop.cancelled()=>return Err(unavailable("Peer cancelled during shutdown")),
            result=tokio::time::timeout(Duration::from_secs(15), adapter.peer_config())=>result.map_err(|_|unavailable("Peer deadline exceeded"))?.map_err(unavailable)?,
        };
        let listeners = state.control.dns_listeners().to_vec();
        let (config, work) = tokio::task::spawn_blocking(move || {
            let config: rustwalld_dns_policy::PolicyConfigSet = serde_json::from_slice(&bytes)
                .map_err(|_| super::invalid("Peer returned an invalid policy configuration"))?;
            let mut accepted=vec![pinned.active.config()];
            if let Some(shadow)=&pinned.shadow {accepted.push(shadow.config());}
            config.validate_new_exceptions(&accepted).map_err(super::invalid)?;
            rustwalld_dns_policy::PolicySnapshot::compile(config.clone(), 1)
                .map_err(super::invalid)?;
            // Only content is copied. A fresh local generation is compiled on publication.
            for listener in listeners {
                crate::config::validate_policy(&config, listener).map_err(super::invalid)?;
            }
            Ok::<_, ApiError>((config, work))
        })
        .await
        .map_err(unavailable)??;
        if super::revisions::pinned(&state)?.version != expected {
            return Err(ApiError(
                StatusCode::PRECONDITION_FAILED,
                "Local configuration changed during peer preview".into(),
            ));
        }
        #[derive(Serialize)]
        struct Preview {
            source: String,
            config: rustwalld_dns_policy::PolicyConfigSet,
        }
        // Response bytes retain both global and per-source admission through slow readers.
        super::json_body_guard(
            StatusCode::OK,
            Some(super::revisions::revision_tag(expected)),
            Preview {
                source: adapter.name.clone(),
                config,
            },
            work,
        )
        .await
    })
    .await
    .map_err(unavailable)?
}
