use super::{ApiError, ApiQuery, AppState};
use crate::store::HistoryEntry;
use axum::{Json, extract::State, http::StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

pub(super) async fn health() -> StatusCode {
    StatusCode::OK
}
pub(super) async fn status(State(state): State<Arc<AppState>>) -> Json<Value> {
    let engine = state.control.engine();
    let snapshot = engine.active();
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "generation": snapshot.generation(),
        "shadow_generation": engine.shadow().as_ref().map(|s| s.generation()),
        "policies": snapshot.policies().len(),
        "cache_entries": engine.resolver().cache.len(),
        "inflight": engine.resolver().inflight(),
        "dns_listen": state.control.listen(),
    }))
}
#[derive(Deserialize)]
pub(super) struct HistoryQuery {
    #[serde(default = "default_limit")]
    limit: usize,
}
fn default_limit() -> usize {
    100
}
pub(super) async fn queries(
    State(state): State<Arc<AppState>>,
    ApiQuery(query): ApiQuery<HistoryQuery>,
) -> Result<Json<Vec<HistoryEntry>>, ApiError> {
    Ok(Json(state.control.queries(query.limit).await?))
}
pub(super) async fn clients(State(state): State<Arc<AppState>>) -> Json<Value> {
    let snapshot = state.control.engine().active();
    let config = snapshot.config();
    Json(json!({
        "generation": snapshot.generation(),
        "default_policy": config.default_policy,
        "bindings": config.bindings,
        "allowed_clients": config.allowed_clients,
    }))
}
pub(super) async fn policies(State(state): State<Arc<AppState>>) -> Json<Value> {
    let snapshot = state.control.engine().active();
    let config = snapshot.config();
    let policies = snapshot.policies().iter().map(|policy| {
        json!({
            "id": policy.id(),
            "name": policy.name(),
            "upstream": config.upstreams.get(policy.upstream()).map(|u| &u.name),
            "effective_rules": policy.filters().effective_rules(),
        })
    });
    Json(Value::Array(policies.collect()))
}
pub(super) async fn filters(State(state): State<Arc<AppState>>) -> Json<Value> {
    let snapshot = state.control.engine().active();
    let lists = snapshot.policies().iter().map(|policy| {
        let filters = policy.filters();
        json!({
            "policy": policy.name(),
            "generation": snapshot.generation(),
            "lists": filters.stats,
            "effective_rules": filters.effective_rules(),
            "payload_bytes_estimate": filters.payload_bytes(),
        })
    });
    Json(Value::Array(lists.collect()))
}
pub(super) async fn temporary_exceptions(State(state): State<Arc<AppState>>) -> Json<Value> {
    let snapshot = state.control.engine().snapshot();
    let now = std::time::Instant::now();
    let entries = snapshot
        .config()
        .policies
        .iter()
        .zip(snapshot.policies())
        .flat_map(|(config, compiled)| {
            config
                .temporary_exceptions
                .iter()
                .enumerate()
                .map(move |(index, exception)| {
                    let domain =
                        rustwalld_dns_filter::normalize(&exception.domain).unwrap_or_default();
                    json!({
                        "policy": config.name,
                        "index": index,
                        "name": exception.name,
                        "domain": domain,
                        "configured_domain": exception.domain,
                        "expires_at": exception.expires_at,
                        "active": compiled.temporary_allow(&domain, now).is_some(),
                    })
                })
        })
        .collect::<Vec<_>>();
    Json(json!({"generation": snapshot.generation(), "exceptions": entries}))
}
pub(super) async fn filter_sources(State(state): State<Arc<AppState>>) -> Json<Value> {
    let snapshot = state.control.engine().snapshot();
    Json(json!({
        "generation": snapshot.generation(),
        "sources": snapshot.config().filter_sources,
    }))
}
