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
    let now = std::time::SystemTime::now();
    let policies = snapshot.policies().iter().map(|policy| {
        json!({
            "id": policy.id(),
            "name": policy.name(),
            "upstream": config.upstreams.get(policy.upstream()).map(|u| &u.name),
            "effective_rules": policy.filters().effective_rules(),
            "service_schedule": policy.service_schedule_at(now).map(|evaluation| serde_json::json!({"state":evaluation.state,"ttl_cap":evaluation.ttl_cap,"tzdb_version":rustwalld_dns_policy::SCHEDULE_TZDB_VERSION,"time_zone":config.policies[policy.id()].blocked_services.as_ref().and_then(|value|value.schedule.as_ref()).map(|value| &value.time_zone)})),
        })
    });
    Json(Value::Array(policies.collect()))
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FilterQuery {
    policy: Option<String>,
}
pub(super) async fn filters(
    State(state): State<Arc<AppState>>,
    ApiQuery(query): ApiQuery<FilterQuery>,
) -> Json<Value> {
    let snapshot = state.control.engine().active();
    // A shared list may appear in hundreds of policies. Bound the combined
    // response too; individual details can request one policy explicitly.
    let mut remaining = 200usize;
    let lists = snapshot
        .policies()
        .iter()
        .filter(|policy| {
            query
                .policy
                .as_deref()
                .is_none_or(|name| name == policy.name())
        })
        .map(|policy| {
            let filters = policy.filters();
            let cancellations: Vec<_> = filters.cancellations().iter().take(remaining).collect();
            remaining -= cancellations.len();
            json!({
                "policy": policy.name(),
                "generation": snapshot.generation(),
                "lists": filters.stats,
                "effective_rules": filters.effective_rules(),
                "payload_bytes_estimate": filters.payload_bytes(),
                "cancellation_targets": filters.cancellation_targets(),
                "cancellations": cancellations,
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
                        if exception.domain == "*" { "*".into() } else { rustwalld_dns_filter::normalize(&exception.domain).unwrap_or_default() };
                    json!({
                        "policy": config.name,
                        "index": index,
                        "name": exception.name,
                        "domain": domain,
                        "configured_domain": exception.domain,
                        "expires_at": exception.expires_at,
                        "active": compiled.temporary_exception_active(index, now),
 "clients": exception.clients, "include_subdomains": exception.include_subdomains,
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

/// Immutable public domain facts, still protected by management authentication.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CatalogQuery {
    #[serde(default = "default_catalog")]
    version: u16,
}
fn default_catalog() -> u16 {
    1
}
pub(super) async fn service_catalog(
    ApiQuery(query): ApiQuery<CatalogQuery>,
) -> Result<Json<Value>, ApiError> {
    let catalog = rustwalld_dns_policy::service_catalog_for_version(query.version)
        .map_err(|error| ApiError(StatusCode::UNPROCESSABLE_ENTITY, error.to_string()))?;
    Ok(Json(
        json!({"catalog_version": query.version, "services": catalog}),
    ))
}
