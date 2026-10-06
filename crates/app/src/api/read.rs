use super::{ApiError, AppState, unavailable};
use crate::store::HistoryEntry;
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

pub(super) async fn health() -> StatusCode {
    StatusCode::OK
}
pub(super) async fn status(State(state): State<Arc<AppState>>) -> Json<Value> {
    let snapshot = state.control.engine.active();
    Json(
        json!({"version":env!("CARGO_PKG_VERSION"),"generation":snapshot.generation(),"shadow_generation":state.control.engine.shadow().as_ref().map(|s|s.generation()),"policies":snapshot.policies().len(),"cache_entries":state.control.engine.resolver().cache.len(),"inflight":state.control.engine.resolver().inflight(),"dns_listen":state.control.listen}),
    )
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
    Query(query): Query<HistoryQuery>,
) -> Result<Json<Vec<HistoryEntry>>, ApiError> {
    Ok(Json(
        state
            .control
            .store
            .queries(query.limit)
            .await
            .map_err(unavailable)?,
    ))
}
pub(super) async fn clients(State(state): State<Arc<AppState>>) -> Json<Value> {
    let snapshot = state.control.engine.active();
    Json(
        json!({"generation":snapshot.generation(),"default_policy":snapshot.config().default_policy,"bindings":snapshot.config().bindings,"allowed_clients":snapshot.config().allowed_clients}),
    )
}
pub(super) async fn policies(State(state): State<Arc<AppState>>) -> Json<Value> {
    let snapshot = state.control.engine.active();
    Json(json!(snapshot.policies().iter().map(|p|json!({"id":p.id(),"name":p.name(),"upstream":snapshot.config().upstreams[p.upstream()].name,"effective_rules":p.filters().effective_rules()})).collect::<Vec<_>>()))
}
pub(super) async fn filters(State(state): State<Arc<AppState>>) -> Json<Value> {
    let snapshot = state.control.engine.active();
    Json(json!(snapshot.policies().iter().map(|p|json!({"policy":p.name(),"generation":snapshot.generation(),"lists":p.filters().stats,"effective_rules":p.filters().effective_rules(),"payload_bytes_estimate":p.filters().payload_bytes()})).collect::<Vec<_>>()))
}
pub(super) async fn temporary_exceptions(State(state): State<Arc<AppState>>) -> Json<Value> {
    let snapshot = state.control.engine.snapshot();
    let now = std::time::Instant::now();
    let entries = snapshot.config().policies.iter().enumerate().flat_map(|(policy, config)| {
        let snapshot = &snapshot;
        config.temporary_exceptions.iter().enumerate().map(move |(index, exception)| {
            let domain = rustwalld_dns_filter::normalize(&exception.domain).unwrap_or_default();
            let active = snapshot.policies()[policy].temporary_allow(&domain, now).is_some();
            json!({"policy":config.name,"index":index,"name":exception.name,"domain":domain,"configured_domain":exception.domain,"expires_at":exception.expires_at,"active":active})
        })
    }).collect::<Vec<_>>();
    Json(json!({"generation":snapshot.generation(),"exceptions":entries}))
}

pub(super) async fn filter_sources(State(state): State<Arc<AppState>>) -> Json<Value> {
    let snapshot = state.control.engine.snapshot();
    Json(json!({"generation": snapshot.generation(), "sources": snapshot.config().filter_sources}))
}
