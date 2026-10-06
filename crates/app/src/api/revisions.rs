use super::{ApiError, AppState, expected_version, invalid, unavailable};
use crate::store::{Revision, RevisionSummary, Store};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use rustwalld_dns_policy::PolicyConfigSet;
use serde_json::json;
use std::sync::Arc;

pub(super) fn revision_tag(active: u64, shadow: Option<u64>) -> String {
    format!("\"g{active}-s{}\"", shadow.unwrap_or(0))
}
pub(super) fn current_tag(state: &AppState) -> String {
    revision_tag(
        state.control.engine.active().generation(),
        state
            .control
            .engine
            .shadow()
            .as_ref()
            .map(|s| s.generation()),
    )
}
pub(super) fn check_revision(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
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
pub(super) async fn config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let active = state.control.engine.snapshot();
    let tag = revision_tag(
        active.generation(),
        state
            .control
            .engine
            .shadow()
            .as_ref()
            .map(|s| s.generation()),
    );
    ([(header::ETAG, tag)], Json(active.config().clone()))
}
pub(super) async fn shadow_config(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let shadow = state.control.engine.shadow_snapshot();
    let tag = revision_tag(
        state.control.engine.active().generation(),
        shadow.as_ref().map(|s| s.generation()),
    );
    (
        [(header::ETAG, tag)],
        Json(json!({
            "generation":shadow.as_ref().map(|s|s.generation()),
            "config":shadow.as_ref().map(|s| s.config())
        })),
    )
}
pub(super) async fn test(
    State(state): State<Arc<AppState>>,
    Json(config): Json<PolicyConfigSet>,
) -> Result<Response, ApiError> {
    let report = state.control.test(config).await.map_err(ApiError::from)?;
    if report.valid {
        Ok(Json(report).into_response())
    } else {
        Ok((StatusCode::UNPROCESSABLE_ENTITY,Json(json!({"error":format!("required policy assertions failed: {} of {}",report.failed,report.assertions),"report":report}))).into_response())
    }
}

pub(super) async fn promote(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(config): Json<PolicyConfigSet>,
) -> Result<Response, ApiError> {
    stage(state, Candidate::Config(config), headers, false, "api").await
}
pub(super) async fn shadow(
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
use rustwalld_dns_runtime::Candidate;
pub(super) async fn stage(
    state: Arc<AppState>,
    candidate: Candidate,
    headers: HeaderMap,
    shadow: bool,
    actor: &'static str,
) -> Result<Response, ApiError> {
    let target = if shadow {
        rustwalld_dns_core::PublicationTarget::Shadow
    } else {
        rustwalld_dns_core::PublicationTarget::Active
    };
    let result = state
        .control
        .stage(candidate, expected_version(&headers), target, actor)
        .await
        .map_err(ApiError::from)?;
    Ok(([(header::ETAG, current_tag(&state))], Json(result)).into_response())
}
pub(super) async fn promote_shadow(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    stage(state, Candidate::Shadow, headers, false, "shadow-promote").await
}
pub(super) async fn clear_shadow(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let result = state
        .control
        .clear_shadow(expected_version(&headers))
        .await
        .map_err(ApiError::from)?;
    Ok(([(header::ETAG, current_tag(&state))], Json(result)).into_response())
}

pub(super) async fn revisions(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<RevisionSummary>>, ApiError> {
    Ok(Json(
        state.control.store.revisions().await.map_err(unavailable)?,
    ))
}
pub(super) async fn revision(
    State(state): State<Arc<AppState>>,
    Path(id): Path<u64>,
) -> Result<Json<Revision>, ApiError> {
    Ok(Json(read_revision(&state.control.store, id).await?))
}
pub(super) async fn read_revision(store: &Store, id: u64) -> Result<Revision, ApiError> {
    if id > i64::MAX as u64 {
        return Err(ApiError(StatusCode::NOT_FOUND, "revision not found".into()));
    }
    let revision = store.revision(id).await.map_err(unavailable)?;
    revision.ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "revision not found".into()))
}
pub(super) async fn rollback(
    State(state): State<Arc<AppState>>,
    Path(id): Path<u64>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let revision = read_revision(&state.control.store, id).await?;
    let config = serde_json::from_value(revision.config).map_err(invalid)?;
    stage(state, Candidate::Config(config), headers, false, "rollback").await
}
