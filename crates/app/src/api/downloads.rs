use super::{ApiError, ApiJson, AppState, json_body, required_version, revisions::revision_tag};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use rustwalld_dns_policy::PolicyConfigSet;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

pub(super) async fn refresh_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<crate::refreshes::Status>, ApiError> {
    Ok(Json(state.control.refresh_status()?))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RefreshRequest {
    source: usize,
}
pub(super) async fn queue_refresh(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<RefreshRequest>,
) -> Result<Response, ApiError> {
    let expected = required_version(&headers)?;
    let generation = state.control.queue_refresh(request.source, expected)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"queued": true, "generation": generation, "source": request.source})),
    )
        .into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DownloadPreview {
    config: PolicyConfigSet,
    source: usize,
}
#[derive(Serialize)]
struct FailedPreview {
    error: &'static str,
    report: rustwalld_dns_policy::CheckReport,
}
pub(super) async fn preview_download(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<DownloadPreview>,
) -> Result<Response, ApiError> {
    let expected = required_version(&headers)?;
    let _heavy = state.heavy()?;
    let preview = state
        .control
        .preview_download(input.config, input.source, expected)
        .await?;
    if preview.report.valid {
        // The tag the caller checked, so staging the preview detects later changes.
        json_body(StatusCode::OK, Some(revision_tag(expected)), preview).await
    } else {
        json_body(
            StatusCode::UNPROCESSABLE_ENTITY,
            None,
            FailedPreview {
                error: "downloaded candidate failed required assertions",
                report: preview.report,
            },
        )
        .await
    }
}
