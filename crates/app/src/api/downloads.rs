use super::revisions::{check_revision, current_tag};
use super::{ApiError, AppState, invalid, unavailable};
use crate::config::validate_policy;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use rustwalld_dns_policy::{PolicyConfigSet, PolicySnapshot};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

pub(super) async fn refresh_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<crate::refreshes::Status>, ApiError> {
    let mut status = state
        .control
        .refreshes
        .status(&state.control.engine.active())
        .map_err(unavailable)?;
    status.paused = if state.control.engine.shadow().is_some() {
        Some("shadow_review")
    } else if state.control.mutation.available_permits() == 0 {
        Some("policy_mutation")
    } else {
        None
    };
    Ok(Json(status))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RefreshRequest {
    source: usize,
}
pub(super) async fn queue_refresh(
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
    let _guard = state
        .control
        .mutation
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            ApiError(
                StatusCode::CONFLICT,
                "policy mutation already running".into(),
            )
        })?;
    check_revision(&state, &headers)?;
    if state.control.engine.shadow().is_some() || state.control.downloads.available_permits() == 0 {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "review the existing shadow or wait for the running download".into(),
        ));
    }
    let snapshot = state.control.engine.snapshot();
    if snapshot
        .config()
        .filter_sources
        .get(request.source)
        .is_none_or(|source| source.refresh_interval_secs.is_none())
    {
        return Err(invalid("source has no active refresh schedule"));
    }
    state
        .control
        .refreshes
        .enqueue(&snapshot, request.source)
        .map_err(|error| ApiError(StatusCode::CONFLICT, error))?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"queued":true,"generation":snapshot.generation(),"source":request.source})),
    )
        .into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DownloadPreview {
    config: PolicyConfigSet,
    source: usize,
}

pub(super) async fn preview_download(
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
        .control
        .downloads
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError(StatusCode::CONFLICT, "list download already running".into()))?;
    let listen = state.control.listen;
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
    let guard = state
        .control
        .mutation
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
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
