use super::{ApiError, ApiJson, ApiPath, AppState, invalid, json_body, required_version};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Response,
};
use rustwalld_dns_core::{PolicyVersion, PublicationTarget};
use rustwalld_dns_policy::{PolicyConfigSet, PolicySnapshot};
use rustwalld_dns_runtime::{
    Candidate,
    store::{Revision, RevisionSummary},
};
use serde::Serialize;
use std::sync::Arc;

pub(super) fn revision_tag(version: PolicyVersion) -> String {
    format!("\"g{}-s{}\"", version.active, version.shadow.unwrap_or(0))
}
/// Parse a tag produced by [`revision_tag`]; any other spelling is rejected.
pub(super) fn parse_tag(tag: &str) -> Option<PolicyVersion> {
    let (active, shadow) = tag
        .strip_prefix("\"g")?
        .strip_suffix('"')?
        .split_once("-s")?;
    let version = PolicyVersion {
        active: active.parse().ok()?,
        shadow: Some(shadow.parse::<u64>().ok()?).filter(|shadow| *shadow != 0),
    };
    (revision_tag(version) == tag).then_some(version)
}
/// Tag of the current active/shadow pair, read under one consistent version.
pub(super) fn current_tag(state: &AppState) -> String {
    revision_tag(state.control.version())
}

/// Serializes a pinned snapshot's configuration without cloning it.
struct SnapshotConfig(Arc<PolicySnapshot>);
impl Serialize for SnapshotConfig {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.config().serialize(serializer)
    }
}
#[derive(Serialize)]
struct ShadowBody {
    generation: Option<u64>,
    config: Option<SnapshotConfig>,
}
/// The live active/shadow snapshots together with the version that names them.
struct Pinned {
    version: PolicyVersion,
    active: Arc<PolicySnapshot>,
    shadow: Option<Arc<PolicySnapshot>>,
}
/// Read a consistent pair; a publication between the reads is retried.
fn pinned(state: &AppState) -> Result<Pinned, ApiError> {
    for _ in 0..3 {
        let version = state.control.version();
        let active = state.control.engine().snapshot();
        let shadow = state.control.engine().shadow_snapshot();
        if active.generation() == version.active
            && shadow.as_ref().map(|s| s.generation()) == version.shadow
        {
            return Ok(Pinned {
                version,
                active,
                shadow,
            });
        }
    }
    Err(ApiError(
        StatusCode::CONFLICT,
        "configuration is changing; retry".into(),
    ))
}

pub(super) async fn config(State(state): State<Arc<AppState>>) -> Result<Response, ApiError> {
    let _heavy = state.heavy()?;
    let pinned = pinned(&state)?;
    json_body(
        StatusCode::OK,
        Some(revision_tag(pinned.version)),
        SnapshotConfig(pinned.active),
    )
    .await
}
pub(super) async fn shadow_config(
    State(state): State<Arc<AppState>>,
) -> Result<Response, ApiError> {
    let _heavy = state.heavy()?;
    let pinned = pinned(&state)?;
    json_body(
        StatusCode::OK,
        Some(revision_tag(pinned.version)),
        ShadowBody {
            generation: pinned.version.shadow,
            config: pinned.shadow.map(SnapshotConfig),
        },
    )
    .await
}

pub(super) async fn test(
    State(state): State<Arc<AppState>>,
    ApiJson(config): ApiJson<PolicyConfigSet>,
) -> Result<Response, ApiError> {
    let _heavy = state.heavy()?;
    let report = state.control.test(config).await?;
    if report.valid {
        json_body(StatusCode::OK, None, report).await
    } else {
        #[derive(Serialize)]
        struct Failed {
            error: String,
            report: rustwalld_dns_policy::CheckReport,
        }
        let error = format!(
            "required policy assertions failed: {} of {}",
            report.failed, report.assertions
        );
        json_body(
            StatusCode::UNPROCESSABLE_ENTITY,
            None,
            Failed { error, report },
        )
        .await
    }
}
pub(super) async fn promote(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ApiJson(config): ApiJson<PolicyConfigSet>,
) -> Result<Response, ApiError> {
    stage(state, Candidate::Config(config), &headers, false, "api").await
}
pub(super) async fn shadow(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ApiJson(config): ApiJson<PolicyConfigSet>,
) -> Result<Response, ApiError> {
    stage(
        state,
        Candidate::Config(config),
        &headers,
        true,
        "api-shadow",
    )
    .await
}
pub(super) async fn stage(
    state: Arc<AppState>,
    candidate: Candidate,
    headers: &HeaderMap,
    shadow: bool,
    actor: &'static str,
) -> Result<Response, ApiError> {
    let expected = required_version(headers)?;
    let _heavy = state.heavy()?;
    let target = if shadow {
        PublicationTarget::Shadow
    } else {
        PublicationTarget::Active
    };
    let result = state
        .control
        .stage(candidate, Some(expected), target, actor)
        .await?;
    json_body(StatusCode::OK, Some(current_tag(&state)), result).await
}
pub(super) async fn promote_shadow(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    stage(state, Candidate::Shadow, &headers, false, "shadow-promote").await
}
pub(super) async fn clear_shadow(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let expected = required_version(&headers)?;
    let result = state.control.clear_shadow(Some(expected)).await?;
    json_body(StatusCode::OK, Some(current_tag(&state)), result).await
}
pub(super) async fn revisions(
    State(state): State<Arc<AppState>>,
) -> Result<axum::Json<Vec<RevisionSummary>>, ApiError> {
    Ok(axum::Json(state.control.revisions().await?))
}
pub(super) async fn revision(
    State(state): State<Arc<AppState>>,
    ApiPath(id): ApiPath<u64>,
) -> Result<Response, ApiError> {
    let _heavy = state.heavy()?;
    let revision: Revision = state.control.revision(id).await?;
    json_body(StatusCode::OK, None, revision).await
}
pub(super) async fn rollback(
    State(state): State<Arc<AppState>>,
    ApiPath(id): ApiPath<u64>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    required_version(&headers)?;
    let revision = state.control.revision(id).await?;
    let config = tokio::task::spawn_blocking(move || {
        serde_json::from_value::<PolicyConfigSet>(revision.config).map_err(invalid)
    })
    .await
    .map_err(super::unavailable)??;
    stage(
        state,
        Candidate::Config(config),
        &headers,
        false,
        "rollback",
    )
    .await
}
