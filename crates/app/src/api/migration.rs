//! Authenticated upload admission before body buffering and offline migration.
use super::{ApiError, ApiQuery, AppState, json_body, required_version, unavailable};
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::{Arc, Mutex};
use tokio::sync::OwnedSemaphorePermit;
struct Admission(Mutex<Option<OwnedSemaphorePermit>>);
pub(super) async fn admit(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Response {
    if request.uri().path() == "/api/v1/migrations/preview" {
        let permit = match state.heavy() {
            Ok(permit) => permit,
            Err(error) => return error.into_response(),
        };
        request
            .extensions_mut()
            .insert(Arc::new(Admission(Mutex::new(Some(permit)))));
    }
    next.run(request).await
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Input {
    source: crate::migration::Source,
}
pub(super) async fn preview(
    State(state): State<Arc<AppState>>,
    ApiQuery(input): ApiQuery<Input>,
    mut request: Request,
) -> Result<Response, ApiError> {
    let admission = request
        .extensions_mut()
        .remove::<Arc<Admission>>()
        .ok_or_else(|| unavailable("migration admission missing"))?;
    let permit = {
        admission
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
            .ok_or_else(|| unavailable("migration admission consumed"))?
    };
    let expected = required_version(request.headers())?;
    let pinned = super::revisions::pinned(&state)?;
    if expected != pinned.version {
        return Err(ApiError(
            StatusCode::PRECONDITION_FAILED,
            "configuration changed before migration preview".into(),
        ));
    }
    let body = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        axum::body::to_bytes(request.into_body(), crate::migration::MAX_INPUT_BYTES),
    )
    .await
    .map_err(|_| {
        ApiError(
            StatusCode::REQUEST_TIMEOUT,
            "migration upload deadline".into(),
        )
    })?
    .map_err(|_| {
        ApiError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "migration upload exceeds 16 MiB".into(),
        )
    })?;
    let tag = super::revisions::revision_tag(pinned.version);
    let listeners = state.control.dns_listeners().to_vec();
    let (report, permit) = tokio::task::spawn_blocking(move || {
        let source = pinned.active.config();
        let base = rustwalld_dns_policy::PolicyConfigSet {
            default_policy: String::new(),
            policies: vec![],
            upstreams: source.upstreams.clone(),
            bindings: vec![],
            allowed_clients: source.allowed_clients.clone(),
            assertions: source.assertions.clone(),
            filter_sources: vec![],
        };
        let mut report =
            crate::migration::preview(input.source, &body, base).map_err(super::invalid)?;
        for listener in listeners {
            report.validate_listener(listener);
        }
        Ok::<_, ApiError>((report, permit))
    })
    .await
    .map_err(unavailable)??;
    json_body(StatusCode::OK, Some(tag), report, Some(permit)).await
}
