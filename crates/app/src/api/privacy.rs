//! Reviewed, durable operational preferences with a separate revision namespace.
use super::{ApiError, ApiJson, AppState, json_body, unavailable};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::Response,
};
use rustwalld_dns_runtime::store::{PrivacyChange, StoreError};
use std::sync::Arc;
fn error(error: StoreError) -> ApiError {
    ApiError(
        match error {
            StoreError::StalePrivacy => StatusCode::PRECONDITION_FAILED,
            StoreError::InvalidPrivacy(_) => StatusCode::UNPROCESSABLE_ENTITY,
            StoreError::QueueUnavailable => StatusCode::TOO_MANY_REQUESTS,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        },
        error.to_string(),
    )
}
pub(super) async fn get(State(state): State<Arc<AppState>>) -> Result<Response, ApiError> {
    let value = state.control.privacy().await.map_err(error)?;
    json_body(
        StatusCode::OK,
        Some(format!("\"p{}\"", value.revision)),
        value,
        None,
    )
    .await
}
pub(super) async fn change(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<PrivacyChange>,
) -> Result<Response, ApiError> {
    let tag = headers
        .get(header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            ApiError(
                StatusCode::PRECONDITION_REQUIRED,
                "Current privacy ETag is required".into(),
            )
        })?;
    let expected = tag
        .strip_prefix("\"p")
        .and_then(|tag| tag.strip_suffix('"'))
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| format!("\"p{value}\"") == tag)
        .ok_or_else(|| {
            ApiError(
                StatusCode::PRECONDITION_FAILED,
                "Privacy revision changed".into(),
            )
        })?;
    let permit = state.heavy()?;
    let control = state.control.clone();
    let (value, permit) = tokio::spawn(async move {
        let value = control
            .change_privacy(expected, input)
            .await
            .map_err(error)?;
        Ok::<_, ApiError>((value, permit))
    })
    .await
    .map_err(unavailable)??;
    json_body(
        StatusCode::OK,
        Some(format!("\"p{}\"", value.revision)),
        value,
        Some(permit),
    )
    .await
}
