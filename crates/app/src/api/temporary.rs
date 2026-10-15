//! Small, explicit per-client temporary actions through durable publication.
use super::{ApiError, ApiJson, AppState, invalid, required_version, unavailable};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Response,
};
use ring::rand::SecureRandom;
use rustwalld_dns_policy::TemporaryException;
use rustwalld_dns_runtime::Candidate;
use std::{
    net::IpAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
#[derive(serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Allow,
    Pause,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Input {
    operation: Operation,
    client: IpAddr,
    domain: Option<String>,
    duration_secs: u64,
}
pub(super) async fn action(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ApiJson(input): ApiJson<Input>,
) -> Result<Response, ApiError> {
    let expected = required_version(&headers)?;
    let permit = state.heavy()?;
    let pinned = super::revisions::pinned(&state)?;
    if expected != pinned.version {
        return Err(ApiError(
            StatusCode::PRECONDITION_FAILED,
            "configuration changed before temporary action".into(),
        ));
    }
    if pinned.version.shadow.is_some() {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "Review or stop the shadow candidate before a quick temporary action".into(),
        ));
    }
    let client = input.client.to_canonical();
    if !pinned.active.permits(client) {
        return Err(invalid("temporary actions cannot grant client admission"));
    }
    if !(1..=3600).contains(&input.duration_secs) {
        return Err(invalid("quick actions last 1..3600 seconds"));
    }
    let domain = match input.operation {
        Operation::Allow => rustwalld_dns_filter::normalize(
            input
                .domain
                .as_deref()
                .ok_or_else(|| invalid("allow action needs a domain"))?,
        )
        .map_err(invalid)?,
        Operation::Pause if input.domain.is_none() => "*".into(),
        Operation::Pause => return Err(invalid("pause action must omit domain")),
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(unavailable)?
        .as_secs();
    let expires_at = now
        .checked_add(input.duration_secs)
        .ok_or_else(|| invalid("expiry overflow"))?;
    let policy_name = pinned.active.select(client).policy.name().to_owned();
    let mut random = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| unavailable("random source unavailable"))?;
    let name = format!(
        "quick-{}",
        random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    // Whole-config cloning stays off the HTTP executor and holds admission on
    // cancellation. The runtime checks assertions and the same ETag again.
    let (config, permit) = tokio::task::spawn_blocking(move || {
        let mut config = pinned.active.config().clone();
        let policy = config
            .policies
            .iter_mut()
            .find(|policy| policy.name == policy_name)
            .ok_or_else(|| unavailable("selected policy missing"))?;
        policy.temporary_exceptions.retain(|entry| {
            entry.expires_at > now
                && !(entry.domain == domain
                    && !entry.include_subdomains
                    && entry.clients == [ipnet::IpNet::from(client)])
        });
        policy.temporary_exceptions.push(TemporaryException {
            name,
            domain,
            expires_at,
            clients: vec![client.into()],
            include_subdomains: false,
        });
        Ok::<_, ApiError>((config, permit))
    })
    .await
    .map_err(unavailable)??;
    super::revisions::stage_admitted(
        state,
        Candidate::Config(config),
        expected,
        false,
        "quick-temporary",
        permit,
    )
    .await
}
