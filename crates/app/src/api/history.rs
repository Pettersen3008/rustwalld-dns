//! Original rule/exception provenance, never a current-policy reconstruction.
use super::{ApiError, ApiPath, AppState, json_body, unavailable};
use axum::{extract::State, http::StatusCode, response::Response};
use rustwalld_dns_filter::{Action, FilterSnapshot, Matcher, Source};
use rustwalld_dns_policy::{PolicyConfigSet, TemporaryException};
use rustwalld_dns_runtime::store::HistoryEntry;
use std::sync::Arc;
#[derive(serde::Serialize)]
struct Trace {
    basis: &'static str,
    event: HistoryEntry,
    revision_available: bool,
    policy: Option<String>,
    rule: Option<RecordedRule>,
    temporary_exception: Option<TemporaryException>,
    safe_search: Option<rustwalld_dns_policy::SafeSearchMatch>,
    service_schedule: Option<RecordedSchedule>,
}
#[derive(serde::Serialize)]
struct RecordedSchedule {
    time_zone: String,
    state: rustwalld_dns_policy::ServiceScheduleState,
}
#[derive(serde::Serialize)]
struct RecordedRule {
    domain: String,
    action: Action,
    matcher: Matcher,
    #[serde(skip_serializing_if = "Option::is_none")]
    denyallow: Option<Arc<rustwalld_dns_filter::DomainExclusions>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dnstype: Option<rustwalld_dns_filter::TypeSelector>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client: Option<rustwalld_dns_filter::ClientSelector>,
    /// Original per-rule tag restrictions.
    #[serde(skip_serializing_if = "Option::is_none")]
    ctag: Option<rustwalld_dns_filter::TagSelector>,
    total_sources: usize,
    sources: Vec<Source>,
}
pub(super) async fn explain(
    State(state): State<Arc<AppState>>,
    ApiPath(id): ApiPath<u64>,
) -> Result<Response, ApiError> {
    let permit = state.heavy()?;
    let event = state
        .control
        .store()
        .query(id)
        .await
        .map_err(unavailable)?
        .ok_or_else(|| {
            ApiError(
                StatusCode::NOT_FOUND,
                "Query has expired from retained history".into(),
            )
        })?;
    let revision = state
        .control
        .store()
        .revision(event.generation)
        .await
        .map_err(unavailable)?;
    let (trace, permit) = tokio::task::spawn_blocking(move || {
        let mut trace = Trace {
            basis: "recorded_generation",
            event,
            revision_available: revision.is_some(),
            policy: None,
            rule: None,
            temporary_exception: None,
            safe_search: None,
            service_schedule: None,
        };
        if let Some(revision) = revision {
            let config: PolicyConfigSet =
                serde_json::from_value(revision.config).map_err(unavailable)?;
            let policy = usize::try_from(trace.event.policy_id)
                .ok()
                .and_then(|id| config.policies.get(id))
                .ok_or_else(|| unavailable("Recorded policy is absent from its revision"))?;
            trace.policy = Some(policy.name.clone());
            if (trace.event.source == "safe_search"
                || trace.event.matched_domain.is_some()
                || (trace.event.source == "failure" && trace.event.action == "allow"))
                && let Some(settings) = &policy.safe_search
            {
                trace.safe_search = settings.explain(&trace.event.domain).map_err(unavailable)?;
            }
            let scheduled = policy.blocked_services.as_ref().is_some_and(|value|value.schedule.is_some());
            if scheduled != trace.event.service_schedule.is_some() {
                return Err(unavailable("Recorded schedule state does not match its revision; original rule provenance cannot be guessed"));
            }
            trace.service_schedule = policy.blocked_services.as_ref().and_then(|value|value.schedule.as_ref()).zip(trace.event.service_schedule).map(|(schedule,state)|RecordedSchedule{time_zone:schedule.time_zone.clone(),state});
            if let Some(id) = trace.event.rule_id {
                let inputs = policy.filter_inputs_for_services(trace.event.service_schedule.is_none_or(|state|state.blocking())).map_err(unavailable)?;
                let filters = FilterSnapshot::compile(&inputs, 10_000_000, 256 * 1024 * 1024)
                    .map_err(unavailable)?;
                let rule = filters
                    .rule(id)
                    .ok_or_else(|| unavailable("Recorded rule is absent from its revision"))?;
                trace.rule = Some(RecordedRule {
                    domain: rule.domain.to_string(),
                    action: rule.action,
                    matcher: rule.matcher,
                    denyallow: rule.denyallow().cloned(),
                    dnstype: rule.dnstype().cloned(),
                    client:rule.client().cloned(),
                    ctag:rule.scope.as_ref().and_then(|scope| scope.ctag.as_deref()).cloned(),
                    total_sources: rule.sources.len(),
                    sources: rule.sources.iter().take(100).cloned().collect(),
                });
            }
            if let Some(id) = trace.event.temporary_exception {
                trace.temporary_exception = Some(
                    policy
                        .temporary_exceptions
                        .get(usize::from(id))
                        .ok_or_else(|| {
                            unavailable("Recorded exception is absent from its revision")
                        })?
                        .clone(),
                );
            }
        }
        Ok::<_, ApiError>((trace, permit))
    })
    .await
    .map_err(unavailable)??;
    json_body(StatusCode::OK, None, trace, Some(permit)).await
}
