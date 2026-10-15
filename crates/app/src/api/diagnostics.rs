use super::{ApiError, ApiQuery, AppState, invalid, unavailable};
use axum::{Json, extract::State};
use rustwalld_dns_core::telemetry::LATENCY_US;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{net::IpAddr, sync::Arc};

pub(super) async fn upstreams(State(state): State<Arc<AppState>>) -> Json<Value> {
    let snapshot = state.control.engine().active();
    let profiles = snapshot
        .upstreams()
        .iter()
        .enumerate()
        .map(|(i, upstream)| {
            let Some(config) = snapshot.config().upstreams.get(i) else {
                return Value::Null;
            };
            let (transport, server_name, path) = match &config.transport {
                rustwalld_dns_policy::UpstreamTransport::Udp => ("udp", None, None),
                rustwalld_dns_policy::UpstreamTransport::Tls { server_name, .. } => {
                    ("tls", Some(server_name), None)
                }
                rustwalld_dns_policy::UpstreamTransport::Https {
                    server_name, path, ..
                } => ("https", Some(server_name), Some(path)),
                _ => ("other", None, None),
            };
            let servers = upstream
                .health()
                .iter()
                .map(|health| {
                    let health = health.snapshot();
                    let failures = rustwalld_dns_resolver::FailureKind::ALL
                        .into_iter()
                        .map(|kind| (kind, health.failure_count(kind)))
                        .collect::<std::collections::BTreeMap<_, _>>();
                    json!({
                        "address": health.address,
                        "attempts": health.attempts,
                        "successes": health.successes,
                        "inflight": health.inflight,
                        "ewma_us": health.ewma_us,
                        "failures": failures,
                        "backoff_skips": health.backoff_skips,
                        "recovery_probes": health.recovery_probes,
                        "admission": health.admission,
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "generation": snapshot.generation(), "name": config.name,
                "transport": transport, "server_name": server_name,
                "path": path, "servers": servers,
            })
        })
        .collect::<Vec<_>>();
    Json(json!(profiles))
}

#[derive(Deserialize)]
pub(super) struct ExplainQuery {
    client: IpAddr,
    domain: String,
    #[serde(default = "default_qtype")]
    qtype: u16,
    answer_value: Option<String>,
    answer_type: Option<u16>,
}
fn default_qtype() -> u16 {
    1
}
pub(super) async fn explain(
    State(state): State<Arc<AppState>>,
    ApiQuery(query): ApiQuery<ExplainQuery>,
) -> Result<Json<Value>, ApiError> {
    let snapshot = state.control.engine().active();
    let kind = hickory_proto::rr::RecordType::from(query.qtype);
    let explanation = match (query.answer_value, query.answer_type) {
        (None, None) => snapshot.explain_query(query.client, &query.domain, kind),
        (Some(value), Some(rrtype)) => {
            snapshot.explain_answer_query(query.client, &query.domain, kind, &value, rrtype)
        }
        _ => Err(rustwalld_dns_policy::PolicyError::Invalid(
            "answer_value and answer_type must be supplied together".into(),
        )),
    }
    .map_err(invalid)?;
    Ok(Json(
        serde_json::to_value(explanation).map_err(unavailable)?,
    ))
}
pub(super) async fn metrics(State(state): State<Arc<AppState>>) -> String {
    use std::fmt::Write;
    let m = state.control.engine().telemetry().metrics.snapshot();
    let r = state.control.engine().resolver().metrics.snapshot();
    let db = state.control.store_metrics().snapshot();
    let mut output = String::new();
    for (name, value) in [
        ("requests", m.requests),
        ("blocked", m.blocked),
        ("temporary_allows", m.temporary_allows),
        ("rewrites", m.rewrites),
        ("failures", m.failures),
        ("stale_answers", m.stale_answers),
        ("decision_cache_hits", m.decision_hits),
        ("events_dropped", m.dropped_events),
        ("shadow_differences", m.shadow_differences),
        ("udp_overloads", m.udp_overloads),
        ("upstream_wait_overloads", m.forward_overloads),
        ("tcp_overloads", m.tcp_overloads),
        ("listener_errors", m.listener_errors),
        ("dns_cache_hits", r.cache_hits),
        ("coalesced", r.coalesced),
        ("upstream_lookups", r.upstream_lookups),
        ("inflight_overloads", r.overloads),
        ("history_write_failures", db.write_failures),
        ("history_events", db.persisted_events),
    ] {
        let _ = writeln!(
            output,
            "# TYPE rustwalld_{name}_total counter\nrustwalld_{name}_total {}",
            value
        );
    }
    let _ = writeln!(
        output,
        "# TYPE rustwalld_query_latency_microseconds histogram"
    );
    let mut count = 0u64;
    for (index, bound) in LATENCY_US.iter().enumerate() {
        count += m.latency_buckets[index];
        let label = if *bound == u64::MAX {
            "+Inf".into()
        } else {
            bound.to_string()
        };
        let _ = writeln!(
            output,
            "rustwalld_query_latency_microseconds_bucket{{le=\"{label}\"}} {count}"
        );
    }
    let _ = writeln!(output, "rustwalld_query_latency_microseconds_count {count}");
    let _ = writeln!(
        output,
        "rustwalld_query_latency_microseconds_sum {}",
        m.latency_sum_us
    );
    output
}
