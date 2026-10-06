use super::{ApiResult, AppState, invalid, unavailable};
use axum::{
    Json,
    extract::{Query, State},
};
use rustwalld_dns_core::telemetry::LATENCY_US;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    net::IpAddr,
    sync::{Arc, atomic::Ordering},
};

pub(super) async fn upstreams(State(state): State<Arc<AppState>>) -> Json<Value> {
    let snapshot = state.control.engine.active();
    let profiles = snapshot
        .upstreams()
        .iter()
        .enumerate()
        .map(|(i, upstream)| {
            let config = &snapshot.config().upstreams[i];
            let (transport, server_name, path) = match &config.transport {
                rustwalld_dns_policy::UpstreamTransport::Udp => ("udp", None, None),
                rustwalld_dns_policy::UpstreamTransport::Tls { server_name, .. } => {
                    ("tls", Some(server_name), None)
                }
                rustwalld_dns_policy::UpstreamTransport::Https {
                    server_name, path, ..
                } => ("https", Some(server_name), Some(path)),
            };
            let servers = upstream
                .health
                .iter()
                .map(|health| {
                    let failures = rustwalld_dns_resolver::FailureKind::ALL
                        .into_iter()
                        .map(|kind| (kind, health.failure_count(kind)))
                        .collect::<std::collections::BTreeMap<_, _>>();
                    json!({
                        "address": health.address,
                        "attempts": health.attempts.load(Ordering::Relaxed),
                        "successes": health.successes.load(Ordering::Relaxed),
                        "inflight": health.inflight.load(Ordering::Relaxed),
                        "ewma_us": health.ewma_us.load(Ordering::Relaxed),
                        "failures": failures,
                        "backoff_skips": health.backoff_skips.load(Ordering::Relaxed),
                        "recovery_probes": health.recovery_probes.load(Ordering::Relaxed),
                        "admission": health.admission_status(),
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
}
pub(super) async fn explain(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ExplainQuery>,
) -> ApiResult {
    let snapshot = state.control.engine.active();
    let explanation = snapshot
        .explain(query.client, &query.domain)
        .map_err(invalid)?;
    Ok(Json(
        serde_json::to_value(explanation).map_err(unavailable)?,
    ))
}
pub(super) async fn metrics(State(state): State<Arc<AppState>>) -> String {
    use std::fmt::Write;
    let m = &state.control.engine.telemetry().metrics;
    let r = &state.control.engine.resolver().metrics;
    let db = &state.control.store.metrics;
    let mut output = String::new();
    for (name, value) in [
        ("requests", &m.requests),
        ("blocked", &m.blocked),
        ("temporary_allows", &m.temporary_allows),
        ("rewrites", &m.rewrites),
        ("failures", &m.failures),
        ("decision_cache_hits", &m.decision_hits),
        ("events_dropped", &m.dropped_events),
        ("shadow_differences", &m.shadow_differences),
        ("dns_cache_hits", &r.cache_hits),
        ("coalesced", &r.coalesced),
        ("upstream_lookups", &r.upstream_lookups),
        ("inflight_overloads", &r.overloads),
        ("history_write_failures", &db.write_failures),
        ("history_events", &db.persisted_events),
    ] {
        let _ = writeln!(
            output,
            "# TYPE rustwalld_{name}_total counter\nrustwalld_{name}_total {}",
            value.load(Ordering::Relaxed)
        );
    }
    let _ = writeln!(
        output,
        "# TYPE rustwalld_query_latency_microseconds histogram"
    );
    let mut count = 0u64;
    for (index, bound) in LATENCY_US.iter().enumerate() {
        count += m.latency_buckets[index].load(Ordering::Relaxed);
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
        m.latency_sum_us.load(Ordering::Relaxed)
    );
    output
}
