#![allow(clippy::unwrap_used)]
use super::*;

#[tokio::test]
async fn real_http_auth_assertions_explanations_history_and_metrics() {
    let harness = Harness::start().await;
    assert_eq!(
        reqwest::get(format!("{}/api/v1/config", harness.base))
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(harness.get("/api/v1/revisions/999").await.status(), 404);
    for endpoint in [
        "/healthz",
        "/api/v1/status",
        "/api/v1/clients",
        "/api/v1/policies",
        "/api/v1/filter-lists",
        "/api/v1/upstreams",
        "/api/v1/revisions",
    ] {
        assert!(
            harness.get(endpoint).await.status().is_success(),
            "{endpoint}"
        );
    }
    assert_eq!(
        harness.dns("x.ads.test.").await.metadata.response_code,
        ResponseCode::NXDomain
    );
    let explanation: Value = harness
        .get("/api/v1/explain?client=127.0.0.1&domain=x.ads.test")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(explanation["decision"]["action"], "block");
    assert_eq!(explanation["rule"]["sources"][0]["list"], "test");
    assert_eq!(explanation["permitted"], true);
    let dropped: Value = harness
        .get("/api/v1/explain?client=192.0.2.1&domain=safe.test")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(dropped["permitted"], false);
    let mut config = harness.state.control.engine().active().config().clone();
    config.assertions.push(rustwalld_dns_policy::Assertion {
        client: "127.0.0.1".parse().unwrap(),
        domain: "ads.test".into(),
        expected: Action::Allow,
    });
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        422
    );
    assert_eq!(harness.state.control.engine().active().generation(), 1);
    assert_eq!(
        harness
            .send("/api/v1/policy/test", &config, false)
            .await
            .status(),
        422
    );
    let histories = timeout(Duration::from_secs(2), async {
        loop {
            let rows: Value = harness.get("/api/v1/queries").await.json().await.unwrap();
            if !rows.as_array().unwrap().is_empty() {
                break rows;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(histories[0]["domain"], "x.ads.test");
    let metrics = harness.get("/metrics").await.text().await.unwrap();
    assert!(metrics.contains("rustwalld_blocked_total 1"));
    assert!(metrics.contains("rustwalld_requests_total 1"));
    assert!(metrics.contains("rustwalld_history_events_total 1"));
    for name in [
        "requests",
        "blocked",
        "temporary_allows",
        "rewrites",
        "failures",
        "stale_answers",
        "decision_cache_hits",
        "events_dropped",
        "shadow_differences",
        "udp_overloads",
        "upstream_wait_overloads",
        "tcp_overloads",
        "listener_errors",
        "dns_cache_hits",
        "coalesced",
        "upstream_lookups",
        "inflight_overloads",
        "history_write_failures",
        "history_events",
    ] {
        let counter = format!("rustwalld_{name}_total");
        assert!(
            metrics
                .lines()
                .any(|line| line == format!("# TYPE {counter} counter"))
        );
        let value = metrics
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{counter} ")))
            .unwrap();
        assert!(value.parse::<u64>().is_ok(), "{counter}: {value}");
    }
    assert!(metrics.contains("rustwalld_query_latency_microseconds_bucket{le=\"+Inf\"} 1"));
    assert!(metrics.contains("rustwalld_query_latency_microseconds_count 1"));
    harness.shutdown().await;
}

#[tokio::test]
async fn history_retention_is_bounded() {
    let harness = Harness::start().await;
    for _ in 0..30 {
        harness.dns("ads.test.").await;
    }
    timeout(Duration::from_secs(2), async {
        while harness
            .state
            .control
            .store()
            .metrics
            .snapshot()
            .persisted_events
            < 30
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let rows: Value = harness
        .get("/api/v1/queries?limit=1000")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 10);
    harness.shutdown().await;
}

#[tokio::test]
async fn upstream_diagnostics_survive_failures_and_reset_with_generation() {
    use hickory_proto::rr::{RData, Record, rdata::A};
    use std::sync::atomic::AtomicU8;
    let harness = Harness::start().await;
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = upstream.local_addr().unwrap();
    let mode = Arc::new(AtomicU8::new(0));
    let pinned_seen = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let fixture = {
        let mode = mode.clone();
        let seen = pinned_seen.clone();
        let release = release.clone();
        tokio::spawn(async move {
            let mut bytes = [0; 4096];
            loop {
                let (len, source) = upstream.recv_from(&mut bytes).await.unwrap();
                let request = Message::from_vec(&bytes[..len]).unwrap();
                if request.queries[0].name().to_ascii() == "pinned.test." {
                    seen.notify_one();
                    release.notified().await;
                }
                let mut response = request.into_response();
                match mode.load(Ordering::SeqCst) {
                    1 => response.metadata.response_code = ResponseCode::ServFail,
                    2 => response.metadata.response_code = ResponseCode::Refused,
                    3 => continue,
                    _ => {
                        response.add_answer(Record::from_rdata(
                            response.queries[0].name().clone(),
                            60,
                            RData::A(A("192.0.2.1".parse().unwrap())),
                        ));
                    }
                };
                upstream
                    .send_to(&response.to_vec().unwrap(), source)
                    .await
                    .unwrap();
            }
        })
    };
    let mut config = harness.state.control.engine().active().config().clone();
    config.upstreams[0].addresses = vec![address];
    config.upstreams[0].timeout_ms = 200;
    assert!(
        harness
            .send("/api/v1/config", &config, true)
            .await
            .status()
            .is_success()
    );
    let old = harness.state.control.engine().snapshot();
    assert_eq!(
        harness.dns("ads.test.").await.metadata.response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(old.upstreams()[0].health()[0].snapshot().attempts, 0);
    assert_eq!(harness.dns("cached.test.").await.answers.len(), 1);
    assert_eq!(harness.dns("cached.test.").await.answers.len(), 1);
    assert_eq!(old.upstreams()[0].health()[0].snapshot().attempts, 1);
    for (value, domain) in [
        (1, "servfail.test."),
        (2, "refused.test."),
        (3, "deadline.test."),
    ] {
        mode.store(value, Ordering::SeqCst);
        assert_eq!(
            harness.dns(domain).await.metadata.response_code,
            ResponseCode::ServFail
        );
    }
    mode.store(0, Ordering::SeqCst);
    assert_eq!(harness.dns("recovered.test.").await.answers.len(), 1);
    let health: Value = harness.get("/api/v1/upstreams").await.json().await.unwrap();
    assert_eq!(health[0]["generation"], old.generation());
    let server = &health[0]["servers"][0];
    let keys: std::collections::BTreeSet<_> = server
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        std::collections::BTreeSet::from([
            "address",
            "attempts",
            "successes",
            "inflight",
            "ewma_us",
            "failures",
            "backoff_skips",
            "recovery_probes",
            "admission",
        ])
    );
    assert_eq!(server["admission"]["state"], "ready");
    assert_eq!(server["admission"]["retry_after_ms"], 0);
    assert_eq!(server["attempts"], 5);
    assert_eq!(server["successes"], 2);
    assert_eq!(server["inflight"], 0);
    assert_eq!(server["failures"]["servfail"], 1);
    assert_eq!(server["failures"]["refused"], 1);
    assert_eq!(server["failures"]["deadline"], 1);
    assert_eq!(
        server["failures"]
            .as_object()
            .unwrap()
            .values()
            .map(|v| v.as_u64().unwrap())
            .sum::<u64>(),
        3
    );
    assert_eq!(server["failures"].as_object().unwrap().len(), 12);
    let engine = harness.state.control.engine().clone();
    let pending = tokio::spawn(async move {
        let mut request = Message::query();
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(
            Name::from_ascii("pinned.test.").unwrap(),
            RecordType::A,
        ));
        engine
            .answer(
                &request.to_vec().unwrap(),
                "127.0.0.1".parse().unwrap(),
                Transport::Udp,
            )
            .await
            .unwrap()
    });
    timeout(Duration::from_secs(1), pinned_seen.notified())
        .await
        .unwrap();
    let pinned_counters = old.upstreams()[0].health()[0].snapshot();
    assert_eq!(pinned_counters.inflight, 1);
    assert!(
        harness
            .send("/api/v1/config", &config, true)
            .await
            .status()
            .is_success()
    );
    assert!(!pending.is_finished());
    release.notify_one();
    assert_eq!(
        Message::from_vec(&pending.await.unwrap())
            .unwrap()
            .answers
            .len(),
        1
    );
    // The sample remains ordinary detached data after the live attempt completes.
    assert_eq!(pinned_counters.inflight, 1);
    assert_eq!(pinned_counters.successes, 2);
    assert_eq!(old.upstreams()[0].health()[0].snapshot().successes, 3);
    assert_eq!(old.upstreams()[0].health()[0].snapshot().inflight, 0);
    let fresh: Value = harness.get("/api/v1/upstreams").await.json().await.unwrap();
    assert!(fresh[0]["generation"].as_u64().unwrap() > old.generation());
    assert_eq!(fresh[0]["servers"][0]["attempts"], 0);
    // Answers cached before the publish stay warm for the unchanged upstream,
    // so use a new name to exercise the fresh forwarder's counters.
    assert_eq!(harness.dns("cached.test.").await.answers.len(), 1);
    let fresh: Value = harness.get("/api/v1/upstreams").await.json().await.unwrap();
    assert_eq!(fresh[0]["servers"][0]["attempts"], 0);
    assert_eq!(harness.dns("fresh.test.").await.answers.len(), 1);
    let fresh: Value = harness.get("/api/v1/upstreams").await.json().await.unwrap();
    assert_eq!(fresh[0]["servers"][0]["attempts"], 1);
    assert_eq!(fresh[0]["servers"][0]["successes"], 1);
    assert!(
        fresh[0]["servers"][0]["failures"]
            .as_object()
            .unwrap()
            .values()
            .all(|v| v == 0)
    );
    harness.shutdown().await;
    fixture.abort();
    let _ = fixture.await;
}
