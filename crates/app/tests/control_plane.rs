#![allow(clippy::unwrap_used, clippy::expect_used)]
use dns_core::{Engine, Server, ServerConfig, telemetry::Telemetry};
use filtering::{Action, ListInput};
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{Name, RecordType},
};
use policy::{PolicyConfigSet, PolicySnapshot};
use rustwalld_dns::{
    api::{self, AppState},
    store::{Operation, Store},
};
use serde_json::Value;
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::Semaphore,
    time::timeout,
};
use tokio_util::sync::CancellationToken;
const TOKEN: &str = "local-test-token-at-least-16";
#[path = "support/download_fixture.rs"]
mod download_fixture;

async fn refresh_state(harness: &Harness, outcome: &str) -> Value {
    timeout(Duration::from_secs(5), async {
        loop {
            let status: Value = harness
                .get("/api/v1/filter-refreshes")
                .await
                .json()
                .await
                .unwrap();
            if status["entries"][0]["outcome"] == outcome && status["running"].is_null() {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap()
}
async fn queue_check(harness: &Harness, tag: Option<&str>) -> reqwest::Response {
    let mut request = reqwest::Client::new()
        .post(format!("{}/api/v1/filter-refreshes/check", harness.base))
        .bearer_auth(TOKEN)
        .json(&serde_json::json!({"source":0}));
    if let Some(tag) = tag {
        request = request.header("If-Match", tag);
    }
    request.send().await.unwrap()
}
async fn current_etag(harness: &Harness) -> String {
    harness.get("/api/v1/config").await.headers()["etag"]
        .to_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn conditional_https_checks_validate_headers_and_preserve_representation() {
    use rustwalld_dns::downloads::{Fetch, fetch_conditional};
    let fixture = download_fixture::Fixture::start().await;
    let source = fixture.source("/conditional");
    let Fetch::Modified {
        text,
        stamp,
        validators,
    } = fetch_conditional(&source, None).await.unwrap()
    else {
        panic!("initial full body required")
    };
    assert_eq!(text, "ads.test");
    assert_eq!(stamp.bytes, text.len());
    assert!(matches!(
        fetch_conditional(&source, Some(&validators)).await.unwrap(),
        Fetch::NotModified { .. }
    ));
    let request = fixture
        .conditional_requests
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .to_lowercase();
    assert!(request.contains("if-none-match: \"v1\""));
    assert!(!request.contains("if-modified-since"));
    fixture.conditional.lock().unwrap().etag = Some("W/\"v1\"".into());
    assert!(matches!(
        fetch_conditional(&source, Some(&validators)).await.unwrap(),
        Fetch::NotModified { .. }
    ));
    // 304 Content-Length is representation metadata, not a body-size admission.
    fixture.conditional.lock().unwrap().text =
        format!("ads.test\n#{}", "x".repeat(policy::MAX_DOWNLOAD_BYTES));
    assert!(matches!(
        fetch_conditional(&source, Some(&validators)).await.unwrap(),
        Fetch::NotModified { .. }
    ));
    fixture.conditional.lock().unwrap().text = "ads.test".into();
    for headers in [
        "ETag: \"other\"\r\n",
        "ETag: malformed\r\n",
        "ETag: \"v1\"\r\nETag: \"v1\"\r\n",
        "Last-Modified: nonsense\r\n",
    ] {
        fixture.conditional.lock().unwrap().not_modified_headers = Some(headers.into());
        assert!(
            fetch_conditional(&source, Some(&validators)).await.is_err(),
            "{headers}"
        );
    }
    {
        let mut publisher = fixture.conditional.lock().unwrap();
        publisher.etag = None;
        publisher.not_modified_headers = None;
    }
    let Fetch::Modified {
        validators: dates, ..
    } = fetch_conditional(&source, None).await.unwrap()
    else {
        panic!("initial body")
    };
    assert!(matches!(
        fetch_conditional(&source, Some(&dates)).await.unwrap(),
        Fetch::NotModified { .. }
    ));
    let request = fixture
        .conditional_requests
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .to_lowercase();
    assert!(request.contains("if-modified-since: sun, 06 nov 1994 08:49:37 gmt"));
    assert!(!request.contains("if-none-match"));
    fixture.conditional.lock().unwrap().not_modified_headers =
        Some("Last-Modified: Sun, 06 Nov 1994 08:49:38 GMT\r\n".into());
    assert!(fetch_conditional(&source, Some(&dates)).await.is_err());
    {
        let mut publisher = fixture.conditional.lock().unwrap();
        publisher.text = "ads.test\nnew.test".into();
        publisher.last_modified = None;
        publisher.not_modified_headers = None;
    }
    let Fetch::Modified {
        text, validators, ..
    } = fetch_conditional(&source, Some(&dates)).await.unwrap()
    else {
        panic!("changed body")
    };
    assert_eq!(text, "ads.test\nnew.test");
    assert!(!validators.usable());
    // Manual recovery does not inherit any conditional header.
    rustwalld_dns::downloads::fetch(&source).await.unwrap();
    let request = fixture
        .conditional_requests
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .to_lowercase();
    assert!(!request.contains("if-none-match"));
    assert!(!request.contains("if-modified-since"));
    fixture.wait_closed().await;
}

async fn checked(
    harness: &Harness,
    fixture: &download_fixture::Fixture,
    outcome: &str,
    status: u16,
) -> Value {
    let before = fixture.requests.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        queue_check(harness, Some(&current_etag(harness).await))
            .await
            .status(),
        202
    );
    fixture.wait_requests(before + 1).await;
    let state = refresh_state(harness, outcome).await;
    assert_eq!(state["entries"][0]["last_http_status"], status);
    state
}
async fn shadow_action(harness: &Harness, promote: bool) {
    let client = reqwest::Client::new();
    let path = format!(
        "{}/api/v1/shadow{}",
        harness.base,
        if promote { "/promote" } else { "" }
    );
    let request = if promote {
        client.post(path)
    } else {
        client.delete(path)
    };
    let response = request
        .bearer_auth(TOKEN)
        .header("If-Match", current_etag(harness).await)
        .send()
        .await
        .unwrap();
    assert!(
        response.status().is_success(),
        "{}",
        response.text().await.unwrap()
    );
}
#[tokio::test]
async fn conditional_schedules_preserve_revisions_and_bind_validators_to_live_content() {
    let harness = Harness::start().await;
    let fixture = download_fixture::Fixture::start().await;
    let (upstream, mock) = local_dns().await;
    let mut config = harness.state.engine.active.load().config.clone();
    config.upstreams[0].addresses = vec![upstream];
    let mut source = fixture.source("/conditional");
    source.refresh_interval_secs = Some(300);
    config.filter_sources = vec![source];
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        200
    );
    refresh_state(&harness, "unchanged").await;
    let next = harness.state.next_generation.load(Ordering::Relaxed);
    let original = harness
        .get("/api/v1/config")
        .await
        .json::<Value>()
        .await
        .unwrap();
    let state = checked(&harness, &fixture, "unchanged", 304).await;
    assert_eq!(state["entries"][0]["last_download_bytes"], 0);
    assert_eq!(harness.state.next_generation.load(Ordering::Relaxed), next);
    assert_eq!(
        harness
            .get("/api/v1/config")
            .await
            .json::<Value>()
            .await
            .unwrap(),
        original
    );
    {
        let mut publisher = fixture.conditional.lock().unwrap();
        publisher.text = "ads.test\n=changed.test".into();
        publisher.etag = Some("\"v2\"".into());
    }
    checked(&harness, &fixture, "staged", 200).await;
    assert_eq!(
        harness.dns("changed.test").await.metadata.response_code,
        ResponseCode::NoError
    );
    // Discarded shadow cannot validate old live bytes using the new ETag.
    shadow_action(&harness, false).await;
    checked(&harness, &fixture, "staged", 200).await;
    let request = fixture
        .conditional_requests
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .to_lowercase();
    assert!(!request.contains("if-none-match"));
    shadow_action(&harness, true).await;
    assert_eq!(
        harness.dns("changed.test").await.metadata.response_code,
        ResponseCode::NXDomain
    );
    checked(&harness, &fixture, "unchanged", 304).await;
    // New generation, same stored body: fingerprint is still valid.
    let mut config = harness.state.engine.active.load().config.clone();
    config.policies[0].rewrites.push(policy::Rewrite {
        domain: "local.test".into(),
        addresses: vec!["192.0.2.10".parse().unwrap()],
        ttl: 60,
    });
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        200
    );
    checked(&harness, &fixture, "unchanged", 304).await;
    // Manual text edits clear provenance. The old entity tag must not validate them.
    config.policies[0].lists[0].rules = "ads.test\n=manual.test".into();
    config.filter_sources[0].download = None;
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        200
    );
    checked(&harness, &fixture, "staged", 200).await;
    let request = fixture
        .conditional_requests
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .to_lowercase();
    assert!(!request.contains("if-none-match"));
    shadow_action(&harness, true).await;
    let next = harness.state.next_generation.load(Ordering::Relaxed);
    fixture.conditional.lock().unwrap().not_modified_headers =
        Some("ETag: \"contradiction\"\r\n".into());
    let before = fixture.requests.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        queue_check(&harness, Some(&current_etag(&harness).await))
            .await
            .status(),
        202
    );
    fixture.wait_requests(before + 1).await;
    let state = refresh_state(&harness, "failed").await;
    assert!(
        state["entries"][0]["error"]
            .as_str()
            .unwrap()
            .contains("contradicts")
    );
    assert_eq!(harness.state.next_generation.load(Ordering::Relaxed), next);
    assert!(harness.state.engine.shadow.load().is_none());
    assert_eq!(
        harness.dns("changed.test").await.metadata.response_code,
        ResponseCode::NXDomain
    );
    fixture.conditional.lock().unwrap().not_modified_headers = None;
    checked(&harness, &fixture, "unchanged", 200).await;
    let request = fixture
        .conditional_requests
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .to_lowercase();
    assert!(!request.contains("if-none-match"));
    checked(&harness, &fixture, "unchanged", 304).await;
    // A fresh worker deliberately has no validators: restart/recovery performs a full GET.
    let worker_stop = CancellationToken::new();
    let state = Arc::new(AppState {
        engine: harness.state.engine.clone(),
        store: harness.state.store.clone(),
        listen: harness.state.listen,
        next_generation: AtomicU64::new(harness.state.next_generation.load(Ordering::Relaxed)),
        mutation: harness.state.mutation.clone(),
        api_slots: harness.state.api_slots.clone(),
        downloads: harness.state.downloads.clone(),
        refreshes: Arc::new(rustwalld_dns::refreshes::Refresher::default()),
        token: TOKEN.into(),
    });
    state
        .refreshes
        .enqueue(&state.engine.active.load(), 0)
        .unwrap();
    let worker = tokio::spawn(rustwalld_dns::refreshes::run(
        state.clone(),
        worker_stop.clone(),
    ));
    timeout(Duration::from_secs(3), async {
        loop {
            if serde_json::to_value(state.refreshes.status(&state.engine.active.load()).unwrap())
                .unwrap()["entries"][0]["outcome"]
                == "unchanged"
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let request = fixture
        .conditional_requests
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .to_lowercase();
    assert!(!request.contains("if-none-match"));
    worker_stop.cancel();
    worker.await.unwrap();
    harness.shutdown().await;
    mock.abort();
}

#[tokio::test]
async fn delayed_conditional_reply_cannot_validate_a_concurrently_edited_generation() {
    let harness = Harness::start().await;
    let fixture = download_fixture::Fixture::start().await;
    let mut config = harness.state.engine.active.load().config.clone();
    let mut source = fixture.source("/conditional");
    source.refresh_interval_secs = Some(300);
    config.filter_sources = vec![source];
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        200
    );
    refresh_state(&harness, "unchanged").await;
    fixture.conditional.lock().unwrap().delay = Duration::from_millis(300);
    let before = fixture.requests.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        queue_check(&harness, Some(&current_etag(&harness).await))
            .await
            .status(),
        202
    );
    fixture.wait_requests(before + 1).await;
    config.policies[0].lists[0].rules = "ads.test\nmanual.test".into();
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        200
    );
    refresh_state(&harness, "deferred").await;
    assert_eq!(harness.state.engine.active.load().generation, 3);
    assert!(harness.state.engine.shadow.load().is_none());
    assert_eq!(
        harness.dns("manual.test").await.metadata.response_code,
        ResponseCode::NXDomain
    );
    fixture.conditional.lock().unwrap().delay = Duration::ZERO;
    checked(&harness, &fixture, "staged", 200).await;
    let request = fixture
        .conditional_requests
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .to_lowercase();
    assert!(!request.contains("if-none-match"));
    harness.shutdown().await;
}

#[tokio::test]
async fn periodic_refresh_is_durable_shadow_only_pauses_and_unchanged_allocates_no_revision() {
    let harness = Harness::start().await;
    let fixture = download_fixture::Fixture::start().await;
    let (upstream, mock) = local_dns().await;
    let mut config = harness.state.engine.active.load().config.clone();
    config.upstreams[0].addresses = vec![upstream];
    let mut source = fixture.source("/ok");
    source.refresh_interval_secs = Some(300);
    config.filter_sources = vec![source];
    assert_eq!(queue_check(&harness, None).await.status(), 428);
    assert_eq!(queue_check(&harness, Some("\"stale\"")).await.status(), 412);
    assert_eq!(
        queue_check(&harness, Some(&current_etag(&harness).await))
            .await
            .status(),
        422
    );
    assert_eq!(
        reqwest::Client::new()
            .get(format!("{}/api/v1/filter-refreshes", harness.base))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        200
    );
    let status = refresh_state(&harness, "staged").await;
    assert_eq!(status["paused"], "shadow_review");
    assert_eq!(harness.state.engine.active.load().generation, 2);
    assert_eq!(
        harness
            .state
            .engine
            .shadow
            .load()
            .as_ref()
            .unwrap()
            .generation,
        3
    );
    assert_eq!(
        harness.dns("downloaded.test").await.metadata.response_code,
        ResponseCode::NoError
    );
    let boot = harness
        .state
        .store
        .call(Operation::Bootstrap {
            config: "ignored".into(),
        })
        .await
        .unwrap();
    assert_eq!(boot["active"], 2);
    assert_eq!(boot["shadow"], 3);
    let revisions: Value = harness.get("/api/v1/revisions").await.json().await.unwrap();
    assert_eq!(revisions[0]["actor"], "scheduled-refresh");
    let saved = harness
        .state
        .store
        .call(Operation::Revision { id: 3 })
        .await
        .unwrap();
    let restored: PolicyConfigSet = serde_json::from_value(saved["config"].clone()).unwrap();
    assert_eq!(restored.filter_sources[0].refresh_interval_secs, Some(300));
    assert_eq!(
        PolicySnapshot::compile(restored, 3)
            .unwrap()
            .explain("127.0.0.1".parse().unwrap(), "downloaded.test")
            .unwrap()
            .decision
            .action,
        Action::Block
    );
    let tag = current_etag(&harness).await;
    assert_eq!(queue_check(&harness, Some(&tag)).await.status(), 409);
    for _ in 0..30 {
        assert_eq!(
            harness.dns("ads.test").await.metadata.response_code,
            ResponseCode::NXDomain
        );
    }
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(
        fixture.requests.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        reqwest::Client::new()
            .post(format!("{}/api/v1/shadow/promote", harness.base))
            .bearer_auth(TOKEN)
            .header("If-Match", &tag)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        harness.dns("downloaded.test").await.metadata.response_code,
        ResponseCode::NXDomain
    );
    let tag = current_etag(&harness).await;
    let next = harness.state.next_generation.load(Ordering::Relaxed);
    assert_eq!(queue_check(&harness, Some(&tag)).await.status(), 202);
    let status = refresh_state(&harness, "unchanged").await;
    assert_eq!(status["entries"][0]["checked_generation"], 4);
    assert_eq!(harness.state.next_generation.load(Ordering::Relaxed), next);
    assert!(harness.state.engine.shadow.load().is_none());
    assert_eq!(
        fixture.requests.load(std::sync::atomic::Ordering::SeqCst),
        2
    );
    let mut disabled = harness.state.engine.active.load().config.clone();
    disabled.filter_sources[0].refresh_interval_secs = None;
    assert_eq!(
        harness
            .send("/api/v1/config", &disabled, true)
            .await
            .status(),
        200
    );
    let status: Value = harness
        .get("/api/v1/filter-refreshes")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(status["entries"], serde_json::json!([]));
    assert_eq!(
        queue_check(&harness, Some(&current_etag(&harness).await))
            .await
            .status(),
        422
    );
    harness.shutdown().await;
    mock.abort();
}

#[tokio::test]
async fn scheduled_failures_keep_last_good_dns_and_shutdown_cancels_stalled_io() {
    let harness = Harness::start().await;
    let fixture = download_fixture::Fixture::start().await;
    let mut config = harness.state.engine.active.load().config.clone();
    config.assertions = vec![policy::Assertion {
        client: "127.0.0.1".parse().unwrap(),
        domain: "ads.test".into(),
        expected: Action::Block,
    }];
    for (path, expected) in [
        ("/invalid", "invalid filter"),
        ("/assertfail", "assertion"),
        ("/redirect", "HTTP 200"),
    ] {
        let mut source = fixture.source(path);
        source.refresh_interval_secs = Some(300);
        config.filter_sources = vec![source];
        assert_eq!(
            harness.send("/api/v1/config", &config, true).await.status(),
            200
        );
        let generation = harness.state.engine.active.load().generation;
        let status = refresh_state(&harness, "failed").await;
        assert!(
            status["entries"][0]["error"]
                .as_str()
                .unwrap()
                .contains(expected),
            "{status}"
        );
        assert!(status["entries"][0]["error"].as_str().unwrap().len() <= 1024);
        assert!(harness.state.engine.shadow.load().is_none());
        assert_eq!(harness.state.engine.active.load().generation, generation);
        assert_eq!(
            harness.dns("ads.test").await.metadata.response_code,
            ResponseCode::NXDomain
        );
    }
    config.assertions.clear();
    config.filter_sources[0] = fixture.source("/comments");
    config.filter_sources[0].refresh_interval_secs = Some(300);
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        200
    );
    assert!(
        refresh_state(&harness, "failed").await["entries"][0]["error"]
            .as_str()
            .unwrap()
            .contains("no rules")
    );
    config.filter_sources[0] = fixture.source("/stall");
    config.filter_sources[0].refresh_interval_secs = Some(300);
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        200
    );
    fixture.wait_requests(5).await;
    assert_eq!(
        queue_check(&harness, Some(&current_etag(&harness).await))
            .await
            .status(),
        409
    );
    for _ in 0..100 {
        assert_eq!(
            harness.dns("ads.test").await.metadata.response_code,
            ResponseCode::NXDomain
        );
    }
    let state = harness.state.clone();
    timeout(Duration::from_secs(3), harness.shutdown())
        .await
        .unwrap();
    fixture.wait_closed().await;
    assert!(state.engine.shadow.load().is_none());
    assert_eq!(state.downloads.available_permits(), 1);
}

#[tokio::test]
async fn a_generation_or_operator_shadow_during_fetch_cannot_be_overwritten() {
    let harness = Harness::start().await;
    let fixture = download_fixture::Fixture::start().await;
    let mut config = harness.state.engine.active.load().config.clone();
    let mut source = fixture.source("/slow");
    source.refresh_interval_secs = Some(300);
    config.filter_sources = vec![source];
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        200
    );
    fixture.wait_requests(1).await;
    config.policies[0].lists[0]
        .rules
        .push_str("\noperator.test");
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        200
    );
    let status = refresh_state(&harness, "deferred").await;
    assert_eq!(status["entries"][0]["checked_generation"], 2);
    assert_eq!(harness.state.engine.active.load().generation, 3);
    assert!(harness.state.engine.shadow.load().is_none());
    assert_eq!(
        queue_check(&harness, Some(&current_etag(&harness).await))
            .await
            .status(),
        202
    );
    fixture.wait_requests(2).await;
    config.policies[0].lists[0].rules.push_str("\ncanary.test");
    assert_eq!(
        harness
            .send("/api/v1/shadow", &config, false)
            .await
            .status(),
        200
    );
    let shadow = harness.state.engine.shadow.load_full().unwrap();
    // Wait for the second attempt's completion, not the previous deferred result.
    timeout(Duration::from_secs(3), async {
        loop {
            let status: Value = harness
                .get("/api/v1/filter-refreshes")
                .await
                .json()
                .await
                .unwrap();
            if status["running"].is_null() && status["entries"][0]["checked_generation"] == 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        harness
            .state
            .engine
            .shadow
            .load()
            .as_ref()
            .unwrap()
            .generation,
        shadow.generation
    );
    assert!(
        shadow.config.policies[0].lists[0]
            .rules
            .contains("canary.test")
    );
    assert_eq!(
        harness.dns("ads.test").await.metadata.response_code,
        ResponseCode::NXDomain
    );
    harness.shutdown().await;
}

#[tokio::test]
async fn scheduled_sqlite_failure_leaves_dns_and_revision_live_then_recovers() {
    let harness = Harness::start().await;
    let fixture = download_fixture::Fixture::start().await;
    let mut config = harness.state.engine.active.load().config.clone();
    let mut source = fixture.source("/ok");
    source.refresh_interval_secs = Some(300);
    source.download = Some(policy::DownloadStamp {
        retrieved_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        sha256: rustwalld_dns::downloads::sha256(b"ads.test"),
        bytes: 8,
    });
    config.filter_sources = vec![source];
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        200
    );
    let database = rusqlite::Connection::open(&harness.path).unwrap();
    database.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert_eq!(
        queue_check(&harness, Some(&current_etag(&harness).await))
            .await
            .status(),
        202
    );
    let status = refresh_state(&harness, "failed").await;
    assert!(
        status["entries"][0]["error"]
            .as_str()
            .unwrap()
            .contains("locked")
    );
    assert_eq!(harness.state.engine.active.load().generation, 2);
    assert!(harness.state.engine.shadow.load().is_none());
    assert_eq!(
        harness.dns("ads.test").await.metadata.response_code,
        ResponseCode::NXDomain
    );
    database.execute_batch("ROLLBACK").unwrap();
    drop(database);
    assert_eq!(
        queue_check(&harness, Some(&current_etag(&harness).await))
            .await
            .status(),
        202
    );
    let status = refresh_state(&harness, "staged").await;
    assert_eq!(status["paused"], "shadow_review");
    assert_eq!(harness.state.engine.active.load().generation, 2);
    harness.shutdown().await;
}

#[tokio::test]
async fn binding_metadata_is_revisioned_specific_and_failure_isolated() {
    let harness = Harness::start().await;
    let mut config = harness.state.engine.active.load().config.clone();
    // Legacy configuration omits metadata and remains readable.
    config.bindings.push(policy::Binding {
        name: "Work laptop".into(),
        network: "127.0.0.1/32".parse().unwrap(),
        policy: "default".into(),
        metadata: None,
    });
    let legacy = serde_json::to_value(&config).unwrap();
    assert!(legacy["bindings"][0].get("metadata").is_none());
    let _: PolicyConfigSet = serde_json::from_value(legacy.clone()).unwrap();
    let mut unknown = legacy;
    unknown["bindings"][0]["metadata"] = serde_json::json!({"auto_vlan": 10});
    assert!(serde_json::from_value::<PolicyConfigSet>(unknown).is_err());
    config.bindings[0].metadata = Some(policy::BindingMetadata {
        group: Some("Work – 内部".into()),
        owner: Some("Pettersen".into()),
        vlan: Some(20),
        tags: vec!["managed".into(), "laptop".into()],
        note: Some("Fixed DHCP reservation".into()),
    });
    config.bindings.push(policy::Binding {
        name: "Loopback network".into(),
        network: "127.0.0.0/8".parse().unwrap(),
        policy: "default".into(),
        metadata: Some(policy::BindingMetadata {
            group: Some("Network group".into()),
            ..Default::default()
        }),
    });
    for path in ["/api/v1/policy/test", "/api/v1/shadow", "/api/v1/config"] {
        let mut invalid = config.clone();
        invalid.bindings[0].metadata.as_mut().unwrap().vlan = Some(4095);
        assert_eq!(
            harness
                .send(path, &invalid, path.ends_with("config"))
                .await
                .status(),
            422
        );
        assert_eq!(harness.state.engine.active.load().generation, 1);
    }
    assert_eq!(
        harness
            .send("/api/v1/shadow", &config, false)
            .await
            .status(),
        200
    );
    let active: Value = harness.get("/api/v1/clients").await.json().await.unwrap();
    assert_eq!(active["generation"], 1);
    assert!(active["bindings"].as_array().unwrap().is_empty());
    assert_eq!(
        harness.dns("ads.test").await.metadata.response_code,
        ResponseCode::NXDomain
    );
    let tag = harness.get("/api/v1/config").await.headers()["etag"]
        .to_str()
        .unwrap()
        .to_owned();
    let promoted = reqwest::Client::new()
        .post(format!("{}/api/v1/shadow/promote", harness.base))
        .bearer_auth(TOKEN)
        .header("If-Match", &tag)
        .send()
        .await
        .unwrap();
    assert_eq!(promoted.status(), 200);
    let original = harness.state.engine.active.load_full();
    let original_generation = original.generation;
    let clients: Value = harness.get("/api/v1/clients").await.json().await.unwrap();
    assert_eq!(clients["default_policy"], "default");
    assert_eq!(clients["bindings"][0]["metadata"]["vlan"], 20);
    let explanation: Value = harness
        .get("/api/v1/explain?client=::ffff:127.0.0.1&domain=ads.test")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(explanation["binding_metadata"]["group"], "Work – 内部");
    let outer: Value = harness
        .get("/api/v1/explain?client=127.0.0.2&domain=ads.test")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(outer["binding_metadata"]["group"], "Network group");
    assert!(!original.permits("127.0.0.2".parse().unwrap()));
    let boot = harness
        .state
        .store
        .call(Operation::Bootstrap {
            config: "ignored".into(),
        })
        .await
        .unwrap();
    let recovered: PolicyConfigSet =
        serde_json::from_str(boot["config"].as_str().unwrap()).unwrap();
    let recovered = PolicySnapshot::compile(recovered, original_generation).unwrap();
    assert_eq!(
        recovered
            .explain("127.0.0.1".parse().unwrap(), "ads.test")
            .unwrap()
            .binding_metadata,
        original
            .explain("127.0.0.1".parse().unwrap(), "ads.test")
            .unwrap()
            .binding_metadata
    );
    config.bindings[0].metadata.as_mut().unwrap().owner = Some("Replacement owner".into());
    let database = rusqlite::Connection::open(&harness.path).unwrap();
    database.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        503
    );
    assert_eq!(
        harness.state.engine.active.load().generation,
        original_generation
    );
    for _ in 0..30 {
        assert_eq!(
            harness.dns("ads.test").await.metadata.response_code,
            ResponseCode::NXDomain
        );
    }
    database.execute_batch("ROLLBACK").unwrap();
    drop(database);
    config.bindings[0].metadata = None;
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        200
    );
    let current_generation = harness.state.engine.active.load().generation;
    assert!(current_generation > original_generation);
    let no_metadata: Value = harness
        .get("/api/v1/explain?client=127.0.0.1&domain=ads.test")
        .await
        .json()
        .await
        .unwrap();
    assert!(no_metadata.get("binding_metadata").is_none());
    assert_eq!(
        original
            .explain("127.0.0.1".parse().unwrap(), "ads.test")
            .unwrap()
            .binding_metadata
            .unwrap()
            .owner
            .as_deref(),
        Some("Pettersen")
    );
    let rollback = reqwest::Client::new()
        .post(format!(
            "{}/api/v1/revisions/{original_generation}/rollback",
            harness.base
        ))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(rollback.status(), 200);
    let restored: Value = harness.get("/api/v1/clients").await.json().await.unwrap();
    assert!(restored["generation"].as_u64().unwrap() > current_generation);
    assert_eq!(restored["bindings"][0]["metadata"]["owner"], "Pettersen");
    assert_eq!(
        harness.dns("ads.test").await.metadata.response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(
        harness
            .state
            .engine
            .resolver
            .metrics
            .upstream_lookups
            .load(Ordering::Relaxed),
        0
    );
    harness.shutdown().await;
}

async fn preview(
    harness: &Harness,
    config: &PolicyConfigSet,
    etag: Option<&str>,
) -> reqwest::Response {
    let mut request = reqwest::Client::new()
        .post(format!("{}/api/v1/filter-sources/preview", harness.base))
        .bearer_auth(TOKEN)
        .json(&serde_json::json!({"config": config, "source": 0}));
    if let Some(etag) = etag {
        request = request.header("If-Match", etag);
    }
    request.send().await.unwrap()
}

async fn local_dns() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        loop {
            let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let query = Message::from_vec(&buffer[..len]).unwrap();
            let answer = dns_core::reply(&query, ResponseCode::NoError)
                .to_vec()
                .unwrap();
            socket.send_to(&answer, peer).await.unwrap();
        }
    });
    (address, task)
}

#[tokio::test]
async fn downloaded_list_preview_durable_shadow_promotion_provenance_and_rollback() {
    let harness = Harness::start().await;
    let fixture = download_fixture::Fixture::start().await;
    let (upstream, mock) = local_dns().await;
    let mut baseline = harness.state.engine.active.load().config.clone();
    baseline.upstreams[0].addresses = vec![upstream];
    baseline.assertions = vec![policy::Assertion {
        client: "127.0.0.1".parse().unwrap(),
        domain: "ads.test".into(),
        expected: Action::Block,
    }];
    assert_eq!(
        harness
            .send("/api/v1/config", &baseline, true)
            .await
            .status(),
        200
    );
    let original = harness.state.engine.active.load().generation;
    let response = harness.get("/api/v1/config").await;
    let etag = response.headers()["etag"].to_str().unwrap().to_owned();
    let mut config = baseline.clone();
    config.filter_sources = vec![fixture.source("/ok")];
    assert_eq!(preview(&harness, &config, None).await.status(), 428);
    assert_eq!(
        preview(&harness, &config, Some("\"stale\"")).await.status(),
        412
    );
    assert_eq!(
        reqwest::Client::new()
            .post(format!("{}/api/v1/filter-sources/preview", harness.base))
            .json(&serde_json::json!({"config":config,"source":0}))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let next = harness.state.next_generation.load(Ordering::Relaxed);
    let database = rusqlite::Connection::open(&harness.path).unwrap();
    database.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let result = preview(&harness, &config, Some(&etag)).await;
    assert_eq!(result.status(), 200);
    assert_eq!(result.headers()["etag"], etag);
    let result: Value = result.json().await.unwrap();
    assert_eq!(result["changed"], true);
    assert_eq!(
        result["report"]["list_stats"][0]["lists"][0]["duplicates"],
        1
    );
    let candidate: PolicyConfigSet = serde_json::from_value(result["config"].clone()).unwrap();
    let stamp = candidate.filter_sources[0].download.as_ref().unwrap();
    assert_eq!(
        stamp.sha256,
        rustwalld_dns::downloads::sha256(candidate.policies[0].lists[0].rules.as_bytes())
    );
    assert_eq!(harness.state.next_generation.load(Ordering::Relaxed), next);
    assert_eq!(harness.state.engine.active.load().generation, original);
    assert_eq!(
        harness.dns("downloaded.test.").await.metadata.response_code,
        ResponseCode::NoError
    );
    assert_eq!(
        harness
            .send("/api/v1/shadow", &candidate, false)
            .await
            .status(),
        503
    );
    database.execute_batch("ROLLBACK").unwrap();
    drop(database);
    assert_eq!(
        harness
            .send("/api/v1/shadow", &candidate, false)
            .await
            .status(),
        200
    );
    assert_eq!(
        harness.dns("downloaded.test.").await.metadata.response_code,
        ResponseCode::NoError
    );
    let promoted = reqwest::Client::new()
        .post(format!("{}/api/v1/shadow/promote", harness.base))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(promoted.status(), 200);
    let generation = harness.state.engine.active.load().generation;
    assert!(generation > original);
    assert_eq!(
        harness.dns("downloaded.test.").await.metadata.response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(
        harness
            .dns("sub.downloaded.test.")
            .await
            .metadata
            .response_code,
        ResponseCode::NoError
    );
    let explanation: Value = harness
        .get("/api/v1/explain?client=127.0.0.1&domain=downloaded.test")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(explanation["rule"]["sources"][0]["list"], "test");
    assert_eq!(explanation["rule"]["sources"][0]["line"], 2);
    let stored: Value = harness
        .get(&format!("/api/v1/revisions/{generation}"))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(stored["config"], result["config"]);
    let active: Value = harness
        .get("/api/v1/filter-sources")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(active["sources"][0]["download"]["sha256"], stamp.sha256);
    assert_eq!(fixture.requests.load(Ordering::SeqCst), 1);
    let mut changed = candidate.clone();
    changed.policies[0].lists[0]
        .rules
        .push_str("tampered.test\n");
    assert_eq!(
        harness
            .send("/api/v1/config", &changed, true)
            .await
            .status(),
        422
    );
    assert_eq!(harness.state.engine.active.load().generation, generation);
    assert_eq!(
        rustwalld_dns::maintenance::verify(&harness.path)
            .unwrap()
            .schema,
        2
    );
    let backup = harness._dir.path().join("download-backup.sqlite");
    rustwalld_dns::maintenance::snapshot(&harness.path, &backup).unwrap();
    let corrupt = rusqlite::Connection::open(&backup).unwrap();
    corrupt
        .execute(
            "UPDATE revisions SET config=?1 WHERE id=?2",
            rusqlite::params![
                serde_json::to_string(&changed).unwrap(),
                i64::try_from(generation).unwrap()
            ],
        )
        .unwrap();
    drop(corrupt);
    assert!(rustwalld_dns::maintenance::verify(&backup).is_err());
    let refused = harness._dir.path().join("refused.sqlite");
    assert!(rustwalld_dns::maintenance::snapshot(&backup, &refused).is_err());
    assert!(!refused.exists());
    assert_eq!(
        reqwest::Client::new()
            .post(format!(
                "{}/api/v1/revisions/{original}/rollback",
                harness.base
            ))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        harness.dns("downloaded.test.").await.metadata.response_code,
        ResponseCode::NoError
    );
    assert!(
        harness
            .state
            .engine
            .active
            .load()
            .config
            .filter_sources
            .is_empty()
    );
    fixture.wait_closed().await;
    mock.abort();
    harness.shutdown().await;
}

#[tokio::test]
async fn downloads_reject_tls_http_body_rules_and_assertion_failures_without_publication() {
    let harness = Harness::start().await;
    let fixture = download_fixture::Fixture::start().await;
    let config = harness.state.engine.active.load().config.clone();
    let etag = harness.get("/api/v1/config").await.headers()["etag"]
        .to_str()
        .unwrap()
        .to_owned();
    for path in [
        "/redirect",
        "/notmodified",
        "/oversize",
        "/streambig",
        "/truncated",
        "/html",
        "/gzip",
        "/utf8",
        "/empty",
        "/manyheaders",
        "/hugeheaders",
        "/trailers",
    ] {
        let source = fixture.source(path);
        assert!(
            rustwalld_dns::downloads::fetch(&source).await.is_err(),
            "{path}"
        );
        fixture.wait_closed().await;
    }
    let (text, stamp) = rustwalld_dns::downloads::fetch(&fixture.source("/chunked"))
        .await
        .unwrap();
    assert_eq!(text, "ads.test\n");
    assert_eq!(stamp.bytes, text.len());
    let mut untrusted = fixture.source("/ok");
    untrusted.ca_pem = None;
    assert!(rustwalld_dns::downloads::fetch(&untrusted).await.is_err());
    let mut wrong = fixture.source("/ok");
    wrong.url = wrong.url.replace("lists.test", "wrong.test");
    assert!(rustwalld_dns::downloads::fetch(&wrong).await.is_err());
    let expired = download_fixture::Fixture::with_expiry(true).await;
    assert!(
        rustwalld_dns::downloads::fetch(&expired.source("/ok"))
            .await
            .is_err()
    );
    assert_eq!(expired.requests.load(Ordering::SeqCst), 0);
    expired.wait_closed().await;
    for path in ["/comments", "/invalid", "/assertfail"] {
        let mut draft = config.clone();
        draft.filter_sources = vec![fixture.source(path)];
        draft.assertions = if path == "/comments" {
            vec![]
        } else {
            vec![policy::Assertion {
                client: "127.0.0.1".parse().unwrap(),
                domain: "ads.test".into(),
                expected: Action::Block,
            }]
        };
        let result = preview(&harness, &draft, Some(&etag)).await;
        assert_eq!(result.status(), 422, "{path}");
        if path == "/assertfail" {
            let body: Value = result.json().await.unwrap();
            assert_eq!(body["report"]["failed"], 1);
        }
        assert_eq!(
            harness.dns("ads.test.").await.metadata.response_code,
            ResponseCode::NXDomain
        );
    }
    let mut fallback = fixture.source("/ok");
    fallback
        .bootstrap_ips
        .insert(0, "127.0.0.2".parse().unwrap());
    assert!(rustwalld_dns::downloads::fetch(&fallback).await.is_ok());
    assert_eq!(harness.state.engine.active.load().generation, 1);
    assert_eq!(harness.state.next_generation.load(Ordering::Relaxed), 2);
    fixture.wait_closed().await;
    harness.shutdown().await;
}

#[tokio::test]
async fn stalled_bounded_downloads_allow_dns_and_mutations_cancel_close_and_reject_stale_preview() {
    let harness = Harness::start().await;
    let fixture = download_fixture::Fixture::start().await;
    let original = harness.state.engine.active.load().config.clone();
    let etag = harness.get("/api/v1/config").await.headers()["etag"]
        .to_str()
        .unwrap()
        .to_owned();
    let mut config = original.clone();
    config.filter_sources = vec![fixture.source("/slow")];
    let request = reqwest::Client::new()
        .post(format!("{}/api/v1/filter-sources/preview", harness.base))
        .bearer_auth(TOKEN)
        .header("If-Match", &etag)
        .json(&serde_json::json!({"config":config,"source":0}));
    let fetching = tokio::spawn(async move { request.send().await.unwrap() });
    fixture.wait_requests(1).await;
    assert_eq!(preview(&harness, &config, Some(&etag)).await.status(), 409);
    for _ in 0..100 {
        assert_eq!(
            harness.dns("ads.test.").await.metadata.response_code,
            ResponseCode::NXDomain
        );
    }
    assert_eq!(
        harness
            .send("/api/v1/config", &original, true)
            .await
            .status(),
        200
    );
    assert_eq!(fetching.await.unwrap().status(), 412);
    fixture.wait_closed().await;
    let source = fixture.source("/stall");
    let cancelled = tokio::spawn(async move { rustwalld_dns::downloads::fetch(&source).await });
    fixture.wait_requests(2).await;
    cancelled.abort();
    let _ = cancelled.await;
    fixture.wait_closed().await;
    let etag = harness.get("/api/v1/config").await.headers()["etag"]
        .to_str()
        .unwrap()
        .to_owned();
    config.filter_sources = vec![fixture.source("/stall")];
    let request = reqwest::Client::new()
        .post(format!("{}/api/v1/filter-sources/preview", harness.base))
        .bearer_auth(TOKEN)
        .header("If-Match", &etag)
        .json(&serde_json::json!({"config":config,"source":0}));
    let stalled = tokio::spawn(async move { request.send().await.unwrap() });
    fixture.wait_requests(3).await;
    for _ in 0..100 {
        assert_eq!(
            harness.dns("ads.test.").await.metadata.response_code,
            ResponseCode::NXDomain
        );
    }
    assert_eq!(preview(&harness, &config, Some(&etag)).await.status(), 409);
    assert_eq!(stalled.await.unwrap().status(), 502);
    assert_eq!(harness.state.downloads.available_permits(), 1);
    assert_eq!(harness.state.engine.active.load().generation, 2);
    fixture.wait_closed().await;
    harness.shutdown().await;
}

#[tokio::test]
async fn temporary_exception_api_shadow_history_sqlite_failure_and_expired_rollback() {
    let harness = Harness::start().await;
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let mock = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        loop {
            let (len, peer) = upstream.recv_from(&mut buffer).await.unwrap();
            let request = Message::from_vec(&buffer[..len]).unwrap();
            let mut response = dns_core::reply(&request, ResponseCode::NoError);
            response.add_answer(hickory_proto::rr::Record::from_rdata(
                request.queries[0].name().clone(),
                60,
                hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(
                    "192.0.2.1".parse().unwrap(),
                )),
            ));
            upstream
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    assert_eq!(
        reqwest::get(format!("{}/api/v1/temporary-exceptions", harness.base))
            .await
            .unwrap()
            .status(),
        401
    );
    let expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3;
    let mut config = harness.state.engine.active.load().config.clone();
    config.upstreams[0].addresses = vec![upstream_addr];
    config.policies[0]
        .temporary_exceptions
        .push(policy::TemporaryException {
            name: "repair".into(),
            domain: "ADS.TEST.".into(),
            expires_at: expiry,
        });
    config.assertions.push(policy::Assertion {
        client: "127.0.0.1".parse().unwrap(),
        domain: "ads.test".into(),
        expected: Action::Block,
    });
    assert_eq!(
        harness
            .send("/api/v1/policy/test", &config, false)
            .await
            .status(),
        200
    );
    assert_eq!(
        harness
            .send("/api/v1/shadow", &config, false)
            .await
            .status(),
        200
    );
    assert_eq!(
        harness.dns("ads.test.").await.metadata.response_code,
        ResponseCode::NXDomain
    );
    let promoted = reqwest::Client::new()
        .post(format!("{}/api/v1/shadow/promote", harness.base))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(promoted.status(), 200);
    let generation = harness.state.engine.active.load().generation;
    let response = harness.dns("ads.test.").await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(response.answers[0].ttl <= 3);
    let explanation: Value = harness
        .get("/api/v1/explain?client=127.0.0.1&domain=ads.test")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(explanation["temporary_exception"]["name"], "repair");
    let live: Value = harness
        .get("/api/v1/temporary-exceptions")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(live["exceptions"][0]["active"], true);
    timeout(Duration::from_secs(2), async {
        loop {
            let history: Value = harness.get("/api/v1/queries").await.json().await.unwrap();
            if history
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["temporary_exception"] == 0)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let database = rusqlite::Connection::open(&harness.path).unwrap();
    database.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let mut revoked = config.clone();
    revoked.policies[0].temporary_exceptions.clear();
    assert_eq!(
        harness
            .send("/api/v1/config", &revoked, true)
            .await
            .status(),
        503
    );
    let remaining = (std::time::UNIX_EPOCH + Duration::from_secs(expiry))
        .duration_since(std::time::SystemTime::now())
        .unwrap_or_default();
    tokio::time::sleep(remaining + Duration::from_millis(20)).await;
    for _ in 0..100 {
        assert_eq!(
            harness.dns("ads.test.").await.metadata.response_code,
            ResponseCode::NXDomain
        );
    }
    let expired: Value = harness
        .get("/api/v1/temporary-exceptions")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(expired["generation"], generation);
    assert_eq!(expired["exceptions"][0]["active"], false);
    database.execute_batch("ROLLBACK").unwrap();
    drop(database);
    let rolled = reqwest::Client::new()
        .post(format!(
            "{}/api/v1/revisions/{generation}/rollback",
            harness.base
        ))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(rolled.status(), 200);
    assert!(harness.state.engine.active.load().generation > generation);
    assert_eq!(
        harness.state.engine.active.load().config.policies[0].temporary_exceptions[0].expires_at,
        expiry
    );
    assert_eq!(
        harness.dns("ads.test.").await.metadata.response_code,
        ResponseCode::NXDomain
    );
    let report = rustwalld_dns::maintenance::verify(&harness.path).unwrap();
    assert_eq!(report.schema, 2);
    mock.abort();
    harness.shutdown().await;
}

#[tokio::test]
async fn policy_test_reports_every_case_without_publishing_or_touching_revisions() {
    let harness = Harness::start().await;
    let mut config = harness.state.engine.active.load().config.clone();
    config.upstreams[0].addresses = vec!["127.0.0.1:9".parse().unwrap()];
    config.assertions = vec![
        policy::Assertion {
            client: "127.0.0.1".parse().unwrap(),
            domain: "ads.test".into(),
            expected: Action::Allow,
        },
        policy::Assertion {
            client: "127.0.0.1".parse().unwrap(),
            domain: "allowed.test".into(),
            expected: Action::Block,
        },
        policy::Assertion {
            client: "127.0.0.1".parse().unwrap(),
            domain: "bad..domain".into(),
            expected: Action::Allow,
        },
        policy::Assertion {
            client: "192.0.2.1".parse().unwrap(),
            domain: "allowed.test".into(),
            expected: Action::Allow,
        },
        policy::Assertion {
            client: "127.0.0.1".parse().unwrap(),
            domain: "x.ads.test".into(),
            expected: Action::Block,
        },
    ];
    let next = harness.state.next_generation.load(Ordering::Relaxed);
    let response = harness.send("/api/v1/policy/test", &config, false).await;
    assert_eq!(response.status(), 422);
    let body: Value = response.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("4 of 5"));
    let report = &body["report"];
    assert_eq!(report["valid"], false);
    assert_eq!(report["results"].as_array().unwrap().len(), 5);
    assert_eq!(
        report["results"][0]["trace"]["rule"]["sources"][0]["list"],
        "test"
    );
    assert_eq!(
        report["results"][1]["failure"]["kind"],
        "unexpected_decision"
    );
    assert_eq!(report["results"][2]["failure"]["kind"], "invalid_domain");
    assert_eq!(
        report["results"][3]["failure"]["kind"],
        "client_not_permitted"
    );
    assert_eq!(report["results"][4]["failure"], Value::Null);
    assert_eq!(harness.state.next_generation.load(Ordering::Relaxed), next);
    for (path, put) in [("/api/v1/config", true), ("/api/v1/shadow", false)] {
        assert_eq!(harness.send(path, &config, put).await.status(), 422);
        assert_eq!(harness.state.engine.active.load().generation, 1);
        assert!(harness.state.engine.shadow.load().is_none());
    }
    let revisions: Value = harness.get("/api/v1/revisions").await.json().await.unwrap();
    assert_eq!(revisions.as_array().unwrap().len(), 1);
    assert_eq!(
        harness.dns("ads.test.").await.metadata.response_code,
        ResponseCode::NXDomain
    );
    config.assertions = vec![config.assertions[4].clone()];
    // The read-only test endpoint must work even while SQLite cannot accept writes.
    let database = rusqlite::Connection::open(&harness.path).unwrap();
    database.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let response = harness.send("/api/v1/policy/test", &config, false).await;
    assert_eq!(response.status(), 200);
    let report: Value = response.json().await.unwrap();
    assert_eq!(report["valid"], true);
    assert_eq!(report["assertions"], 1);
    assert_eq!(report["policies"], 1);
    assert_eq!(report["failed"], 0);
    assert_eq!(report["results"][0]["trace"]["domain"], "x.ads.test");
    database.execute_batch("ROLLBACK").unwrap();
    drop(database);
    harness.shutdown().await;
}
struct Harness {
    base: String,
    state: Arc<AppState>,
    path: std::path::PathBuf,
    _dir: tempfile::TempDir,
    stop: CancellationToken,
    db_stop: CancellationToken,
    dns_task: tokio::task::JoinHandle<std::io::Result<()>>,
    api_task: tokio::task::JoinHandle<std::io::Result<()>>,
    done: tokio::sync::oneshot::Receiver<()>,
    refresh_task: tokio::task::JoinHandle<()>,
}
impl Harness {
    async fn start() -> Self {
        let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let path = dir.path().join("dns.sqlite");
        let (telemetry, events) = Telemetry::channel(32);
        let db_stop = CancellationToken::new();
        let (store, done) = Store::start(path.clone(), 10, events, db_stop.clone())
            .await
            .unwrap();
        let mut config = PolicyConfigSet::default();
        config.policies[0].lists = vec![ListInput {
            name: "test".into(),
            action: Action::Block,
            rules: "ads.test".into(),
        }];
        let initial = serde_json::to_string(&config).unwrap();
        store
            .call(Operation::Bootstrap { config: initial })
            .await
            .unwrap();
        let engine = Arc::new(Engine::new(
            PolicySnapshot::compile(config, 1).unwrap(),
            100,
            100,
            32,
            telemetry,
        ));
        let server = Server::bind(
            ServerConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                ..Default::default()
            },
            engine.clone(),
        )
        .await
        .unwrap();
        let listen = server.local_addr().unwrap();
        let stop = CancellationToken::new();
        let dns_task = tokio::spawn(server.run(stop.clone()));
        let state = Arc::new(AppState {
            engine,
            store,
            listen,
            next_generation: AtomicU64::new(2),
            mutation: Arc::new(Semaphore::new(1)),
            api_slots: Arc::new(Semaphore::new(32)),
            downloads: Arc::new(Semaphore::new(1)),
            refreshes: Arc::new(rustwalld_dns::refreshes::Refresher::default()),
            token: TOKEN.into(),
        });
        let refresh_task = tokio::spawn(rustwalld_dns::refreshes::run(state.clone(), stop.clone()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let router = api::router(state.clone());
        let cancel = stop.clone();
        let api_task = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(cancel.cancelled_owned())
                .await
        });
        Self {
            base,
            state,
            path,
            _dir: dir,
            stop,
            db_stop,
            dns_task,
            api_task,
            done,
            refresh_task,
        }
    }
    async fn get(&self, path: &str) -> reqwest::Response {
        reqwest::Client::new()
            .get(format!("{}{path}", self.base))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap()
    }
    async fn send(&self, path: &str, config: &PolicyConfigSet, put: bool) -> reqwest::Response {
        let client = reqwest::Client::new();
        let url = format!("{}{path}", self.base);
        let request = if put {
            client.put(url)
        } else {
            client.post(url)
        };
        request
            .bearer_auth(TOKEN)
            .json(config)
            .send()
            .await
            .unwrap()
    }
    async fn dns(&self, domain: &str) -> Message {
        let mut request = Message::query();
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(
            Name::from_ascii(domain).unwrap(),
            RecordType::A,
        ));
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket
            .send_to(&request.to_vec().unwrap(), self.state.listen)
            .await
            .unwrap();
        let mut bytes = [0; 1232];
        let len = timeout(Duration::from_secs(1), socket.recv(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        Message::from_vec(&bytes[..len]).unwrap()
    }
    async fn shutdown(self) {
        self.stop.cancel();
        self.refresh_task.await.unwrap();
        self.dns_task.await.unwrap().unwrap();
        self.api_task.await.unwrap().unwrap();
        self.db_stop.cancel();
        timeout(Duration::from_secs(2), self.done)
            .await
            .unwrap()
            .unwrap();
    }
}
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
    let mut config = harness.state.engine.active.load().config.clone();
    config.assertions.push(policy::Assertion {
        client: "127.0.0.1".parse().unwrap(),
        domain: "ads.test".into(),
        expected: Action::Allow,
    });
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        422
    );
    assert_eq!(harness.state.engine.active.load().generation, 1);
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
    harness.shutdown().await;
}
#[tokio::test]
async fn shadow_promote_rollback_and_durable_generation() {
    let harness = Harness::start().await;
    let mut config = harness.state.engine.active.load().config.clone();
    config.policies[0].lists.clear();
    assert!(
        harness
            .send("/api/v1/shadow", &config, false)
            .await
            .status()
            .is_success()
    );
    assert_eq!(
        harness.dns("ads.test.").await.metadata.response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(
        harness
            .state
            .engine
            .shadow
            .load()
            .as_ref()
            .unwrap()
            .generation,
        2
    );
    let response = reqwest::Client::new()
        .post(format!("{}/api/v1/shadow/promote", harness.base))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    assert_eq!(harness.state.engine.active.load().generation, 3);
    assert!(harness.state.engine.shadow.load().is_none());
    let response = reqwest::Client::new()
        .post(format!("{}/api/v1/revisions/1/rollback", harness.base))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    assert_eq!(harness.state.engine.active.load().generation, 4);
    assert_eq!(
        harness.dns("ads.test.").await.metadata.response_code,
        ResponseCode::NXDomain
    );
    let boot = harness
        .state
        .store
        .call(Operation::Bootstrap {
            config: "ignored".into(),
        })
        .await
        .unwrap();
    assert_eq!(boot["active"], 4);
    assert_eq!(boot["next"], 5);
    let stored: PolicyConfigSet = serde_json::from_str(boot["config"].as_str().unwrap()).unwrap();
    assert_eq!(stored.policies[0].lists.len(), 1);
    harness.shutdown().await;
}
#[tokio::test]
async fn sqlite_lock_rejects_promotion_but_dns_keeps_answering() {
    let harness = Harness::start().await;
    let connection = rusqlite::Connection::open(&harness.path).unwrap();
    connection.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut config = harness.state.engine.active.load().config.clone();
    config.policies[0].lists[0].rules = "new.test".into();
    let requests = {
        let base = harness.base.clone();
        tokio::spawn(async move {
            reqwest::Client::new()
                .put(format!("{base}/api/v1/config"))
                .bearer_auth(TOKEN)
                .json(&config)
                .send()
                .await
                .unwrap()
        })
    };
    for _ in 0..20 {
        assert_eq!(
            harness.dns("ads.test.").await.metadata.response_code,
            ResponseCode::NXDomain
        );
    }
    assert_eq!(requests.await.unwrap().status(), 503);
    assert_eq!(harness.state.engine.active.load().generation, 1);
    connection.execute_batch("ROLLBACK").unwrap();
    assert_eq!(
        harness.dns("ads.test.").await.metadata.response_code,
        ResponseCode::NXDomain
    );
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
            .store
            .metrics
            .persisted_events
            .load(Ordering::Relaxed)
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
async fn stale_edit_shadow_promotion_clear_and_rollback_cannot_publish() {
    let harness = Harness::start().await;
    let client = reqwest::Client::new();
    let response = harness.get("/api/v1/config").await;
    let initial_tag = response.headers()["etag"].to_str().unwrap().to_owned();
    assert_eq!(response.headers()["cache-control"], "no-store");
    let mut config: PolicyConfigSet = response.json().await.unwrap();
    config.policies[0].lists[0].rules.push_str("\nnew.test");
    let response = client
        .post(format!("{}/api/v1/shadow", harness.base))
        .bearer_auth(TOKEN)
        .header("if-match", &initial_tag)
        .json(&config)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let shadow_tag = response.headers()["etag"].to_str().unwrap().to_owned();
    assert_ne!(shadow_tag, initial_tag);
    let candidate = harness.get("/api/v1/shadow").await;
    assert_eq!(candidate.headers()["etag"], shadow_tag);
    let body: Value = candidate.json().await.unwrap();
    assert_eq!(body["generation"], 2);
    assert_eq!(
        body["config"]["policies"][0]["lists"][0]["rules"],
        "ads.test\nnew.test"
    );
    for (method, path) in [
        (reqwest::Method::PUT, "/api/v1/config"),
        (reqwest::Method::POST, "/api/v1/shadow"),
        (reqwest::Method::POST, "/api/v1/shadow/promote"),
        (reqwest::Method::DELETE, "/api/v1/shadow"),
        (reqwest::Method::POST, "/api/v1/revisions/1/rollback"),
    ] {
        let response = client
            .request(method, format!("{}{path}", harness.base))
            .bearer_auth(TOKEN)
            .header("if-match", &initial_tag)
            .json(&config)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 412, "{path}");
        assert_eq!(harness.state.engine.active.load().generation, 1);
        assert_eq!(
            harness
                .state
                .engine
                .shadow
                .load()
                .as_ref()
                .unwrap()
                .generation,
            2
        );
        assert_eq!(harness.state.next_generation.load(Ordering::Relaxed), 3);
    }
    let response = client
        .post(format!("{}/api/v1/shadow/promote", harness.base))
        .bearer_auth(TOKEN)
        .header("if-match", shadow_tag)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["etag"], "\"g3-s0\"");
    assert_eq!(harness.state.engine.active.load().generation, 3);
    assert!(harness.state.engine.shadow.load().is_none());
    assert_eq!(
        harness.dns("new.test").await.metadata.response_code,
        ResponseCode::NXDomain
    );
    harness.shutdown().await;
}

#[tokio::test]
async fn static_console_is_optional_hardened_and_keeps_api_misses_as_errors() {
    let harness = Harness::start().await;
    let root = harness._dir.path().join("web");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(
        root.join("index.html"),
        "<!doctype html><title>Local console</title>",
    )
    .unwrap();
    std::fs::write(root.join("app.js"), "console.log('local')").unwrap();
    std::fs::write(harness._dir.path().join("private.txt"), "private").unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let stop = CancellationToken::new();
    let cancel = stop.clone();
    let router = api::router_with_ui(harness.state.clone(), Some(root));
    let task = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(cancel.cancelled_owned())
            .await
    });
    let client = reqwest::Client::new();
    let response = client.get(&base).send().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    assert_eq!(response.headers()["referrer-policy"], "no-referrer");
    assert!(
        response.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
    assert!(response.text().await.unwrap().contains("Local console"));
    for path in [
        "/missing.js",
        "/api/v1/unknown",
        "/%2e%2e/private.txt",
        "/%2e%2e%2fprivate.txt",
    ] {
        let response = client
            .get(format!("{base}{path}"))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 404, "{path}");
        assert!(!response.text().await.unwrap().contains("Local console"));
    }
    assert_eq!(
        client
            .get(format!("{base}/api/v1/unknown"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        client
            .get(format!("{base}/app.js"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    stop.cancel();
    task.await.unwrap().unwrap();
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
    let mut config = harness.state.engine.active.load().config.clone();
    config.upstreams[0].addresses = vec![address];
    config.upstreams[0].timeout_ms = 200;
    assert!(
        harness
            .send("/api/v1/config", &config, true)
            .await
            .status()
            .is_success()
    );
    let old = harness.state.engine.active.load_full();
    assert_eq!(
        harness.dns("ads.test.").await.metadata.response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(
        old.upstreams[0].health[0].attempts.load(Ordering::SeqCst),
        0
    );
    assert_eq!(harness.dns("cached.test.").await.answers.len(), 1);
    assert_eq!(harness.dns("cached.test.").await.answers.len(), 1);
    assert_eq!(
        old.upstreams[0].health[0].attempts.load(Ordering::SeqCst),
        1
    );
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
    assert_eq!(health[0]["generation"], old.generation);
    let server = &health[0]["servers"][0];
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
    let engine = harness.state.engine.clone();
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
                false,
            )
            .await
            .unwrap()
    });
    timeout(Duration::from_secs(1), pinned_seen.notified())
        .await
        .unwrap();
    assert_eq!(
        old.upstreams[0].health[0].inflight.load(Ordering::SeqCst),
        1
    );
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
    assert_eq!(
        old.upstreams[0].health[0].successes.load(Ordering::SeqCst),
        3
    );
    assert_eq!(
        old.upstreams[0].health[0].inflight.load(Ordering::SeqCst),
        0
    );
    let fresh: Value = harness.get("/api/v1/upstreams").await.json().await.unwrap();
    assert!(fresh[0]["generation"].as_u64().unwrap() > old.generation);
    assert_eq!(fresh[0]["servers"][0]["attempts"], 0);
    assert_eq!(harness.dns("cached.test.").await.answers.len(), 1);
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
