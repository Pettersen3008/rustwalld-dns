#![allow(clippy::unwrap_used)]
use super::*;

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
    fixture.conditional.lock().unwrap().text = format!(
        "ads.test\n#{}",
        "x".repeat(rustwalld_dns_policy::MAX_DOWNLOAD_BYTES)
    );
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

#[tokio::test]
async fn conditional_schedules_preserve_revisions_and_bind_validators_to_live_content() {
    let harness = Harness::start().await;
    let fixture = download_fixture::Fixture::start().await;
    let (upstream, mock) = local_dns().await;
    let mut config = harness.state.control.engine().active().config().clone();
    config.upstreams[0].addresses = vec![upstream];
    let mut source = fixture.source("/conditional");
    source.refresh_interval_secs = Some(300);
    config.filter_sources = vec![source];
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        200
    );
    refresh_state(&harness, "unchanged").await;
    let next = harness.state.control.next_generation();
    let original = harness
        .get("/api/v1/config")
        .await
        .json::<Value>()
        .await
        .unwrap();
    let state = checked(&harness, &fixture, "unchanged", 304).await;
    assert_eq!(state["entries"][0]["last_download_bytes"], 0);
    assert_eq!(harness.state.control.next_generation(), next);
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
    let mut config = harness.state.control.engine().active().config().clone();
    config.policies[0]
        .rewrites
        .push(rustwalld_dns_policy::Rewrite {
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
    let next = harness.state.control.next_generation();
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
    assert_eq!(harness.state.control.next_generation(), next);
    assert!(harness.state.control.engine().shadow().is_none());
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
    let state = Arc::new(
        (*harness.state.control)
            .clone()
            .with_refresher(Arc::new(rustwalld_dns::refreshes::Refresher::default())),
    );
    state.queue_refresh(0, state.version()).unwrap();
    let worker = tokio::spawn(rustwalld_dns::refreshes::run(
        state.clone(),
        worker_stop.clone(),
    ));
    timeout(Duration::from_secs(3), async {
        loop {
            if serde_json::to_value(state.refresh_status().unwrap())
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
    let mut config = harness.state.control.engine().active().config().clone();
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
    assert_eq!(harness.state.control.engine().active().generation(), 3);
    assert!(harness.state.control.engine().shadow().is_none());
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
    let mut config = harness.state.control.engine().active().config().clone();
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
    assert_eq!(harness.state.control.engine().active().generation(), 2);
    assert_eq!(
        harness
            .state
            .control
            .engine()
            .shadow()
            .as_ref()
            .unwrap()
            .generation(),
        3
    );
    assert_eq!(
        harness.dns("downloaded.test").await.metadata.response_code,
        ResponseCode::NoError
    );
    let boot = harness
        .state
        .control
        .store()
        .bootstrap("ignored".into())
        .await
        .unwrap();
    assert_eq!(boot.active, 2);
    assert_eq!(boot.shadow, Some(3));
    let revisions: Value = harness.get("/api/v1/revisions").await.json().await.unwrap();
    assert_eq!(revisions[0]["actor"], "scheduled-refresh");
    let saved = harness.state.control.store().revision(3).await.unwrap();
    let restored: PolicyConfigSet = serde_json::from_value(saved.unwrap().config).unwrap();
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
    let next = harness.state.control.next_generation();
    assert_eq!(queue_check(&harness, Some(&tag)).await.status(), 202);
    let status = refresh_state(&harness, "unchanged").await;
    assert_eq!(status["entries"][0]["checked_generation"], 4);
    assert_eq!(harness.state.control.next_generation(), next);
    assert!(harness.state.control.engine().shadow().is_none());
    assert_eq!(
        fixture.requests.load(std::sync::atomic::Ordering::SeqCst),
        2
    );
    let mut disabled = harness.state.control.engine().active().config().clone();
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
    let mut config = harness.state.control.engine().active().config().clone();
    config.assertions = vec![rustwalld_dns_policy::Assertion {
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
        let generation = harness.state.control.engine().active().generation();
        let status = refresh_state(&harness, "failed").await;
        assert!(
            status["entries"][0]["error"]
                .as_str()
                .unwrap()
                .contains(expected),
            "{status}"
        );
        assert!(status["entries"][0]["error"].as_str().unwrap().len() <= 1024);
        assert!(harness.state.control.engine().shadow().is_none());
        assert_eq!(
            harness.state.control.engine().active().generation(),
            generation
        );
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
    assert!(state.control.engine().shadow().is_none());
    assert!(!state.control.is_downloading());
}

#[tokio::test]
async fn a_generation_or_operator_shadow_during_fetch_cannot_be_overwritten() {
    let harness = Harness::start().await;
    let fixture = download_fixture::Fixture::start().await;
    let mut config = harness.state.control.engine().active().config().clone();
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
    assert_eq!(harness.state.control.engine().active().generation(), 3);
    assert!(harness.state.control.engine().shadow().is_none());
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
    let shadow = harness.state.control.engine().shadow_snapshot().unwrap();
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
            .control
            .engine()
            .shadow()
            .as_ref()
            .unwrap()
            .generation(),
        shadow.generation()
    );
    assert!(
        shadow.config().policies[0].lists[0]
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
    let mut config = harness.state.control.engine().active().config().clone();
    let mut source = fixture.source("/ok");
    source.refresh_interval_secs = Some(300);
    source.download = Some(rustwalld_dns_policy::DownloadStamp {
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
    assert_eq!(harness.state.control.engine().active().generation(), 2);
    assert!(harness.state.control.engine().shadow().is_none());
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
    assert_eq!(harness.state.control.engine().active().generation(), 2);
    harness.shutdown().await;
}

#[tokio::test]
async fn downloaded_list_preview_durable_shadow_promotion_provenance_and_rollback() {
    let harness = Harness::start().await;
    let fixture = download_fixture::Fixture::start().await;
    let (upstream, mock) = local_dns().await;
    let mut baseline = harness.state.control.engine().active().config().clone();
    baseline.upstreams[0].addresses = vec![upstream];
    baseline.assertions = vec![rustwalld_dns_policy::Assertion {
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
    let original = harness.state.control.engine().active().generation();
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
    let next = harness.state.control.next_generation();
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
    assert_eq!(harness.state.control.next_generation(), next);
    assert_eq!(
        harness.state.control.engine().active().generation(),
        original
    );
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
        .header("If-Match", current_etag(&harness).await)
        .send()
        .await
        .unwrap();
    assert_eq!(promoted.status(), 200);
    let generation = harness.state.control.engine().active().generation();
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
    assert_eq!(
        harness.state.control.engine().active().generation(),
        generation
    );
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
            .header("If-Match", current_etag(&harness).await)
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
            .control
            .engine()
            .active()
            .config()
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
    let config = harness.state.control.engine().active().config().clone();
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
            vec![rustwalld_dns_policy::Assertion {
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
    assert_eq!(harness.state.control.engine().active().generation(), 1);
    assert_eq!(harness.state.control.next_generation(), 2);
    fixture.wait_closed().await;
    harness.shutdown().await;
}

#[tokio::test]
async fn stalled_bounded_downloads_allow_dns_and_mutations_cancel_close_and_reject_stale_preview() {
    let harness = Harness::start().await;
    let fixture = download_fixture::Fixture::start().await;
    let original = harness.state.control.engine().active().config().clone();
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
    assert!(!harness.state.control.is_downloading());
    assert_eq!(harness.state.control.engine().active().generation(), 2);
    fixture.wait_closed().await;
    harness.shutdown().await;
}
