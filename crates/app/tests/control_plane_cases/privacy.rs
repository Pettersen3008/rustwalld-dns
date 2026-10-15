use super::*;
async fn privacy(harness: &Harness) -> (Value, String) {
    let response = harness.get("/api/v1/privacy").await;
    let tag = response.headers()["etag"].to_str().unwrap().to_owned();
    (response.json().await.unwrap(), tag)
}
async fn change(
    harness: &Harness,
    tag: &str,
    mode: &str,
    rows: usize,
    clear: bool,
) -> reqwest::Response {
    reqwest::Client::new()
        .put(format!("{}/api/v1/privacy", harness.base))
        .bearer_auth(TOKEN)
        .header("If-Match", tag)
        .json(&serde_json::json!({"mode":mode,"retention_rows":rows,"clear_history":clear}))
        .send()
        .await
        .unwrap()
}
#[tokio::test]
async fn privacy_is_durable_revision_checked_masks_identity_and_is_failure_isolated() {
    let harness = Harness::start().await;
    let (initial, tag) = privacy(&harness).await;
    assert_eq!(initial["mode"], "full");
    let dns_tag = current_etag(&harness).await;
    assert_eq!(
        reqwest::Client::new()
            .put(format!("{}/api/v1/privacy", harness.base))
            .bearer_auth(TOKEN)
            .json(&serde_json::json!({"mode":"disabled","retention_rows":10,"clear_history":false}))
            .send()
            .await
            .unwrap()
            .status(),
        428
    );
    assert_eq!(
        change(&harness, &tag, "no_client_identity", 10, true)
            .await
            .status(),
        200
    );
    assert_eq!(
        change(&harness, &tag, "full", 10, false).await.status(),
        412
    );
    assert_eq!(
        harness.dns("ads.test").await.response_code,
        ResponseCode::NXDomain
    );
    let events = timeout(Duration::from_secs(2), async {
        loop {
            let rows: Vec<Value> = harness
                .get("/api/v1/queries?limit=10")
                .await
                .json()
                .await
                .unwrap();
            if !rows.is_empty() {
                break rows;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(events[0]["client"], "anonymous");
    assert_eq!(events[0]["client_masked"], true);
    assert_eq!(current_etag(&harness).await, dns_tag);
    let id = events[0]["id"].as_u64().unwrap();
    let trace: Value = harness
        .get(&format!("/api/v1/queries/{id}/explain"))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(trace["rule"]["domain"], "ads.test");
    let (_, tag) = privacy(&harness).await;
    let database = rusqlite::Connection::open(&harness.path).unwrap();
    database.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert_eq!(
        change(&harness, &tag, "disabled", 10, false).await.status(),
        503
    );
    assert!(harness.state.control.engine().telemetry().logging_enabled());
    assert_eq!(
        harness.dns("ads.test").await.response_code,
        ResponseCode::NXDomain
    );
    database.execute_batch("ROLLBACK").unwrap();
    assert_eq!(
        change(&harness, &tag, "disabled", 10, true).await.status(),
        200
    );
    assert!(!harness.state.control.engine().telemetry().logging_enabled());
    let before = harness
        .state
        .control
        .engine()
        .telemetry()
        .metrics
        .snapshot()
        .requests;
    for _ in 0..20 {
        assert_eq!(
            harness.dns("ads.test").await.response_code,
            ResponseCode::NXDomain
        );
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let events: Vec<Value> = harness
        .get("/api/v1/queries?limit=10")
        .await
        .json()
        .await
        .unwrap();
    assert!(events.is_empty());
    assert!(
        harness
            .state
            .control
            .engine()
            .telemetry()
            .metrics
            .snapshot()
            .requests
            >= before + 20
    );
    let (disabled, tag) = privacy(&harness).await;
    assert_eq!(disabled["retained_rows"], 0);
    assert_eq!(
        change(&harness, &tag, "full", 1000001, false)
            .await
            .status(),
        422
    );
    assert!(!harness.state.control.engine().telemetry().logging_enabled());
    let backup = harness._dir.path().join("privacy-backup.sqlite");
    rustwalld_dns::maintenance::snapshot(&harness.path, &backup).unwrap();
    let (_telemetry, events) = Telemetry::channel(1);
    let cancel = CancellationToken::new();
    let (restored, done) = Store::start(backup, 100, events, cancel.clone())
        .await
        .unwrap();
    assert_eq!(
        restored.privacy().await.unwrap().mode,
        rustwalld_dns_runtime::store::HistoryMode::Disabled
    );
    cancel.cancel();
    done.await.unwrap();
    assert_eq!(change(&harness, &tag, "full", 1, false).await.status(), 200);
    for _ in 0..5 {
        harness.dns("ads.test").await;
    }
    timeout(Duration::from_secs(2), async {
        loop {
            if privacy(&harness).await.0["retained_rows"] == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let events: Vec<Value> = harness
        .get("/api/v1/queries?limit=10")
        .await
        .json()
        .await
        .unwrap();
    assert!(events[0]["id"].as_u64().unwrap() > id);
    assert_eq!(
        harness
            .get(&format!("/api/v1/queries/{id}/explain"))
            .await
            .status(),
        404
    );
    harness.shutdown().await;
}
