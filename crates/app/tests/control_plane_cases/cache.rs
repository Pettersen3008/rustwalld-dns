#![allow(clippy::unwrap_used)]
use super::*;

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
        "/overview",
        "/queries",
        "/policies",
        "/clients",
        "/filters",
        "/upstreams",
        "/history",
    ] {
        let response = client.get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(response.status(), 200, "{path}");
        assert!(response.text().await.unwrap().contains("Local console"));
    }
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
