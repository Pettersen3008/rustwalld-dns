#![allow(clippy::unwrap_used)]
use super::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

/// Raw HTTP/1.1 exchange, so the Host header is exactly what the test sends.
async fn raw(harness: &Harness, request: &str) -> String {
    let address = harness.base.trim_start_matches("http://");
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    String::from_utf8_lossy(&response).into_owned()
}

#[tokio::test]
async fn foreign_host_headers_are_rejected_on_every_route() {
    let harness = Harness::start().await;
    for path in ["/healthz", "/metrics", "/api/v1/status", "/api/v1/config"] {
        let response = raw(
            &harness,
            &format!("GET {path} HTTP/1.1\r\nHost: rebind.example\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 421"), "{path}: {response}");
        assert!(response.contains("\"error\""), "{path}: {response}");
    }
    for host in [
        "localhost",
        "localhost:8080",
        "127.0.0.1:8080",
        "[::1]:8080",
    ] {
        let response = raw(
            &harness,
            &format!("GET /healthz HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200"), "{host}: {response}");
    }
    harness.shutdown().await;
}

#[tokio::test]
async fn liveness_answers_while_management_admission_is_full() {
    let harness = Harness::start().await;
    let address = harness.base.trim_start_matches("http://").to_owned();
    // Authenticated requests with unfinished bodies hold every admission slot.
    let mut stalled = Vec::new();
    for _ in 0..32 {
        let mut stream = TcpStream::connect(&address).await.unwrap();
        stream
            .write_all(
                format!(
                    "POST /api/v1/policy/test HTTP/1.1\r\nHost: localhost\r\n\
                     Authorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\n\
                     Content-Length: 1048576\r\n\r\n{{"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        stalled.push(stream);
    }
    timeout(Duration::from_secs(2), async {
        while harness.get("/api/v1/status").await.status() != 429 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(harness.get("/healthz").await.status(), 200);
    drop(stalled);
    harness.shutdown().await;
}

#[tokio::test]
async fn authentication_failures_name_the_scheme_and_use_json() {
    let harness = Harness::start().await;
    for token in [None, Some("wrong"), Some("local-test-token-at-least-17")] {
        let mut request = reqwest::Client::new().get(format!("{}/api/v1/config", harness.base));
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), 401);
        assert!(
            response.headers()["www-authenticate"]
                .to_str()
                .unwrap()
                .starts_with("Bearer")
        );
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["error"], "bearer token required");
    }
    harness.shutdown().await;
}

#[tokio::test]
async fn every_mutation_requires_if_match() {
    let harness = Harness::start().await;
    let config = harness.state.control.engine().active().config().clone();
    let client = reqwest::Client::new();
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
            .json(&config)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 428, "{path}");
        let body: Value = response.json().await.unwrap();
        assert!(body["error"].as_str().unwrap().contains("If-Match"));
    }
    assert_eq!(harness.state.control.engine().active().generation(), 1);
    // The documented curl recipe reads the tag with HEAD.
    let head = client
        .head(format!("{}/api/v1/config", harness.base))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(head.status(), 200);
    assert_eq!(
        head.headers()["etag"].to_str().unwrap(),
        current_etag(&harness).await
    );
    harness.shutdown().await;
}

#[tokio::test]
async fn malformed_requests_are_reported_as_json_errors() {
    let harness = Harness::start().await;
    let client = reqwest::Client::new();
    let responses = [
        client
            .post(format!("{}/api/v1/policy/test", harness.base))
            .bearer_auth(TOKEN)
            .header("Content-Type", "application/json")
            .body("{not json"),
        client
            .get(format!("{}/api/v1/revisions/not-a-number", harness.base))
            .bearer_auth(TOKEN),
        client
            .get(format!("{}/api/v1/queries?limit=many", harness.base))
            .bearer_auth(TOKEN),
        client
            .get(format!(
                "{}/api/v1/explain?client=nowhere&domain=a.test",
                harness.base
            ))
            .bearer_auth(TOKEN),
    ];
    for request in responses {
        let response = request.send().await.unwrap();
        assert!(response.status().is_client_error(), "{}", response.status());
        assert!(
            response.headers()["content-type"]
                .to_str()
                .unwrap()
                .starts_with("application/json")
        );
        let body: Value = response.json().await.unwrap();
        assert!(body["error"].is_string());
    }
    harness.shutdown().await;
}
