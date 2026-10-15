use super::*;
#[tokio::test]
async fn v5_archive_preview_requires_revision_and_publishes_only_after_review() {
    let harness = Harness::start().await;
    let client = reqwest::Client::new();
    let input = include_bytes!("../../../../web/e2e/fixtures/pihole-v5.tar.gz");
    let tag = current_etag(&harness).await;
    let url = format!("{}/api/v1/migrations/preview?source=pihole", harness.base);
    let response = client
        .post(&url)
        .bearer_auth(TOKEN)
        .header("If-Match", &tag)
        .body(input.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let report: Value = response.json().await.unwrap();
    assert_eq!(report["ready"], true);
    assert!(
        !report
            .to_string()
            .contains("PUBLIC_TEST_SENTINEL_DO_NOT_COPY")
    );
    assert_eq!(current_etag(&harness).await, tag);
    assert_eq!(
        harness.dns("ads.test").await.response_code,
        ResponseCode::NXDomain
    );
    let config: PolicyConfigSet = serde_json::from_value(report["config"].clone()).unwrap();
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        200
    );
    let answer = harness.dns("storage.home.arpa").await;
    assert_eq!(answer.response_code, ResponseCode::NoError);
    assert_eq!(answer.answers.len(), 2);
    assert_eq!(answer.answers[0].ttl, 40);
    assert_eq!(
        harness.dns("ads.test").await.response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(
        client
            .post(url)
            .bearer_auth(TOKEN)
            .header("If-Match", tag)
            .body(input.to_vec())
            .send()
            .await
            .unwrap()
            .status(),
        412
    );
    harness.shutdown().await;
}
#[tokio::test]
async fn import_requires_auth_admission_and_current_revision_and_never_publishes() {
    let harness = Harness::start().await;
    let client = reqwest::Client::new();
    let url = format!("{}/api/v1/migrations/preview?source=adguard", harness.base);
    let payload =
        "dns: {upstream_dns: [127.0.0.1:15354]}\nuser_rules: [ads.test, '||tracking.test^']\n";
    let tag = current_etag(&harness).await;
    let baseline = harness.get("/api/v1/config").await.text().await.unwrap();
    assert_eq!(
        client
            .post(&url)
            .body(payload)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        client
            .post(&url)
            .bearer_auth(TOKEN)
            .body(payload)
            .send()
            .await
            .unwrap()
            .status(),
        428
    );
    assert_eq!(
        client
            .post(&url)
            .bearer_auth(TOKEN)
            .header("If-Match", "\"g0-s0\"")
            .body(payload)
            .send()
            .await
            .unwrap()
            .status(),
        412
    );
    use tokio::io::AsyncWriteExt;
    let address = harness.base.strip_prefix("http://").unwrap();
    let mut uploads = Vec::new();
    for _ in 0..2 {
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream.write_all(format!("POST /api/v1/migrations/preview?source=adguard HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {TOKEN}\r\nIf-Match: {tag}\r\nContent-Length: 1\r\n\r\n").as_bytes()).await.unwrap();
        uploads.push(stream);
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        client
            .post(&url)
            .bearer_auth(TOKEN)
            .header("If-Match", &tag)
            .body(payload)
            .send()
            .await
            .unwrap()
            .status(),
        429
    );
    assert_eq!(harness.get("/healthz").await.status(), 200);
    drop(uploads);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let response = client
        .post(&url)
        .bearer_auth(TOKEN)
        .header("If-Match", &tag)
        .body(payload)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["etag"], tag);
    let report: Value = response.json().await.unwrap();
    assert_eq!(report["translated_rules"], 2);
    assert_eq!(report["ready"], true);
    assert_eq!(
        report["config"]["policies"][0]["lists"][0]["syntax"],
        "adguard_v6"
    );
    assert_eq!(current_etag(&harness).await, tag);
    assert_eq!(
        harness.get("/api/v1/config").await.text().await.unwrap(),
        baseline
    );
    assert_eq!(
        harness.dns("ads.test").await.response_code,
        ResponseCode::NXDomain
    );
    let events = timeout(Duration::from_secs(2), async {
        loop {
            let events: Vec<Value> = harness
                .get("/api/v1/queries?limit=10")
                .await
                .json()
                .await
                .unwrap();
            if !events.is_empty() {
                break events;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let event = &events[0];
    let id = event["id"].as_u64().unwrap();
    let recorded = harness.get(&format!("/api/v1/queries/{id}/explain")).await;
    assert_eq!(recorded.status(), 200);
    let trace: Value = recorded.json().await.unwrap();
    assert_eq!(trace["basis"], "recorded_generation");
    assert_eq!(trace["rule"]["domain"], "ads.test");
    assert_eq!(trace["rule"]["sources"][0]["list"], "test");
    let mut updated: PolicyConfigSet = serde_json::from_str(&baseline).unwrap();
    updated.policies[0].lists[0].name = "changed-list".into();
    assert_eq!(
        harness
            .send("/api/v1/config", &updated, true)
            .await
            .status(),
        200
    );
    let trace: Value = harness
        .get(&format!("/api/v1/queries/{id}/explain"))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(trace["rule"]["sources"][0]["list"], "test");
    assert_eq!(trace["event"]["generation"], event["generation"]);
    assert_eq!(
        harness
            .get("/api/v1/queries/18446744073709551615/explain")
            .await
            .status(),
        404
    );
    let tag = current_etag(&harness).await;
    assert_eq!(
        client
            .post(&url)
            .bearer_auth(TOKEN)
            .header("If-Match", &tag)
            .body("users: [password: secret]\ndns: [broken")
            .send()
            .await
            .unwrap()
            .status(),
        422
    );
    let blocked:Value = client.post(&url).bearer_auth(TOKEN).header("If-Match",&tag).body("user_rules: [ads.test]\nfilters: [{id: 1, enabled: true, url: 'https://publisher.test/filter'}]").send().await.unwrap().json().await.unwrap();
    assert_eq!(blocked["ready"], false);
    assert_eq!(blocked["publishers"][0]["needs_download"], true);
    harness.shutdown().await;
}

async fn answering_resolver(
    last_octet: u8,
) -> (
    std::net::SocketAddr,
    Arc<std::sync::atomic::AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = calls.clone();
    let task = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        loop {
            let (len, peer) = socket.recv_from(&mut bytes).await.unwrap();
            counter.fetch_add(1, Ordering::SeqCst);
            let request = Message::from_vec(&bytes[..len]).unwrap();
            let mut response = rustwalld_dns_core::reply(&request, ResponseCode::NoError);
            response.add_answer(hickory_proto::rr::Record::from_rdata(
                request.queries[0].name().clone(),
                600,
                hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(std::net::Ipv4Addr::new(
                    192, 0, 2, last_octet,
                ))),
            ));
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    (address, calls, task)
}
async fn client_answer(harness: &Harness, client: &str) -> hickory_proto::rr::RData {
    let socket = UdpSocket::bind(format!("{client}:0")).await.unwrap();
    let mut request = Message::query();
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(
        Name::from_ascii("resolver.test").unwrap(),
        RecordType::A,
    ));
    socket
        .send_to(&request.to_vec().unwrap(), harness.state.control.listen())
        .await
        .unwrap();
    let mut bytes = [0; 1232];
    let len = timeout(Duration::from_secs(1), socket.recv(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    let response = Message::from_vec(&bytes[..len]).unwrap();
    assert_eq!(response.response_code, ResponseCode::NoError);
    response.answers[0].data.clone()
}
#[tokio::test]
async fn client_resolver_import_preview_shadow_promotion_cache_and_durable_recompile() {
    let (global, global_calls, global_task) = answering_resolver(10).await;
    let (custom, custom_calls, custom_task) = answering_resolver(20).await;
    let harness = Harness::start().await;
    let source = format!(
        "dns: {{upstream_dns: ['{global}'], allowed_clients: [127.0.0.0/8]}}\nclients: {{persistent: [{{name: Work, ids: [127.0.0.2], use_global_settings: true, upstreams: ['{custom}']}}, {{name: Shared, ids: [127.0.0.3], upstreams: ['{custom}']}}, {{name: Inherited, ids: [127.0.0.4], upstreams: []}}]}}\nuser_rules: [ads.test]\n"
    );
    let tag = current_etag(&harness).await;
    let response = reqwest::Client::new()
        .post(format!(
            "{}/api/v1/migrations/preview?source=adguard",
            harness.base
        ))
        .bearer_auth(TOKEN)
        .header("If-Match", &tag)
        .body(source)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let report: Value = response.json().await.unwrap();
    assert_eq!(report["ready"], true, "{report}");
    let config: PolicyConfigSet = serde_json::from_value(report["config"].clone()).unwrap();
    assert_eq!(config.upstreams.len(), 3);
    assert_eq!(current_etag(&harness).await, tag);
    assert_eq!(global_calls.load(Ordering::SeqCst), 0);
    assert_eq!(custom_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        harness
            .send("/api/v1/shadow", &config, false)
            .await
            .status(),
        200
    );
    assert_eq!(
        harness.dns("ads.test").await.response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(custom_calls.load(Ordering::SeqCst), 0);
    shadow_action(&harness, true).await;
    for _ in 0..2 {
        for (client, octet) in [
            ("127.0.0.1", 10),
            ("127.0.0.2", 20),
            ("127.0.0.3", 20),
            ("127.0.0.4", 10),
        ] {
            assert_eq!(
                client_answer(&harness, client).await,
                hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(std::net::Ipv4Addr::new(
                    192, 0, 2, octet
                )))
            );
        }
    }
    assert_eq!(global_calls.load(Ordering::SeqCst), 1);
    assert_eq!(custom_calls.load(Ordering::SeqCst), 1);
    let boot = harness
        .state
        .control
        .store()
        .bootstrap("ignored".into())
        .await
        .unwrap();
    let stored: PolicyConfigSet = serde_json::from_str(&boot.config).unwrap();
    let recovered = PolicySnapshot::compile(stored.clone(), 99).unwrap();
    assert_eq!(
        recovered
            .explain("127.0.0.2".parse().unwrap(), "resolver.test")
            .unwrap()
            .upstream,
        config.policies[1].upstream
    );
    assert_eq!(stored.upstreams, config.upstreams);
    assert_eq!(stored.bindings, config.bindings);
    harness.shutdown().await;
    global_task.abort();
    custom_task.abort();
}

#[tokio::test]
async fn imported_ds_routing_is_ready_revisioned_and_typed_explanations_keep_native_defaults() {
    let harness = Harness::start().await;
    let tag = current_etag(&harness).await;
    let source = "dns: {upstream_dns: ['127.0.0.1:15401', '[/test/]127.0.0.1:15402', '[/child.test/]127.0.0.1:15403']}\nclients: {persistent: [{name: Custom, ids: [127.0.0.2], upstreams: ['[/test/]127.0.0.1:15404']}]}\nuser_rules: [ads.test]\n";
    let report: Value = reqwest::Client::new()
        .post(format!(
            "{}/api/v1/migrations/preview?source=adguard",
            harness.base
        ))
        .bearer_auth(TOKEN)
        .header("If-Match", &tag)
        .body(source)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(report["ready"], true, "{report}");
    let config: PolicyConfigSet = serde_json::from_value(report["config"].clone()).unwrap();
    assert_eq!(
        config.policies[0].ds_routing,
        rustwalld_dns_policy::DsRouting::Parent
    );
    assert_eq!(
        config.policies[1].ds_routing,
        rustwalld_dns_policy::DsRouting::Parent
    );
    assert_eq!(current_etag(&harness).await, tag);
    assert_eq!(
        harness
            .send("/api/v1/shadow", &config, false)
            .await
            .status(),
        200
    );
    shadow_action(&harness, true).await;
    for (client, kind, upstream) in [
        ("127.0.0.1", "", "adguard/upstreams/route-0"),
        ("127.0.0.1", "&qtype=1", "adguard/upstreams/route-0"),
        ("127.0.0.1", "&qtype=43", "adguard/upstreams/route-1"),
        ("127.0.0.1", "&qtype=48", "adguard/upstreams/route-0"),
        (
            "127.0.0.2",
            "&qtype=43",
            "adguard/client-0/upstreams/route-0",
        ),
    ] {
        let trace: Value = harness
            .get(&format!(
                "/api/v1/explain?client={client}&domain=child.test{kind}"
            ))
            .await
            .json()
            .await
            .unwrap();
        assert_eq!(trace["upstream"], upstream, "{trace}");
    }
    for kind in ["bad", "-1", "65536"] {
        assert_eq!(
            harness
                .get(&format!(
                    "/api/v1/explain?client=127.0.0.1&domain=child.test&qtype={kind}"
                ))
                .await
                .status(),
            400
        );
    }
    let boot = harness
        .state
        .control
        .store()
        .bootstrap("ignored".into())
        .await
        .unwrap();
    let stored: PolicyConfigSet = serde_json::from_str(&boot.config).unwrap();
    assert_eq!(
        stored.policies[0].ds_routing,
        rustwalld_dns_policy::DsRouting::Parent
    );
    let recovered = PolicySnapshot::compile(stored, 99).unwrap();
    assert_eq!(
        recovered
            .explain_query("127.0.0.1".parse().unwrap(), "child.test", RecordType::DS)
            .unwrap()
            .upstream,
        "adguard/upstreams/route-1"
    );
    let mut native = config;
    native.policies[0].ds_routing = rustwalld_dns_policy::DsRouting::Question;
    assert_eq!(
        harness.send("/api/v1/config", &native, true).await.status(),
        200
    );
    let trace: Value = harness
        .get("/api/v1/explain?client=127.0.0.1&domain=child.test&qtype=43")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(trace["upstream"], "adguard/upstreams/route-0");
    harness.shutdown().await;
}
