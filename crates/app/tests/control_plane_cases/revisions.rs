#![allow(clippy::unwrap_used)]
use super::*;

#[tokio::test]
async fn binding_metadata_is_revisioned_specific_and_failure_isolated() {
    let harness = Harness::start().await;
    let mut config = harness.state.control.engine().active().config().clone();
    // Legacy configuration omits metadata and remains readable.
    config.bindings.push(rustwalld_dns_policy::Binding {
        name: "Work laptop".into(),
        network: "127.0.0.1/32".parse().unwrap(),
        policy: "default".into(),
        filter_tags: Vec::new(),
        metadata: None,
    });
    let legacy = serde_json::to_value(&config).unwrap();
    assert!(legacy["bindings"][0].get("metadata").is_none());
    let _: PolicyConfigSet = serde_json::from_value(legacy.clone()).unwrap();
    let mut unknown = legacy;
    unknown["bindings"][0]["metadata"] = serde_json::json!({"auto_vlan": 10});
    assert!(serde_json::from_value::<PolicyConfigSet>(unknown).is_err());
    config.bindings[0].metadata = Some(rustwalld_dns_policy::BindingMetadata {
        group: Some("Work – 内部".into()),
        owner: Some("Pettersen".into()),
        vlan: Some(20),
        tags: vec!["managed".into(), "laptop".into()],
        note: Some("Fixed DHCP reservation".into()),
    });
    config.bindings.push(rustwalld_dns_policy::Binding {
        name: "Loopback network".into(),
        network: "127.0.0.0/8".parse().unwrap(),
        policy: "default".into(),
        filter_tags: Vec::new(),
        metadata: Some(rustwalld_dns_policy::BindingMetadata {
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
        assert_eq!(harness.state.control.engine().active().generation(), 1);
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
    let original = harness.state.control.engine().snapshot();
    let original_generation = original.generation();
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
        .control
        .store()
        .bootstrap("ignored".into())
        .await
        .unwrap();
    let recovered: PolicyConfigSet = serde_json::from_str(&boot.config).unwrap();
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
        harness.state.control.engine().active().generation(),
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
    let current_generation = harness.state.control.engine().active().generation();
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
        .header("If-Match", current_etag(&harness).await)
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
            .control
            .engine()
            .resolver()
            .metrics
            .snapshot()
            .upstream_lookups,
        0
    );
    harness.shutdown().await;
}

#[tokio::test]
async fn policy_test_reports_every_case_without_publishing_or_touching_revisions() {
    let harness = Harness::start().await;
    let mut config = harness.state.control.engine().active().config().clone();
    config.upstreams[0].addresses = vec!["127.0.0.1:9".parse().unwrap()];
    config.assertions = vec![
        rustwalld_dns_policy::Assertion {
            qtype: 1,
            client: "127.0.0.1".parse().unwrap(),
            domain: "ads.test".into(),
            expected: Action::Allow,
        },
        rustwalld_dns_policy::Assertion {
            qtype: 1,
            client: "127.0.0.1".parse().unwrap(),
            domain: "allowed.test".into(),
            expected: Action::Block,
        },
        rustwalld_dns_policy::Assertion {
            qtype: 1,
            client: "127.0.0.1".parse().unwrap(),
            domain: "bad..domain".into(),
            expected: Action::Allow,
        },
        rustwalld_dns_policy::Assertion {
            qtype: 1,
            client: "192.0.2.1".parse().unwrap(),
            domain: "allowed.test".into(),
            expected: Action::Allow,
        },
        rustwalld_dns_policy::Assertion {
            qtype: 1,
            client: "127.0.0.1".parse().unwrap(),
            domain: "x.ads.test".into(),
            expected: Action::Block,
        },
    ];
    let next = harness.state.control.next_generation();
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
    assert_eq!(harness.state.control.next_generation(), next);
    for (path, put) in [("/api/v1/config", true), ("/api/v1/shadow", false)] {
        assert_eq!(harness.send(path, &config, put).await.status(), 422);
        assert_eq!(harness.state.control.engine().active().generation(), 1);
        assert!(harness.state.control.engine().shadow().is_none());
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

#[tokio::test]
async fn shadow_promote_rollback_and_durable_generation() {
    let harness = Harness::start().await;
    let mut config = harness.state.control.engine().active().config().clone();
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
            .control
            .engine()
            .shadow()
            .as_ref()
            .unwrap()
            .generation(),
        2
    );
    let response = reqwest::Client::new()
        .post(format!("{}/api/v1/shadow/promote", harness.base))
        .bearer_auth(TOKEN)
        .header("If-Match", current_etag(&harness).await)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    assert_eq!(harness.state.control.engine().active().generation(), 3);
    assert!(harness.state.control.engine().shadow().is_none());
    let response = reqwest::Client::new()
        .post(format!("{}/api/v1/revisions/1/rollback", harness.base))
        .bearer_auth(TOKEN)
        .header("If-Match", current_etag(&harness).await)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    assert_eq!(harness.state.control.engine().active().generation(), 4);
    assert_eq!(
        harness.dns("ads.test.").await.metadata.response_code,
        ResponseCode::NXDomain
    );
    let boot = harness
        .state
        .control
        .store()
        .bootstrap("ignored".into())
        .await
        .unwrap();
    assert_eq!(boot.active, 4);
    assert_eq!(boot.next, 5);
    let stored: PolicyConfigSet = serde_json::from_str(&boot.config).unwrap();
    assert_eq!(stored.policies[0].lists.len(), 1);
    harness.shutdown().await;
}

#[tokio::test]
async fn sqlite_lock_rejects_promotion_but_dns_keeps_answering() {
    let harness = Harness::start().await;
    let connection = rusqlite::Connection::open(&harness.path).unwrap();
    connection.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut config = harness.state.control.engine().active().config().clone();
    config.policies[0].lists[0].rules = "new.test".into();
    let requests = {
        let base = harness.base.clone();
        let tag = current_etag(&harness).await;
        tokio::spawn(async move {
            reqwest::Client::new()
                .put(format!("{base}/api/v1/config"))
                .bearer_auth(TOKEN)
                .header("If-Match", tag)
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
    assert_eq!(harness.state.control.engine().active().generation(), 1);
    connection.execute_batch("ROLLBACK").unwrap();
    assert_eq!(
        harness.dns("ads.test.").await.metadata.response_code,
        ResponseCode::NXDomain
    );
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
        .header("If-Match", current_etag(&harness).await)
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
        assert_eq!(harness.state.control.engine().active().generation(), 1);
        assert_eq!(
            harness
                .state
                .control
                .engine()
                .shadow()
                .as_ref()
                .unwrap()
                .generation(),
            2
        );
        assert_eq!(harness.state.control.next_generation(), 3);
    }
    let response = client
        .post(format!("{}/api/v1/shadow/promote", harness.base))
        .bearer_auth(TOKEN)
        .header("If-Match", current_etag(&harness).await)
        .header("if-match", shadow_tag)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["etag"], "\"g3-s0\"");
    assert_eq!(harness.state.control.engine().active().generation(), 3);
    assert!(harness.state.control.engine().shadow().is_none());
    assert_eq!(
        harness.dns("new.test").await.metadata.response_code,
        ResponseCode::NXDomain
    );
    harness.shutdown().await;
}
