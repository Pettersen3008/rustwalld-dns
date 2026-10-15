use super::*;
use rustwalld_dns_filter::RuleSyntax;
#[tokio::test]
async fn denyallow_dns_publication_history_assertions_and_recovery() {
    let harness = Harness::start().await;
    let (upstream, mock) = local_dns().await;
    let mut config = harness.state.control.engine().active().config().clone();
    config.upstreams[0].addresses = vec![upstream];
    config.policies[0].lists.push(ListInput {
        name: "scoped".into(),
        action: Action::Block,
        syntax: RuleSyntax::AdguardV3,
        rules: "||test^$denyallow=safe.test\n||ads.safe.test^\n".into(),
    });
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        200
    );
    let old_generation = harness.state.control.engine().active().generation();
    for (name, rcode) in [
        ("safe.test", ResponseCode::NoError),
        ("x.safe.test", ResponseCode::NoError),
        ("ads.safe.test", ResponseCode::NXDomain),
        ("blocked.test", ResponseCode::NXDomain),
    ] {
        assert_eq!(harness.dns(name).await.response_code, rcode);
    }
    let explain: Value = harness
        .get("/api/v1/explain?client=127.0.0.1&domain=blocked.test")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(
        explain["rule"]["denyallow"],
        serde_json::json!(["safe.test"])
    );
    let event = timeout(Duration::from_secs(2), async {
        loop {
            let events: Vec<Value> = harness
                .get("/api/v1/queries?limit=20")
                .await
                .json()
                .await
                .unwrap();
            if let Some(event) = events
                .into_iter()
                .find(|event| event["domain"] == "blocked.test")
            {
                break event;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let mut next = config.clone();
    next.policies[0].lists[1].rules = "||test^$denyallow=blocked.test\n||safe.test^".into();
    assert_eq!(
        harness.send("/api/v1/shadow", &next, false).await.status(),
        200
    );
    assert_eq!(
        harness.dns("blocked.test").await.response_code,
        ResponseCode::NXDomain
    );
    shadow_action(&harness, true).await;
    let generation = harness.state.control.engine().active().generation();
    assert!(generation > old_generation);
    assert_eq!(
        harness.dns("blocked.test").await.response_code,
        ResponseCode::NoError
    );
    assert_eq!(
        harness.dns("safe.test").await.response_code,
        ResponseCode::NXDomain
    );
    let recorded: Value = harness
        .get(&format!("/api/v1/queries/{}/explain", event["id"]))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(
        recorded["rule"]["denyallow"],
        serde_json::json!(["safe.test"])
    );
    assert_eq!(recorded["rule"]["sources"][0]["list"], "scoped");
    let mut invalid = next.clone();
    invalid.policies[0].lists[1]
        .rules
        .push_str("\n||test^$denyallow=safe.test,badfilter");
    assert_eq!(
        harness
            .send("/api/v1/config", &invalid, true)
            .await
            .status(),
        422
    );
    invalid = next.clone();
    invalid.assertions.push(rustwalld_dns_policy::Assertion {
        qtype: 1,
        client: "127.0.0.1".parse().unwrap(),
        domain: "blocked.test".into(),
        expected: Action::Block,
    });
    assert_eq!(
        harness
            .send("/api/v1/config", &invalid, true)
            .await
            .status(),
        422
    );
    assert_eq!(
        harness.state.control.engine().active().generation(),
        generation
    );
    let boot = harness
        .state
        .control
        .store()
        .bootstrap("ignored".into())
        .await
        .unwrap();
    let recovered =
        PolicySnapshot::compile(serde_json::from_str(&boot.config).unwrap(), generation).unwrap();
    assert_eq!(
        recovered
            .explain("127.0.0.1".parse().unwrap(), "blocked.test")
            .unwrap()
            .decision
            .action,
        Action::Allow
    );
    let rollback = reqwest::Client::new()
        .post(format!(
            "{}/api/v1/revisions/{old_generation}/rollback",
            harness.base
        ))
        .bearer_auth(TOKEN)
        .header("If-Match", current_etag(&harness).await)
        .send()
        .await
        .unwrap();
    assert_eq!(rollback.status(), 200);
    assert!(harness.state.control.engine().active().generation() > generation);
    assert_eq!(
        harness.dns("safe.test").await.response_code,
        ResponseCode::NoError
    );
    assert_eq!(
        harness.dns("blocked.test").await.response_code,
        ResponseCode::NXDomain
    );
    harness.shutdown().await;
    mock.abort();
}
