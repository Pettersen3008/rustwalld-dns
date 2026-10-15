use super::*;
use rustwalld_dns_filter::RuleSyntax;
#[tokio::test]
async fn tag_assertions_history_shadow_and_rollback_use_original_explicit_tags() {
    let harness = Harness::start().await;
    let mut config = harness.state.control.engine().active().config().clone();
    config.allowed_clients = vec!["127.0.0.0/24".parse().unwrap()];
    config.bindings = vec![rustwalld_dns_policy::Binding {
        name: "Kids".into(),
        network: "127.0.0.1/32".parse().unwrap(),
        policy: "default".into(),
        filter_tags: vec!["user_child".into()],
        metadata: None,
    }];
    config.policies[0].lists.push(ListInput {
        name: "clients".into(),
        syntax: RuleSyntax::AdguardV6,
        action: Action::Block,
        rules: "||client.test^$ctag=user_child,dnstype=A\n||other.test^$ctag=user_admin".into(),
    });
    config.assertions.push(rustwalld_dns_policy::Assertion {
        client: "127.0.0.1".parse().unwrap(),
        domain: "client.test".into(),
        qtype: 1,
        expected: Action::Block,
    });
    config.assertions.push(rustwalld_dns_policy::Assertion {
        client: "127.0.0.2".parse().unwrap(),
        domain: "client.test".into(),
        qtype: 1,
        expected: Action::Allow,
    });
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        200
    );
    let generation = harness.state.control.engine().active().generation();
    assert_eq!(
        harness.dns("client.test").await.response_code,
        ResponseCode::NXDomain
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
                .find(|event| event["domain"] == "client.test")
            {
                break event;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let mut next = config.clone();
    next.bindings[0].filter_tags.clear();
    next.assertions.last_mut().unwrap().expected = Action::Allow;
    for assertion in &mut next.assertions {
        if assertion.domain == "client.test" {
            assertion.expected = Action::Allow;
        }
    }
    assert_eq!(
        harness.send("/api/v1/shadow", &next, false).await.status(),
        200
    );
    shadow_action(&harness, true).await;
    let recorded: Value = harness
        .get(&format!("/api/v1/queries/{}/explain", event["id"]))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(
        recorded["rule"]["ctag"]["include"],
        serde_json::json!(["user_child"])
    );
    let current: Value = harness
        .get("/api/v1/explain?client=127.0.0.1&domain=client.test")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(current["decision"]["action"], "allow");
    assert_eq!(current["client_name"], "Kids");
    let mut invalid = next.clone();
    invalid
        .assertions
        .iter_mut()
        .find(|assertion| {
            assertion.domain == "client.test"
                && assertion.client == "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
        })
        .unwrap()
        .expected = Action::Block;
    assert_eq!(
        harness
            .send("/api/v1/config", &invalid, true)
            .await
            .status(),
        422
    );
    let boot = harness
        .state
        .control
        .store()
        .bootstrap("ignored".into())
        .await
        .unwrap();
    let recovered =
        PolicySnapshot::compile(serde_json::from_str(&boot.config).unwrap(), boot.active).unwrap();
    assert_eq!(
        recovered
            .explain("127.0.0.1".parse().unwrap(), "client.test")
            .unwrap()
            .decision
            .action,
        Action::Allow
    );
    let rollback = reqwest::Client::new()
        .post(format!(
            "{}/api/v1/revisions/{generation}/rollback",
            harness.base
        ))
        .bearer_auth(TOKEN)
        .header("If-Match", current_etag(&harness).await)
        .send()
        .await
        .unwrap();
    assert_eq!(rollback.status(), 200);
    assert_eq!(
        harness.dns("client.test").await.response_code,
        ResponseCode::NXDomain
    );
    harness.shutdown().await;
}
