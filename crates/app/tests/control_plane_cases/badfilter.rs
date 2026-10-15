use super::*;
use rustwalld_dns_filter::RuleSyntax;

#[tokio::test]
async fn badfilter_publication_history_rollback_and_recovery_preserve_generations() {
    let harness = Harness::start().await;
    let (upstream, mock) = local_dns().await;
    let mut legacy = harness.state.control.engine().active().config().clone();
    legacy.upstreams[0].addresses = vec![upstream];
    legacy.policies[0].lists.push(ListInput {
        name: "legacy".into(),
        action: Action::Block,
        syntax: RuleSyntax::Adguard,
        rules: "||cancel.test^ # historical comment\n||retained.test^".into(),
    });
    assert_eq!(
        harness.send("/api/v1/config", &legacy, true).await.status(),
        200
    );
    let old_generation = harness.state.control.engine().active().generation();
    assert_eq!(
        harness.dns("cancel.test").await.response_code,
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
                .find(|event| event["domain"] == "cancel.test")
            {
                break event;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let mut next = legacy.clone();
    next.policies[0].lists[1].syntax = RuleSyntax::AdguardV2;
    next.policies[0].lists[1].rules =
        "||cancel.test^\n||retained.test^\n||cancel.test^$badfilter\n||youtube.com^$badfilter"
            .into();
    next.policies[0].blocked_services = Some(rustwalld_dns_policy::BlockedServices {
        catalog_version: 1,
        ids: vec!["youtube".into()],
        schedule: None,
    });
    assert_eq!(
        harness.send("/api/v1/shadow", &next, false).await.status(),
        200
    );
    assert_eq!(
        harness.dns("cancel.test").await.response_code,
        ResponseCode::NXDomain
    );
    shadow_action(&harness, true).await;
    let new_generation = harness.state.control.engine().active().generation();
    assert!(new_generation > old_generation);
    assert_eq!(
        harness.dns("cancel.test").await.response_code,
        ResponseCode::NoError
    );
    assert_eq!(
        harness.dns("youtube.com").await.response_code,
        ResponseCode::NXDomain
    );
    let stats: Value = harness
        .get("/api/v1/filter-lists")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(stats[0]["cancellation_targets"], 2);
    assert_eq!(stats[0]["lists"][1]["disabled"], 1);
    assert_eq!(
        stats[0]["cancellations"][0]["disabled_sources"][0]["line"],
        1
    );
    let path = format!("/api/v1/queries/{}/explain", event["id"]);
    let recorded: Value = harness.get(&path).await.json().await.unwrap();
    assert_eq!(recorded["rule"]["domain"], "cancel.test");
    assert_eq!(recorded["rule"]["sources"][0]["list"], "legacy");
    assert_eq!(recorded["rule"]["sources"][0]["line"], 1);
    // Failed assertions and malformed modifiers leave the last good generation.
    let mut invalid = next.clone();
    invalid.assertions.push(rustwalld_dns_policy::Assertion {
        qtype: 1,
        client: "127.0.0.1".parse().unwrap(),
        domain: "cancel.test".into(),
        expected: Action::Block,
    });
    assert_eq!(
        harness
            .send("/api/v1/config", &invalid, true)
            .await
            .status(),
        422
    );
    invalid = next.clone();
    invalid.policies[0].lists[1]
        .rules
        .push_str("\n||retained.test^$important,badfilter");
    assert_eq!(
        harness
            .send("/api/v1/config", &invalid, true)
            .await
            .status(),
        422
    );
    assert_eq!(
        harness.state.control.engine().active().generation(),
        new_generation
    );
    let boot = harness
        .state
        .control
        .store()
        .bootstrap("ignored".into())
        .await
        .unwrap();
    let recovered =
        PolicySnapshot::compile(serde_json::from_str(&boot.config).unwrap(), new_generation)
            .unwrap();
    assert_eq!(recovered.policies()[0].filters().cancellation_targets(), 2);
    assert_eq!(
        recovered
            .explain("127.0.0.1".parse().unwrap(), "cancel.test")
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
    assert!(harness.state.control.engine().active().generation() > new_generation);
    assert_eq!(
        harness.dns("cancel.test").await.response_code,
        ResponseCode::NXDomain
    );
    harness.shutdown().await;
    mock.abort();
}

#[tokio::test]
async fn badfilter_api_reports_are_bounded_across_shared_policies_and_can_be_scoped() {
    let harness = Harness::start().await;
    let mut config = harness.state.control.engine().active().config().clone();
    let mut rules = String::new();
    for i in 0..205 {
        rules.push_str(&format!("||cancel{i}.test^\n||cancel{i}.test^$badfilter\n"));
    }
    config.policies[0].lists.push(ListInput {
        name: "shared".into(),
        action: Action::Block,
        syntax: RuleSyntax::AdguardV2,
        rules,
    });
    let mut second = config.policies[0].clone();
    second.name = "other policy".into();
    config.policies.push(second);
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        200
    );
    let all: Vec<Value> = harness
        .get("/api/v1/filter-lists")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(
        all.iter()
            .map(|policy| policy["cancellations"].as_array().unwrap().len())
            .sum::<usize>(),
        200
    );
    assert!(all[1]["cancellations"].as_array().unwrap().is_empty());
    assert_eq!(all[1]["cancellation_targets"], 205);
    let scoped: Vec<Value> = harness
        .get("/api/v1/filter-lists?policy=other%20policy")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(scoped.len(), 1);
    assert_eq!(scoped[0]["policy"], "other policy");
    assert_eq!(scoped[0]["cancellations"].as_array().unwrap().len(), 200);
    assert_eq!(scoped[0]["cancellations"][0]["disabled"], 1);
    assert_eq!(
        harness.get("/api/v1/filter-lists?unknown=1").await.status(),
        400
    );
    harness.shutdown().await;
}
