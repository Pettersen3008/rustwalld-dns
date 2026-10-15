use super::*;
#[tokio::test]
async fn service_catalog_is_authenticated_and_recorded_rules_survive_current_disable() {
    let harness = Harness::start().await;
    let public = reqwest::Client::new()
        .get(format!("{}/api/v1/service-catalog", harness.base))
        .send()
        .await
        .unwrap();
    assert_eq!(public.status(), 401);
    let catalog: Value = harness
        .get("/api/v1/service-catalog")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(catalog["catalog_version"], 1);
    assert_eq!(catalog["services"].as_array().unwrap().len(), 4);
    let mut config: PolicyConfigSet = harness.get("/api/v1/config").await.json().await.unwrap();
    // A blocked request must never contact a public resolver.
    config.upstreams[0].addresses = vec!["127.0.0.1:9".parse().unwrap()];
    config.policies[0].lists.push(ListInput {
        name: "ordinary".into(),
        action: Action::Block,
        rules: "aaa.test\nz.test".into(),
        syntax: Default::default(),
    });
    config.policies[0].blocked_services = Some(rustwalld_dns_policy::BlockedServices {
        catalog_version: 1,
        ids: vec!["youtube".into()],
        schedule: None,
    });
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        200
    );
    assert_eq!(
        harness.dns("www.youtube.com").await.response_code,
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
                .find(|event| event["domain"] == "www.youtube.com")
            {
                break event;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    config.policies[0].blocked_services = None;
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        200
    );
    let path = format!("/api/v1/queries/{}/explain", event["id"].as_u64().unwrap());
    let recorded: Value = harness.get(&path).await.json().await.unwrap();
    assert_eq!(recorded["rule"]["domain"], "youtube.com");
    assert!(
        recorded["rule"]["sources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|source| source["list"]
                .as_str()
                .unwrap()
                .contains("@service/v1/youtube"))
    );
    let current: Value = harness
        .get("/api/v1/explain?client=127.0.0.1&domain=www.youtube.com")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(current["decision"]["action"], "allow");
    harness.shutdown().await;
}

#[tokio::test]
async fn expanded_catalog_versions_validate_and_retain_original_v2_history_after_downgrade() {
    let harness = Harness::start().await;
    let public = reqwest::Client::new()
        .get(format!("{}/api/v1/service-catalog?version=2", harness.base))
        .send()
        .await
        .unwrap();
    assert_eq!(public.status(), 401);
    let catalog: Value = harness
        .get("/api/v1/service-catalog?version=2")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(catalog["catalog_version"], 2);
    assert_eq!(catalog["services"].as_array().unwrap().len(), 12);
    let netflix = catalog["services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["id"] == "netflix")
        .unwrap();
    assert_eq!(netflix["suffixes"], serde_json::json!(["netflix.com"]));
    assert!(!netflix["limitations"].as_array().unwrap().is_empty());
    for path in [
        "/api/v1/service-catalog?version=0",
        "/api/v1/service-catalog?version=3",
    ] {
        assert_eq!(harness.get(path).await.status(), 422);
    }
    for path in [
        "/api/v1/service-catalog?version=wrong",
        "/api/v1/service-catalog?extra=2",
    ] {
        assert_eq!(harness.get(path).await.status(), 400);
    }
    let mut config: PolicyConfigSet = harness.get("/api/v1/config").await.json().await.unwrap();
    config.upstreams[0].addresses = vec!["127.0.0.1:9".parse().unwrap()];
    config.policies[0].blocked_services = Some(rustwalld_dns_policy::BlockedServices {
        catalog_version: 1,
        ids: vec!["netflix".into()],
        schedule: None,
    });
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        422
    );
    config.policies[0]
        .blocked_services
        .as_mut()
        .unwrap()
        .catalog_version = 2;
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        200
    );
    assert_eq!(
        harness.dns("www.netflix.com").await.response_code,
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
                .find(|event| event["domain"] == "www.netflix.com")
            {
                break event;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    config.policies[0].blocked_services = Some(rustwalld_dns_policy::BlockedServices {
        catalog_version: 1,
        ids: vec!["youtube".into()],
        schedule: None,
    });
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        200
    );
    let trace: Value = harness
        .get(&format!(
            "/api/v1/queries/{}/explain",
            event["id"].as_u64().unwrap()
        ))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(trace["rule"]["domain"], "netflix.com");
    assert_eq!(
        trace["rule"]["sources"][0]["list"],
        "@service/v2/netflix (Netflix)"
    );
    harness.shutdown().await;
}
