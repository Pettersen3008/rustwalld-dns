use super::*;
#[tokio::test]
async fn safesearch_publication_current_and_recorded_provenance_use_exact_generations() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let mock = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        loop {
            let (len, peer) = socket.recv_from(&mut bytes).await.unwrap();
            let request = Message::from_vec(&bytes[..len]).unwrap();
            assert_eq!(
                request.queries[0].name().to_ascii(),
                "forcesafesearch.google.com."
            );
            let mut response = rustwalld_dns_core::reply(&request, ResponseCode::NoError);
            response.add_answer(hickory_proto::rr::Record::from_rdata(
                request.queries[0].name().clone(),
                60,
                hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(
                    "192.0.2.20".parse().unwrap(),
                )),
            ));
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let harness = Harness::start().await;
    let mut config: PolicyConfigSet = harness.get("/api/v1/config").await.json().await.unwrap();
    config.upstreams[0].addresses = vec![address];
    config.policies[0].safe_search = Some(rustwalld_dns_policy::SafeSearchConfig {
        google: true,
        ..Default::default()
    });
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        200
    );
    let explain: Value = harness
        .get("/api/v1/explain?client=127.0.0.1&domain=www.google.com")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(explain["safe_search"]["provider"], "google");
    assert_eq!(
        explain["safe_search"]["target"],
        "forcesafesearch.google.com"
    );
    let response = harness.dns("www.google.com").await;
    assert_eq!(response.response_code, ResponseCode::NoError);
    assert!(
        matches!(&response.answers[0].data,hickory_proto::rr::RData::CNAME(target) if target.0.to_ascii()=="forcesafesearch.google.com.")
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
                .find(|event| event["domain"] == "www.google.com")
            {
                break event;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(event["source"], "safe_search");
    config.policies[0].safe_search = None;
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        200
    );
    let path = format!("/api/v1/queries/{}/explain", event["id"].as_u64().unwrap());
    let historical: Value = harness.get(&path).await.json().await.unwrap();
    assert_eq!(historical["basis"], "recorded_generation");
    assert_eq!(historical["event"]["generation"], event["generation"]);
    assert_eq!(historical["safe_search"]["catalog_version"], 1);
    assert_eq!(
        historical["safe_search"]["target"],
        "forcesafesearch.google.com"
    );
    let current: Value = harness
        .get("/api/v1/explain?client=127.0.0.1&domain=www.google.com")
        .await
        .json()
        .await
        .unwrap();
    assert!(current.get("safe_search").is_none());
    harness.shutdown().await;
    mock.abort();
}
