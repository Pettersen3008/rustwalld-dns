use super::*;
#[tokio::test]
async fn quick_actions_are_scoped_durable_revision_checked_and_expire_on_cached_answers() {
    let harness = Harness::start().await;
    let resolver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = resolver.local_addr().unwrap();
    let mock = tokio::spawn(async move {
        let mut bytes = [0u8; 4096];
        loop {
            let (len, peer) = resolver.recv_from(&mut bytes).await.unwrap();
            let mut answer = Message::from_vec(&bytes[..len]).unwrap();
            answer.metadata.message_type = hickory_proto::op::MessageType::Response;
            answer.metadata.recursion_available = true;
            answer.add_answer(hickory_proto::rr::Record::from_rdata(
                answer.queries[0].name().clone(),
                120,
                hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(
                    "192.0.2.10".parse().unwrap(),
                )),
            ));
            resolver
                .send_to(&answer.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let mut config: PolicyConfigSet = harness.get("/api/v1/config").await.json().await.unwrap();
    config.upstreams[0].addresses = vec![address];
    config.assertions = vec![rustwalld_dns_policy::Assertion {
        qtype: 1,
        client: "127.0.0.1".parse().unwrap(),
        domain: "ads.test".into(),
        expected: Action::Block,
    }];
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        200
    );
    let client = reqwest::Client::new();
    let url = format!("{}/api/v1/temporary-actions", harness.base);
    let body = serde_json::json!({"operation":"allow","client":"127.0.0.1","domain":"ads.test","duration_secs":2});
    assert_eq!(
        client.post(&url).json(&body).send().await.unwrap().status(),
        401
    );
    assert_eq!(
        client
            .post(&url)
            .bearer_auth(TOKEN)
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        428
    );
    let tag = current_etag(&harness).await;
    let denied = serde_json::json!({"operation":"pause","client":"192.0.2.1","duration_secs":60});
    assert_eq!(
        client
            .post(&url)
            .bearer_auth(TOKEN)
            .header("If-Match", &tag)
            .json(&denied)
            .send()
            .await
            .unwrap()
            .status(),
        422
    );
    assert_eq!(
        client
            .post(&url)
            .bearer_auth(TOKEN)
            .header("If-Match", &tag)
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        client
            .post(&url)
            .bearer_auth(TOKEN)
            .header("If-Match", &tag)
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        412
    );
    let answer = harness.dns("ads.test").await;
    assert_eq!(answer.response_code, ResponseCode::NoError);
    assert!(answer.answers[0].ttl <= 2);
    let config: PolicyConfigSet = harness.get("/api/v1/config").await.json().await.unwrap();
    assert_eq!(
        config.policies[0].temporary_exceptions[0].clients[0].to_string(),
        "127.0.0.1/32"
    );
    assert!(
        harness.state.control.engine().snapshot().policies()[0]
            .temporary_allow_for(
                "ads.test",
                "127.0.0.2".parse().unwrap(),
                std::time::Instant::now()
            )
            .is_none()
    );
    // Renewal replaces the same scope; it does not create a duplicate exception.
    assert_eq!(
        client
            .post(&url)
            .bearer_auth(TOKEN)
            .header("If-Match", current_etag(&harness).await)
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    tokio::time::sleep(Duration::from_millis(2100)).await;
    assert_eq!(
        harness.dns("ads.test").await.response_code,
        ResponseCode::NXDomain
    );
    let pause = serde_json::json!({"operation":"pause","client":"127.0.0.1","duration_secs":300});
    assert_eq!(
        client
            .post(&url)
            .bearer_auth(TOKEN)
            .header("If-Match", current_etag(&harness).await)
            .json(&pause)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        harness.dns("ads.test").await.response_code,
        ResponseCode::NoError
    );
    let config: PolicyConfigSet = harness.get("/api/v1/config").await.json().await.unwrap();
    assert_eq!(
        harness
            .send("/api/v1/shadow", &config, false)
            .await
            .status(),
        200
    );
    assert_eq!(
        client
            .post(&url)
            .bearer_auth(TOKEN)
            .header("If-Match", current_etag(&harness).await)
            .json(&pause)
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
    mock.abort();
    harness.shutdown().await;
}
