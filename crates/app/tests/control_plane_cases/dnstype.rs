use super::*;
use rustwalld_dns_filter::RuleSyntax;
#[tokio::test]
async fn typed_assertions_publication_history_and_recovery_keep_original_types() {
    let harness = Harness::start().await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream = socket.local_addr().unwrap();
    let mock = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        loop {
            let (len, peer) = socket.recv_from(&mut bytes).await.unwrap();
            let request = Message::from_vec(&bytes[..len]).unwrap();
            let mut reply = rustwalld_dns_core::reply(&request, ResponseCode::NoError);
            reply.add_answer(hickory_proto::rr::Record::from_rdata(
                request.queries[0].name().clone(),
                600,
                hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(
                    "192.0.2.1".parse().unwrap(),
                )),
            ));
            socket
                .send_to(&reply.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let mut config = harness.state.control.engine().active().config().clone();
    config.upstreams[0].addresses = vec![upstream];
    config.policies[0].lists.push(ListInput {
        name: "typed".into(),
        action: Action::Block,
        syntax: RuleSyntax::AdguardV4,
        rules: "||typed.test^$dnstype=AAAA\n/^192\\.0\\.2\\.1$/$dnstype=A".into(),
    });
    config.assertions.push(rustwalld_dns_policy::Assertion {
        client: "127.0.0.1".parse().unwrap(),
        domain: "typed.test".into(),
        qtype: 28,
        expected: Action::Block,
    });
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        200
    );
    let generation = harness.state.control.engine().active().generation();
    let trace: Value = harness
        .get("/api/v1/explain?client=127.0.0.1&domain=typed.test&qtype=28")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(trace["decision"]["action"], "block");
    assert_eq!(trace["rule"]["dnstype"]["include"], serde_json::json!([28]));
    let trace:Value=harness.get("/api/v1/explain?client=127.0.0.1&domain=typed.test&qtype=1&answer_value=192.0.2.1&answer_type=1").await.json().await.unwrap();
    assert_eq!(trace["decision"]["action"], "block");
    assert_eq!(trace["rule"]["matcher"], "regex");
    assert_eq!(
        harness
            .get("/api/v1/explain?client=127.0.0.1&domain=typed.test&answer_value=192.0.2.1")
            .await
            .status(),
        422
    );
    // A real response-value block is recorded separately from the original A question.
    assert_eq!(
        harness.dns("value.test").await.response_code,
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
                .find(|event| event["domain"] == "value.test")
            {
                break event;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(event["matched_type"], 1);
    assert_eq!(event["qtype"], 1);
    assert_eq!(event["matched_domain"], "192.0.2.1");
    let mut next = config.clone();
    next.policies[0].lists[1].rules =
        "||typed.test^$dnstype=AAAA\n/^192\\.0\\.2\\.1$/$dnstype=AAAA".into();
    assert_eq!(
        harness.send("/api/v1/shadow", &next, false).await.status(),
        200
    );
    shadow_action(&harness, true).await;
    assert_eq!(
        harness.dns("value.test").await.response_code,
        ResponseCode::NoError
    );
    let recorded: Value = harness
        .get(&format!("/api/v1/queries/{}/explain", event["id"]))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(recorded["event"]["matched_type"], 1);
    assert_eq!(
        recorded["rule"]["dnstype"]["include"],
        serde_json::json!([1])
    );
    let mut invalid = next.clone();
    invalid.assertions.last_mut().unwrap().qtype = 1;
    assert_eq!(
        harness
            .send("/api/v1/config", &invalid, true)
            .await
            .status(),
        422
    );
    let active = harness.state.control.engine().active().generation();
    let boot = harness
        .state
        .control
        .store()
        .bootstrap("ignored".into())
        .await
        .unwrap();
    let recovered =
        PolicySnapshot::compile(serde_json::from_str(&boot.config).unwrap(), active).unwrap();
    assert_eq!(
        recovered
            .explain_query("127.0.0.1".parse().unwrap(), "typed.test", RecordType::AAAA)
            .unwrap()
            .decision
            .action,
        Action::Block
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
        harness.dns("value.test").await.response_code,
        ResponseCode::NXDomain
    );
    harness.shutdown().await;
    mock.abort();
}
