#![allow(clippy::unwrap_used)]
use super::*;

#[tokio::test]
async fn temporary_exception_api_shadow_history_sqlite_failure_and_expired_rollback() {
    let harness = Harness::start().await;
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let mock = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        loop {
            let (len, peer) = upstream.recv_from(&mut buffer).await.unwrap();
            let request = Message::from_vec(&buffer[..len]).unwrap();
            let mut response = rustwalld_dns_core::reply(&request, ResponseCode::NoError);
            response.add_answer(hickory_proto::rr::Record::from_rdata(
                request.queries[0].name().clone(),
                60,
                hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(
                    "192.0.2.1".parse().unwrap(),
                )),
            ));
            upstream
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    assert_eq!(
        reqwest::get(format!("{}/api/v1/temporary-exceptions", harness.base))
            .await
            .unwrap()
            .status(),
        401
    );
    let expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3;
    let mut config = harness.state.control.engine.active().config().clone();
    config.upstreams[0].addresses = vec![upstream_addr];
    config.policies[0]
        .temporary_exceptions
        .push(rustwalld_dns_policy::TemporaryException {
            name: "repair".into(),
            domain: "ADS.TEST.".into(),
            expires_at: expiry,
        });
    config.assertions.push(rustwalld_dns_policy::Assertion {
        client: "127.0.0.1".parse().unwrap(),
        domain: "ads.test".into(),
        expected: Action::Block,
    });
    assert_eq!(
        harness
            .send("/api/v1/policy/test", &config, false)
            .await
            .status(),
        200
    );
    assert_eq!(
        harness
            .send("/api/v1/shadow", &config, false)
            .await
            .status(),
        200
    );
    assert_eq!(
        harness.dns("ads.test.").await.metadata.response_code,
        ResponseCode::NXDomain
    );
    let promoted = reqwest::Client::new()
        .post(format!("{}/api/v1/shadow/promote", harness.base))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(promoted.status(), 200);
    let generation = harness.state.control.engine.active().generation();
    let response = harness.dns("ads.test.").await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(response.answers[0].ttl <= 3);
    let explanation: Value = harness
        .get("/api/v1/explain?client=127.0.0.1&domain=ads.test")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(explanation["temporary_exception"]["name"], "repair");
    let live: Value = harness
        .get("/api/v1/temporary-exceptions")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(live["exceptions"][0]["active"], true);
    timeout(Duration::from_secs(2), async {
        loop {
            let history: Value = harness.get("/api/v1/queries").await.json().await.unwrap();
            if history
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["temporary_exception"] == 0)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let database = rusqlite::Connection::open(&harness.path).unwrap();
    database.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let mut revoked = config.clone();
    revoked.policies[0].temporary_exceptions.clear();
    assert_eq!(
        harness
            .send("/api/v1/config", &revoked, true)
            .await
            .status(),
        503
    );
    let remaining = (std::time::UNIX_EPOCH + Duration::from_secs(expiry))
        .duration_since(std::time::SystemTime::now())
        .unwrap_or_default();
    tokio::time::sleep(remaining + Duration::from_millis(20)).await;
    for _ in 0..100 {
        assert_eq!(
            harness.dns("ads.test.").await.metadata.response_code,
            ResponseCode::NXDomain
        );
    }
    let expired: Value = harness
        .get("/api/v1/temporary-exceptions")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(expired["generation"], generation);
    assert_eq!(expired["exceptions"][0]["active"], false);
    database.execute_batch("ROLLBACK").unwrap();
    drop(database);
    let rolled = reqwest::Client::new()
        .post(format!(
            "{}/api/v1/revisions/{generation}/rollback",
            harness.base
        ))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(rolled.status(), 200);
    assert!(harness.state.control.engine.active().generation() > generation);
    assert_eq!(
        harness.state.control.engine.active().config().policies[0].temporary_exceptions[0]
            .expires_at,
        expiry
    );
    assert_eq!(
        harness.dns("ads.test.").await.metadata.response_code,
        ResponseCode::NXDomain
    );
    let report = rustwalld_dns::maintenance::verify(&harness.path).unwrap();
    assert_eq!(report.schema, 2);
    mock.abort();
    harness.shutdown().await;
}
