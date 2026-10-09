#![allow(clippy::unwrap_used)]
use super::*;

#[tokio::test]
async fn temporary_exact_allow_caps_udp_tcp_cache_ttls_and_expires_without_telemetry() {
    let mock = Mock::start(false, false).await;
    let expiry = exception_expiry(2);
    let mut config = temporary_config(&mock, expiry);
    config.allowed_clients = vec!["127.0.0.0/8".parse().unwrap()];
    config.policies.push(PolicyConfig {
        name: "permanent".into(),
        upstream: "default".into(),
        lists: vec![],
        rewrites: vec![],
        temporary_exceptions: vec![],
    });
    config.bindings.push(Binding {
        name: "Other client".into(),
        network: "127.0.0.2/32".parse().unwrap(),
        policy: "permanent".into(),
        metadata: None,
    });
    let mut baseline = config.clone();
    baseline.policies[0].temporary_exceptions.clear();
    let (telemetry, _receiver) = Telemetry::channel(1);
    let engine = Arc::new(Engine::new(
        PolicySnapshot::compile(baseline, 1).unwrap(),
        32,
        32,
        16,
        telemetry,
    ));
    let server = Server::bind(
        ServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        },
        engine.handle(),
    )
    .await
    .unwrap();
    let addr = server.local_addr().unwrap();
    let cancel = CancellationToken::new();
    let task = tokio::spawn(server.run(cancel.clone()));
    let request = query(RecordType::A);
    assert_eq!(
        udp_query(addr, &request).await.metadata.response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(
        udp_query(addr, &request).await.metadata.response_code,
        ResponseCode::NXDomain
    );
    engine
        .active
        .store(Arc::new(PolicySnapshot::compile(config, 2).unwrap()));
    let response = udp_query(addr, &request).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(response.answers[0].ttl <= 2);
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let bytes = request.to_vec().unwrap();
    stream.write_u16(bytes.len() as u16).await.unwrap();
    stream.write_all(&bytes).await.unwrap();
    let length = stream.read_u16().await.unwrap();
    let mut output = vec![0; length as usize];
    stream.read_exact(&mut output).await.unwrap();
    assert!(Message::from_vec(&output).unwrap().answers[0].ttl <= 2);
    // Same profile/generation cache, another permanent policy: no TTL contamination.
    let other = engine
        .answer(&bytes, "127.0.0.2".parse().unwrap(), Transport::Udp)
        .await
        .unwrap();
    assert!(Message::from_vec(&other).unwrap().answers[0].ttl >= 50);
    assert_eq!(mock.hits.load(Ordering::Relaxed), 1);
    let mut subdomain = request.clone();
    subdomain.queries[0].set_name(Name::from_ascii("sub.test.example.").unwrap());
    assert_eq!(
        udp_query(addr, &subdomain).await.metadata.response_code,
        ResponseCode::NXDomain
    );
    wait_exception_expiry(expiry).await;
    for _ in 0..3 {
        assert_eq!(
            udp_query(addr, &request).await.metadata.response_code,
            ResponseCode::NXDomain
        );
    }
    assert_eq!(mock.hits.load(Ordering::Relaxed), 1);
    assert!(!engine.resolver().cache.is_empty());
    assert!(
        engine
            .telemetry()
            .metrics
            .dropped_events
            .load(Ordering::Relaxed)
            > 0
    );
    cancel.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn temporary_coalesced_waiters_and_pinned_generation_cannot_answer_after_expiry() {
    let mock = Mock::with_delay(false, false, Duration::from_secs(3)).await;
    let expiry = exception_expiry(2);
    let config = temporary_config(&mock, expiry);
    let (telemetry, mut receiver) = Telemetry::channel(32);
    let engine = Arc::new(Engine::new(
        PolicySnapshot::compile(config.clone(), 1).unwrap(),
        32,
        32,
        32,
        telemetry,
    ));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let engine = engine.clone();
        tasks.push(tokio::spawn(async move {
            Message::from_vec(
                &engine
                    .answer(
                        &query(RecordType::A).to_vec().unwrap(),
                        "127.0.0.1".parse().unwrap(),
                        Transport::Udp,
                    )
                    .await
                    .unwrap(),
            )
            .unwrap()
        }));
    }
    timeout(Duration::from_secs(1), async {
        while engine.resolver().metrics.coalesced.load(Ordering::Relaxed) < 15 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut replacement = config;
    replacement.policies[0].temporary_exceptions.clear();
    engine
        .active
        .store(Arc::new(PolicySnapshot::compile(replacement, 2).unwrap()));
    for task in tasks {
        assert_eq!(
            task.await.unwrap().metadata.response_code,
            ResponseCode::NXDomain
        );
    }
    assert_eq!(mock.hits.load(Ordering::Relaxed), 1);
    assert_eq!(
        engine
            .resolver()
            .metrics
            .upstream_lookups
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        engine.telemetry().metrics.failures.load(Ordering::Relaxed),
        0
    );
    for _ in 0..16 {
        let event = receiver.recv().await.unwrap();
        assert_eq!(event.generation, 1);
        assert!(event.temporary_exception.is_none());
        assert_eq!(event.decision.action, rustwalld_dns_filter::Action::Block);
    }
    engine.resolver().shutdown();
}

#[tokio::test]
async fn shadow_temporary_allows_expire_without_enforcement_or_reload() {
    let mock = Mock::start(false, false).await;
    let expiry = exception_expiry(2);
    let candidate = temporary_config(&mock, expiry);
    let mut active = candidate.clone();
    active.policies[0].temporary_exceptions.clear();
    let (telemetry, mut receiver) = Telemetry::channel(8);
    let engine = Engine::new(
        PolicySnapshot::compile(active, 1).unwrap(),
        32,
        32,
        8,
        telemetry,
    );
    engine.shadow.store(Some(Arc::new(
        PolicySnapshot::compile(candidate, 2).unwrap(),
    )));
    let bytes = query(RecordType::A).to_vec().unwrap();
    let client = "127.0.0.1".parse().unwrap();
    engine.answer(&bytes, client, Transport::Udp).await.unwrap();
    let shadow = receiver.recv().await.unwrap().shadow.unwrap();
    assert!(shadow.differs);
    assert_eq!(shadow.temporary_exception, Some(0));
    assert_eq!(shadow.decision.action, rustwalld_dns_filter::Action::Allow);
    wait_exception_expiry(expiry).await;
    engine.answer(&bytes, client, Transport::Udp).await.unwrap();
    let shadow = receiver.recv().await.unwrap().shadow.unwrap();
    assert!(!shadow.differs);
    assert!(shadow.temporary_exception.is_none());
    assert_eq!(mock.hits.load(Ordering::Relaxed), 0);
}
