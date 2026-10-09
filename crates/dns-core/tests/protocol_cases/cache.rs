#![allow(clippy::unwrap_used)]
use super::*;

#[tokio::test]
async fn cached_answer_restores_client_id_and_skips_upstream() {
    let mock = Mock::start(false, false).await;
    let (addr, cancel, task) = server(vec![mock.addr]).await;
    let mut request = query(RecordType::A);
    let first = udp_query(addr, &request).await;
    request.metadata.id = 99;
    let second = udp_query(addr, &request).await;
    assert_eq!(second.metadata.id, 99);
    assert_eq!(first.answers, second.answers);
    assert_eq!(mock.hits.load(Ordering::Relaxed), 1);
    cancel.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn normalized_upstream_flight_preserves_each_clients_question_and_size() {
    use rustwalld_dns_core::telemetry::QuerySource;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut config = PolicyConfigSet::default();
    config.upstreams[0].addresses = vec![socket.local_addr().unwrap()];
    config.upstreams[0].timeout_ms = 3000;
    let (telemetry, mut events) = Telemetry::channel(8);
    let engine = Arc::new(Engine::new(
        PolicySnapshot::compile(config, 1).unwrap(),
        32,
        32,
        1,
        telemetry,
    ));
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let release = gate.clone();
    let (observed, received) = tokio::sync::oneshot::channel();
    let upstream = tokio::spawn(async move {
        let mut buffer = vec![0; 4096];
        let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
        let request = Message::from_vec(&buffer[..len]).unwrap();
        observed.send(request.clone()).unwrap();
        release.acquire().await.unwrap().forget();
        socket
            .send_to(&answer(&request).to_vec().unwrap(), peer)
            .await
            .unwrap();
    });
    let mut request = query(RecordType::A);
    request.queries[0].set_name(
        Name::from_labels([
            vec![b'A'; 63],
            vec![b'B'; 63],
            vec![b'C'; 63],
            vec![b'D'; 61],
        ])
        .unwrap(),
    );
    request.metadata.authentic_data = true;
    request.metadata.checking_disabled = true;
    let client = "127.0.0.1".parse().unwrap();
    let initial = {
        let engine = engine.clone();
        let bytes = request.to_vec().unwrap();
        tokio::spawn(async move { engine.answer(&bytes, client, false).await.unwrap() })
    };
    let forwarded = timeout(Duration::from_secs(1), received)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        forwarded.queries[0].name().to_ascii(),
        request.queries[0].name().to_lowercase().to_ascii()
    );
    assert!(forwarded.metadata.recursion_desired);
    assert!(forwarded.metadata.checking_disabled);
    assert!(!forwarded.metadata.authentic_data);
    let edns = forwarded.edns.as_ref().unwrap();
    assert_eq!(edns.max_payload(), 1232);
    assert!(!edns.flags().dnssec_ok);
    assert!(edns.options().as_ref().is_empty());

    let mut waiters = Vec::new();
    for (id, lowercase, extended, tcp) in [
        (43, true, false, false),
        (44, false, true, false),
        (45, false, false, true),
    ] {
        let mut caller = request.clone();
        caller.metadata.id = id;
        caller.metadata.authentic_data = false;
        if lowercase {
            let name = caller.queries[0].name().to_lowercase();
            caller.queries[0].set_name(name);
        }
        if extended {
            let mut edns = hickory_proto::op::Edns::new();
            edns.set_max_payload(4096);
            caller.edns = Some(edns);
        }
        let engine = engine.clone();
        waiters.push(tokio::spawn(async move {
            let response = Message::from_vec(
                &engine
                    .answer(&caller.to_vec().unwrap(), client, tcp)
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(response.metadata.id, caller.metadata.id);
            assert_eq!(response.queries, caller.queries);
            assert_eq!(
                response.queries[0].name().to_ascii(),
                caller.queries[0].name().to_ascii()
            );
            assert!(response.metadata.checking_disabled);
            assert!(!response.metadata.authentic_data);
            // Hickory emits a full name before trying compression. Even the
            // lowercase maximum-length answer can exceed legacy UDP capacity
            // during that write; EDNS and TCP must receive the complete answer.
            assert_eq!(
                response.metadata.truncation,
                !extended && !tcp,
                "client {id}"
            );
            assert_eq!(response.answers.len(), usize::from(extended || tcp));
            assert_eq!(response.edns.is_some(), extended);
            if let Some(edns) = response.edns {
                assert_eq!(edns.max_payload(), 1232);
                assert!(!edns.flags().dnssec_ok);
            }
        }));
    }
    timeout(Duration::from_secs(1), async {
        while engine.resolver().metrics.coalesced.load(Ordering::Relaxed) != 3 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    gate.add_permits(1);
    let first = Message::from_vec(&initial.await.unwrap()).unwrap();
    assert_eq!(first.metadata.id, request.metadata.id);
    assert_eq!(
        first.queries[0].name().to_ascii(),
        request.queries[0].name().to_ascii()
    );
    assert!(first.metadata.truncation);
    assert!(first.answers.is_empty());
    for waiter in waiters {
        waiter.await.unwrap();
    }
    upstream.await.unwrap();
    // The mock has closed. The same raw request must still hit the response
    // cache without losing the original question or legacy truncation behavior.
    let cached = Message::from_vec(
        &engine
            .answer(&request.to_vec().unwrap(), client, false)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(cached.metadata.truncation);
    assert_eq!(
        cached.queries[0].name().to_ascii(),
        request.queries[0].name().to_ascii()
    );
    assert_eq!(
        engine
            .resolver()
            .metrics
            .upstream_lookups
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        engine.resolver().metrics.cache_hits.load(Ordering::Relaxed),
        1
    );
    let mut sources = [0; 3];
    for _ in 0..5 {
        let event = events.try_recv().unwrap();
        assert_eq!(
            event.domain,
            forwarded.queries[0].name().to_ascii().trim_end_matches('.')
        );
        sources[match event.source {
            QuerySource::Upstream => 0,
            QuerySource::Coalesced => 1,
            QuerySource::Cache => 2,
            other => panic!("unexpected source: {other:?}"),
        }] += 1;
    }
    assert_eq!(sources, [1, 3, 1]);
}

#[tokio::test]
async fn raw_client_requests_keep_flag_type_and_upstream_identity_cache_partitions() {
    use rustwalld_dns_core::telemetry::QuerySource;
    let mock = Mock::start(false, false).await;
    let mut config = PolicyConfigSet {
        allowed_clients: vec!["127.0.0.0/8".parse().unwrap()],
        ..Default::default()
    };
    config.upstreams[0].addresses = vec![mock.addr];
    // A different address list is a different upstream identity, even though
    // the first (answering) address is the same mock.
    let mut other = config.upstreams[0].clone();
    other.name = "second".into();
    other.addresses.push("127.0.0.1:9".parse().unwrap());
    config.upstreams.push(other);
    let mut policy = config.policies[0].clone();
    policy.name = "second".into();
    policy.upstream = "second".into();
    config.policies.push(policy);
    config.bindings.push(Binding {
        name: "second client".into(),
        network: "127.0.0.2/32".parse().unwrap(),
        policy: "second".into(),
        metadata: None,
    });
    let (telemetry, mut events) = Telemetry::channel(32);
    let engine = Engine::new(
        PolicySnapshot::compile(config.clone(), 1).unwrap(),
        32,
        32,
        4,
        telemetry,
    );
    let client = "127.0.0.1".parse().unwrap();
    let mut expected = 0;
    let mut request = query(RecordType::A);
    for kind in [RecordType::A, RecordType::AAAA] {
        for dnssec in [false, true] {
            for checking_disabled in [false, true] {
                request.queries[0].set_query_type(kind);
                request.queries[0].set_name(Name::from_ascii("MiXeD.Example.").unwrap());
                request.metadata.checking_disabled = checking_disabled;
                request.metadata.authentic_data = true;
                let mut edns = hickory_proto::op::Edns::new();
                edns.set_dnssec_ok(dnssec);
                edns.set_max_payload(512);
                request.edns = Some(edns);
                for source in [QuerySource::Upstream, QuerySource::Cache] {
                    let response = Message::from_vec(
                        &engine
                            .answer(&request.to_vec().unwrap(), client, false)
                            .await
                            .unwrap(),
                    )
                    .unwrap();
                    assert_eq!(response.answers[0].data.record_type(), kind);
                    assert_eq!(response.metadata.checking_disabled, checking_disabled);
                    assert!(!response.metadata.authentic_data);
                    assert_eq!(response.edns.unwrap().flags().dnssec_ok, dnssec);
                    assert_eq!(events.try_recv().unwrap().source, source);
                    request.queries[0].set_name(Name::from_ascii("mixed.example.").unwrap());
                    request.edns.as_mut().unwrap().set_max_payload(4096);
                    request.metadata.authentic_data = false;
                }
                expected += 1;
                assert_eq!(mock.hits.load(Ordering::Relaxed), expected);
            }
        }
    }
    for source in [QuerySource::Upstream, QuerySource::Cache] {
        engine
            .answer(
                &request.to_vec().unwrap(),
                "127.0.0.2".parse().unwrap(),
                true,
            )
            .await
            .unwrap();
        assert_eq!(events.try_recv().unwrap().source, source);
    }
    assert_eq!(mock.hits.load(Ordering::Relaxed), expected + 1);
    // Publishing unchanged upstream profiles keeps their cached answers.
    engine.active.store(Arc::new(
        PolicySnapshot::compile(config.clone(), 2).unwrap(),
    ));
    for _ in 0..2 {
        engine
            .answer(&request.to_vec().unwrap(), client, false)
            .await
            .unwrap();
        let event = events.try_recv().unwrap();
        assert_eq!(event.source, QuerySource::Cache);
        assert_eq!(event.generation, 2);
    }
    assert_eq!(mock.hits.load(Ordering::Relaxed), expected + 1);
    // Changing a profile's content selects a fresh partition for its policies.
    config.upstreams[0]
        .addresses
        .push("127.0.0.1:9".parse().unwrap());
    config.upstreams[0]
        .addresses
        .push("127.0.0.1:7".parse().unwrap());
    engine
        .active
        .store(Arc::new(PolicySnapshot::compile(config, 3).unwrap()));
    for source in [QuerySource::Upstream, QuerySource::Cache] {
        engine
            .answer(&request.to_vec().unwrap(), client, false)
            .await
            .unwrap();
        let event = events.try_recv().unwrap();
        assert_eq!(event.source, source);
        assert_eq!(event.generation, 3);
    }
    assert_eq!(mock.hits.load(Ordering::Relaxed), expected + 2);
}

#[tokio::test]
async fn normalized_event_names_preserve_wire_questions_and_all_decision_paths() {
    use rustwalld_dns_core::telemetry::QuerySource;
    use rustwalld_dns_filter::{Action, ListInput};
    let mock = Mock::start(false, false).await;
    let mut config = PolicyConfigSet::default();
    config.upstreams[0].addresses = vec![mock.addr];
    config.policies[0].lists.push(ListInput {
        name: "deny".into(),
        action: Action::Block,
        rules: "blocked.test\ntemporary.test".into(),
    });
    config.policies[0]
        .rewrites
        .push(rustwalld_dns_policy::Rewrite {
            domain: "rewritten.test".into(),
            addresses: vec!["192.0.2.2".parse().unwrap()],
            ttl: 60,
        });
    config.policies[0]
        .temporary_exceptions
        .push(TemporaryException {
            name: "temporary".into(),
            domain: "temporary.test".into(),
            expires_at: exception_expiry(3600),
        });
    let mut shadow_config = config.clone();
    shadow_config.policies[0].lists[0]
        .rules
        .push_str("\nmixed.example");
    let (telemetry, mut receiver) = Telemetry::channel(1);
    let engine = Engine::new(
        PolicySnapshot::compile(config, 1).unwrap(),
        100,
        100,
        8,
        telemetry,
    );
    engine.shadow.store(Some(Arc::new(
        PolicySnapshot::compile(shadow_config, 2).unwrap(),
    )));
    let longest = format!(
        "{}.{}.{}.{}.",
        "A".repeat(63),
        "B".repeat(63),
        "C".repeat(63),
        "D".repeat(61)
    );
    let long_normalized = longest.trim_end_matches('.').to_ascii_lowercase();
    let cases = [
        (
            Name::from_ascii("MiXeD.Example.").unwrap(),
            "mixed.example",
            QuerySource::Upstream,
        ),
        (
            Name::from_ascii(r"A\.B.Example.").unwrap(),
            r"a\.b.example",
            QuerySource::Upstream,
        ),
        (
            Name::from_labels([b"A\\B".as_slice(), b"Example".as_slice()]).unwrap(),
            r"a\\b.example",
            QuerySource::Upstream,
        ),
        (
            Name::from_labels([&[0, 255][..], b"Example".as_slice()]).unwrap(),
            r"\000\377.example",
            QuerySource::Upstream,
        ),
        (Name::root(), "", QuerySource::Upstream),
        (
            Name::from_ascii(longest).unwrap(),
            long_normalized.as_str(),
            QuerySource::Upstream,
        ),
        (
            Name::from_ascii("Blocked.Test.").unwrap(),
            "blocked.test",
            QuerySource::Blocked,
        ),
        (
            Name::from_ascii("ReWritten.Test.").unwrap(),
            "rewritten.test",
            QuerySource::Rewrite,
        ),
        (
            Name::from_ascii("Temporary.Test.").unwrap(),
            "temporary.test",
            QuerySource::Upstream,
        ),
    ];
    for (name, expected_domain, first_source) in cases {
        for cached in [false, true] {
            let mut request = query(RecordType::A);
            let mut edns = hickory_proto::op::Edns::new();
            edns.set_max_payload(1232);
            request.edns = Some(edns);
            let name = if cached {
                name.to_lowercase()
            } else {
                name.clone()
            };
            request.queries[0].set_name(name);
            request.metadata.id = if cached { 99 } else { 42 };
            let response = Message::from_vec(
                &engine
                    .answer(
                        &request.to_vec().unwrap(),
                        "::ffff:127.0.0.1".parse().unwrap(),
                        cached,
                    )
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(response.metadata.id, request.metadata.id);
            assert_eq!(
                response.queries[0].name().to_ascii(),
                request.queries[0].name().to_ascii()
            );
            let blocked = first_source == QuerySource::Blocked;
            assert_eq!(
                response.metadata.response_code,
                if blocked {
                    ResponseCode::NXDomain
                } else {
                    ResponseCode::NoError
                }
            );
            assert_eq!(response.answers.len(), usize::from(!blocked));
            let event = receiver.try_recv().unwrap();
            assert_eq!(event.domain, expected_domain);
            assert_eq!(
                event.client,
                "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
            );
            assert_eq!(event.generation, 1);
            assert_eq!(event.policy, 0);
            assert_eq!(event.qtype, u16::from(RecordType::A));
            assert_eq!(
                event.response_code,
                u16::from(response.metadata.response_code)
            );
            let source = if cached && first_source == QuerySource::Upstream {
                QuerySource::Cache
            } else {
                first_source
            };
            assert_eq!(event.source, source);
            assert_eq!(
                event.decision_cached,
                cached
                    && first_source != QuerySource::Rewrite
                    && expected_domain != "temporary.test"
            );
            assert_eq!(
                event.temporary_exception,
                (expected_domain == "temporary.test").then_some(0)
            );
            let shadow = event.shadow.unwrap();
            assert_eq!(shadow.generation, 2);
            assert_eq!(shadow.differs, expected_domain == "mixed.example");
        }
    }
    // A maximum-length mixed-case question plus its canonical answer can
    // exceed legacy UDP's 512 bytes. Truncation still retains the original
    // question and emits the same normalized telemetry domain.
    let mut legacy = query(RecordType::A);
    legacy.queries[0].set_name(
        Name::from_ascii(format!(
            "{}.{}.{}.{}.",
            "A".repeat(63),
            "B".repeat(63),
            "C".repeat(63),
            "D".repeat(61)
        ))
        .unwrap(),
    );
    let response = Message::from_vec(
        &engine
            .answer(
                &legacy.to_vec().unwrap(),
                "127.0.0.1".parse().unwrap(),
                false,
            )
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(response.metadata.truncation);
    assert!(response.answers.is_empty());
    assert_eq!(
        response.queries[0].name().to_ascii(),
        legacy.queries[0].name().to_ascii()
    );
    let event = receiver.try_recv().unwrap();
    assert_eq!(event.domain, long_normalized);
    assert_eq!(event.source, QuerySource::Cache);
    assert_eq!(mock.hits.load(Ordering::Relaxed), 7);
    assert_eq!(
        engine
            .telemetry()
            .metrics
            .dropped_events
            .load(Ordering::Relaxed),
        0
    );
    let invalid = Message::query().to_vec().unwrap();
    assert_eq!(
        Message::from_vec(
            &engine
                .answer(&invalid, "127.0.0.1".parse().unwrap(), false)
                .await
                .unwrap()
        )
        .unwrap()
        .metadata
        .response_code,
        ResponseCode::FormErr
    );
    assert!(receiver.try_recv().is_err());
    engine.resolver().shutdown();
}

#[tokio::test]
async fn full_and_closed_event_queues_preserve_replies_and_drop_accounting() {
    let mock = Mock::start(false, false).await;
    let (engine, mut receiver) = engine_for(&mock, 1, 8);
    let mut config = engine.active.load().config().clone();
    config.policies[0]
        .lists
        .push(rustwalld_dns_filter::ListInput {
            name: "deny".into(),
            action: rustwalld_dns_filter::Action::Block,
            rules: "example".into(),
        });
    engine
        .active
        .store(Arc::new(PolicySnapshot::compile(config, 2).unwrap()));
    let bytes = query(RecordType::A).to_vec().unwrap();
    for _ in 0..2 {
        let response = Message::from_vec(
            &engine
                .answer(&bytes, "127.0.0.1".parse().unwrap(), false)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    }
    assert_eq!(
        engine
            .telemetry()
            .metrics
            .dropped_events
            .load(Ordering::Relaxed),
        1
    );
    assert_eq!(receiver.try_recv().unwrap().domain, "test.example");
    drop(receiver);
    let response = Message::from_vec(
        &engine
            .answer(&bytes, "127.0.0.1".parse().unwrap(), true)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(
        engine
            .telemetry()
            .metrics
            .dropped_events
            .load(Ordering::Relaxed),
        2
    );
    assert_eq!(mock.hits.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn simultaneous_misses_coalesce_and_initiator_cancellation_is_safe() {
    let mock = Mock::with_delay(false, false, Duration::from_millis(80)).await;
    let (engine, _receiver) = engine_for(&mock, 1000, 32);
    let bytes = query(RecordType::A).to_vec().unwrap();
    let client = "127.0.0.1".parse().unwrap();
    let initial = {
        let engine = engine.clone();
        let bytes = bytes.clone();
        tokio::spawn(async move { engine.answer(&bytes, client, false).await })
    };
    timeout(Duration::from_secs(1), async {
        while mock.hits.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    initial.abort();
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..1000 {
        let engine = engine.clone();
        let bytes = bytes.clone();
        tasks.spawn(async move { engine.answer(&bytes, client, false).await.unwrap() });
    }
    while let Some(result) = tasks.join_next().await {
        assert_eq!(
            Message::from_vec(&result.unwrap()).unwrap().answers.len(),
            1
        );
    }
    assert_eq!(mock.hits.load(Ordering::Relaxed), 1);
    assert!(engine.resolver().metrics.coalesced.load(Ordering::Relaxed) > 0);
    timeout(Duration::from_secs(1), async {
        while engine.resolver().inflight() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn inflight_limit_and_telemetry_overload_do_not_stall_dns() {
    let mock = Mock::with_delay(false, false, Duration::from_millis(80)).await;
    let (engine, _receiver) = engine_for(&mock, 1, 1);
    let client = "127.0.0.1".parse().unwrap();
    let bytes = query(RecordType::A).to_vec().unwrap();
    let initial = {
        let engine = engine.clone();
        let bytes = bytes.clone();
        tokio::spawn(async move { engine.answer(&bytes, client, false).await })
    };
    timeout(Duration::from_secs(1), async {
        while mock.hits.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let other = query(RecordType::AAAA).to_vec().unwrap();
    let response = engine.answer(&other, client, false).await.unwrap();
    assert_eq!(
        Message::from_vec(&response).unwrap().metadata.response_code,
        ResponseCode::ServFail
    );
    assert!(engine.resolver().inflight() <= 1);
    initial.await.unwrap();
    for _ in 0..10 {
        assert!(engine.answer(&bytes, client, false).await.is_some());
    }
    assert!(
        engine
            .telemetry()
            .metrics
            .dropped_events
            .load(Ordering::Relaxed)
            > 0
    );
}

#[tokio::test]
async fn tls_forwarding_filter_cache_generation_and_retirement() {
    let mock = tls_fixture::Mock::start(0).await;
    let mut config = PolicyConfigSet::default();
    config.upstreams[0].addresses = vec![mock.address];
    config.upstreams[0].transport = mock.transport.clone();
    config.upstreams[0].timeout_ms = 200;
    config.policies[0]
        .lists
        .push(rustwalld_dns_filter::ListInput {
            name: "fixture".into(),
            action: rustwalld_dns_filter::Action::Block,
            rules: "blocked.test".into(),
        });
    let (telemetry, _receiver) = Telemetry::channel(100);
    let engine = Arc::new(Engine::new(
        PolicySnapshot::compile(config.clone(), 1).unwrap(),
        100,
        100,
        8,
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
    for _ in 0..3 {
        let response = udp_query(addr, &request).await;
        assert_eq!(response.metadata.id, request.metadata.id);
        assert_eq!(response.answers.len(), 1);
    }
    assert_eq!(mock.queries.load(Ordering::SeqCst), 1);
    let mut blocked = request.clone();
    blocked.queries[0].set_name(Name::from_ascii("blocked.test.").unwrap());
    assert_eq!(
        udp_query(addr, &blocked).await.metadata.response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(mock.queries.load(Ordering::SeqCst), 1);
    // Concurrent identical TLS misses still use the resolver's single-flight table.
    mock.mode.store(8, Ordering::SeqCst);
    let mut concurrent = request.clone();
    concurrent.queries[0].set_name(Name::from_ascii("coalesced.test.").unwrap());
    let mut tasks = vec![];
    for i in 0..16 {
        let mut concurrent = concurrent.clone();
        concurrent.metadata.id = i;
        tasks.push(tokio::spawn(async move {
            let result = udp_query(addr, &concurrent).await;
            assert_eq!(result.metadata.id, i);
            assert_eq!(result.answers.len(), 1);
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(mock.queries.load(Ordering::SeqCst), 2);
    mock.mode.store(0, Ordering::SeqCst);
    // Changed identity must not reuse cached answers or the old authenticated socket.
    if let rustwalld_dns_resolver::UpstreamTransport::Tls { server_name, .. } =
        &mut config.upstreams[0].transport
    {
        *server_name = "wrong.test".into();
    }
    let retired = engine.active.swap(Arc::new(
        PolicySnapshot::compile(config.clone(), 2).unwrap(),
    ));
    let weak = Arc::downgrade(&retired);
    drop(retired);
    assert!(weak.upgrade().is_none());
    assert_eq!(
        udp_query(addr, &request).await.metadata.response_code,
        ResponseCode::ServFail
    );
    assert_eq!(mock.queries.load(Ordering::SeqCst), 2);
    // Restoring the original identity may reuse its still-valid cached answer;
    // a different question still needs the new authenticated connection.
    config.upstreams[0].transport = mock.transport.clone();
    engine
        .active
        .store(Arc::new(PolicySnapshot::compile(config, 3).unwrap()));
    assert_eq!(udp_query(addr, &request).await.answers.len(), 1);
    assert_eq!(mock.queries.load(Ordering::SeqCst), 2);
    let mut fresh = request.clone();
    fresh.queries[0].set_name(Name::from_ascii("fresh.test.").unwrap());
    assert_eq!(udp_query(addr, &fresh).await.answers.len(), 1);
    assert_eq!(mock.queries.load(Ordering::SeqCst), 3);
    cancel.cancel();
    timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn https_filter_cache_coalescing_generation_and_shutdown() {
    let mock = https_fixture::Mock::start(0).await;
    let mut config = PolicyConfigSet::default();
    config.upstreams[0].addresses = vec![mock.address];
    config.upstreams[0].transport = mock.transport.clone();
    config.upstreams[0].timeout_ms = 200;
    config.policies[0]
        .lists
        .push(rustwalld_dns_filter::ListInput {
            name: "fixture".into(),
            action: rustwalld_dns_filter::Action::Block,
            rules: "blocked.test".into(),
        });
    let (telemetry, _receiver) = Telemetry::channel(100);
    let engine = Arc::new(Engine::new(
        PolicySnapshot::compile(config.clone(), 1).unwrap(),
        100,
        100,
        8,
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
    let address = server.local_addr().unwrap();
    let cancel = CancellationToken::new();
    let task = tokio::spawn(server.run(cancel.clone()));
    let request = query(RecordType::A);
    for _ in 0..3 {
        let response = udp_query(address, &request).await;
        assert_eq!(response.metadata.id, 42);
        assert_eq!(response.answers.len(), 1);
    }
    assert_eq!(mock.queries.load(Ordering::SeqCst), 1);
    let mut blocked = request.clone();
    blocked.queries[0].set_name(Name::from_ascii("blocked.test.").unwrap());
    assert_eq!(
        udp_query(address, &blocked).await.metadata.response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(mock.queries.load(Ordering::SeqCst), 1);
    mock.mode.store(17, Ordering::SeqCst);
    let mut concurrent = request.clone();
    concurrent.queries[0].set_name(Name::from_ascii("coalesced.test.").unwrap());
    let mut tasks = vec![];
    for id in 0..16 {
        let mut q = concurrent.clone();
        q.metadata.id = id;
        tasks.push(tokio::spawn(async move {
            let r = udp_query(address, &q).await;
            assert_eq!(r.metadata.id, id);
            assert_eq!(r.answers.len(), 1);
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(mock.queries.load(Ordering::SeqCst), 2);
    mock.mode.store(0, Ordering::SeqCst);
    if let rustwalld_dns_resolver::UpstreamTransport::Https { server_name, .. } =
        &mut config.upstreams[0].transport
    {
        *server_name = "wrong.test".into();
    }
    let retired = engine.active.swap(Arc::new(
        PolicySnapshot::compile(config.clone(), 2).unwrap(),
    ));
    let weak = Arc::downgrade(&retired);
    drop(retired);
    assert!(weak.upgrade().is_none());
    mock.wait_closed().await;
    assert_eq!(
        udp_query(address, &request).await.metadata.response_code,
        ResponseCode::ServFail
    );
    assert_eq!(mock.queries.load(Ordering::SeqCst), 2);
    // Restoring the original identity may reuse its still-valid cached answer;
    // a different question still needs the new authenticated connection.
    config.upstreams[0].transport = mock.transport.clone();
    engine
        .active
        .store(Arc::new(PolicySnapshot::compile(config, 3).unwrap()));
    assert_eq!(udp_query(address, &request).await.answers.len(), 1);
    assert_eq!(mock.queries.load(Ordering::SeqCst), 2);
    let mut fresh = request.clone();
    fresh.queries[0].set_name(Name::from_ascii("fresh.test.").unwrap());
    assert_eq!(udp_query(address, &fresh).await.answers.len(), 1);
    assert_eq!(mock.queries.load(Ordering::SeqCst), 3);
    cancel.cancel();
    timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    drop(engine);
    mock.wait_closed().await;
}
