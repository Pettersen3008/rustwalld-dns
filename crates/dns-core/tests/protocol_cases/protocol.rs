#![allow(clippy::unwrap_used)]
use super::*;

#[tokio::test]
async fn udp_tcp_records_and_persistent_tcp() {
    let mock = Mock::start(false, false).await;
    let (addr, cancel, task) = server(vec![mock.addr]).await;
    for kind in [RecordType::A, RecordType::AAAA, RecordType::CNAME] {
        let request = query(kind);
        let result = udp_query(addr, &request).await;
        assert_eq!(result.metadata.id, 42);
        assert_eq!(result.answers[0].data.record_type(), kind);
    }
    let mut stream = TcpStream::connect(addr).await.unwrap();
    for kind in [RecordType::A, RecordType::AAAA] {
        let bytes = query(kind).to_vec().unwrap();
        stream.write_u16(bytes.len() as u16).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
        let len = stream.read_u16().await.unwrap() as usize;
        let mut bytes = vec![0; len];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(
            Message::from_vec(&bytes).unwrap().answers[0]
                .data
                .record_type(),
            kind
        );
    }
    cancel.cancel();
    timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn spoofed_responses_ignored_and_truncation_retried_tcp() {
    let mock = Mock::start(true, true).await;
    let (addr, cancel, task) = server(vec![mock.addr]).await;
    let response = udp_query(addr, &query(RecordType::A)).await;
    assert!(!response.metadata.truncation);
    assert_eq!(response.answers.len(), 1);
    cancel.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn timeout_fallback_and_servfail() {
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mock = Mock::start(false, false).await;
    let (addr, cancel, task) = server(vec![silent.local_addr().unwrap(), mock.addr]).await;
    assert_eq!(
        udp_query(addr, &query(RecordType::A))
            .await
            .metadata
            .response_code,
        ResponseCode::NoError
    );
    cancel.cancel();
    task.await.unwrap().unwrap();
    let (addr, cancel, task) = server(vec![silent.local_addr().unwrap()]).await;
    assert_eq!(
        udp_query(addr, &query(RecordType::A))
            .await
            .metadata
            .response_code,
        ResponseCode::ServFail
    );
    cancel.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn malformed_dropped_invalid_queries_never_forwarded() {
    let mock = Mock::start(false, false).await;
    let (addr, cancel, task) = server(vec![mock.addr]).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // Compression pointer points to itself.
    let mut malformed = vec![0, 42, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1];
    for bytes in [&[][..], &malformed[..], &[0; 11][..]] {
        socket.send_to(bytes, addr).await.unwrap();
        assert!(
            timeout(Duration::from_millis(20), socket.recv(&mut [0; 512]))
                .await
                .is_err()
        );
    }
    malformed.clear();
    let mut request = query(RecordType::A);
    request.add_query(request.queries[0].clone());
    assert_eq!(
        udp_query(addr, &request).await.metadata.response_code,
        ResponseCode::FormErr
    );
    request = query(RecordType::AXFR);
    assert_eq!(
        udp_query(addr, &request).await.metadata.response_code,
        ResponseCode::Refused
    );
    assert_eq!(mock.hits.load(Ordering::Relaxed), 0);
    assert_eq!(
        udp_query(addr, &query(RecordType::A)).await.answers.len(),
        1
    );
    cancel.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn udp_size_limit_edns_and_tcp_idle_shutdown() {
    let mock = Mock::start(false, false).await;
    let (engine, _receiver) = engine_for(&mock, 1000, 32);
    let mut config = engine.active.load().config().clone();
    config.policies[0]
        .rewrites
        .push(rustwalld_dns_policy::Rewrite {
            domain: "test.example".into(),
            addresses: (1..=32)
                .map(|i| format!("2001:db8::{i}").parse().unwrap())
                .collect(),
            ttl: 60,
        });
    engine
        .active
        .store(Arc::new(PolicySnapshot::compile(config, 2).unwrap()));
    let client = "127.0.0.1".parse().unwrap();
    let request = query(RecordType::AAAA);
    let bytes = engine
        .answer(&request.to_vec().unwrap(), client, Transport::Udp)
        .await
        .unwrap();
    assert!(bytes.len() <= 512);
    assert!(Message::from_vec(&bytes).unwrap().metadata.truncation);
    let mut request = request;
    let mut edns = hickory_proto::op::Edns::new();
    edns.set_max_payload(1232);
    request.edns = Some(edns);
    let bytes = engine
        .answer(&request.to_vec().unwrap(), client, Transport::Udp)
        .await
        .unwrap();
    assert!(!Message::from_vec(&bytes).unwrap().metadata.truncation);
    request.edns.as_mut().unwrap().set_version(1);
    // BADVERS and BADSIG share wire RCODE 16; Hickory decodes it as BADSIG.
    let reply = Message::from_vec(
        &engine
            .answer(&request.to_vec().unwrap(), client, Transport::Udp)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(u16::from(reply.metadata.response_code), 16);
    let (addr, cancel, task) = server(vec![mock.addr]).await;
    let _idle = TcpStream::connect(addr).await.unwrap();
    cancel.cancel();
    timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn escaped_dot_in_dns_label_does_not_false_block_suffix() {
    let mock = Mock::start(false, false).await;
    let (engine, _receiver) = engine_for(&mock, 100, 32);
    let mut config = engine.active.load().config().clone();
    config.policies[0]
        .lists
        .push(rustwalld_dns_filter::ListInput {
            syntax: Default::default(),
            name: "deny".into(),
            action: rustwalld_dns_filter::Action::Block,
            rules: "example.com".into(),
        });
    engine
        .active
        .store(Arc::new(PolicySnapshot::compile(config, 2).unwrap()));
    let mut request = query(RecordType::A);
    request.queries[0].set_name(Name::from_ascii(r"evil\.example.com.").unwrap());
    let response = engine
        .answer(
            &request.to_vec().unwrap(),
            "127.0.0.1".parse().unwrap(),
            Transport::Udp,
        )
        .await
        .unwrap();
    assert_eq!(
        Message::from_vec(&response).unwrap().metadata.response_code,
        ResponseCode::NoError
    );
    assert_eq!(mock.hits.load(Ordering::Relaxed), 1);
    request.queries[0].set_name(Name::from_ascii(r"evil\.label.example.com.").unwrap());
    let response = engine
        .answer(
            &request.to_vec().unwrap(),
            "127.0.0.1".parse().unwrap(),
            Transport::Udp,
        )
        .await
        .unwrap();
    assert_eq!(
        Message::from_vec(&response).unwrap().metadata.response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(mock.hits.load(Ordering::Relaxed), 1);
}

async fn quick_udp(addr: SocketAddr, query: &Message) -> Message {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .send_to(&query.to_vec().unwrap(), addr)
        .await
        .unwrap();
    let mut bytes = vec![0; 4096];
    let len = timeout(Duration::from_millis(500), socket.recv(&mut bytes))
        .await
        .expect("a locally answerable query waited behind slow upstream work")
        .unwrap();
    Message::from_vec(&bytes[..len]).unwrap()
}
async fn slow_upstream_server(
    config: ServerConfig,
) -> (
    SocketAddr,
    Arc<rustwalld_dns_core::Engine>,
    UdpSocket,
    CancellationToken,
    JoinHandle<std::io::Result<()>>,
) {
    // A bound socket that never answers: every forwarded query waits for the
    // full upstream timeout.
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut policy = PolicyConfigSet::default();
    policy.upstreams[0].addresses = vec![silent.local_addr().unwrap()];
    policy.upstreams[0].timeout_ms = 1500;
    policy.policies[0].lists = vec![rustwalld_dns_filter::ListInput {
        syntax: Default::default(),
        name: "deny".into(),
        action: rustwalld_dns_filter::Action::Block,
        rules: "blocked.example".into(),
    }];
    let (telemetry, _receiver) = Telemetry::channel(16);
    let engine = Arc::new(rustwalld_dns_core::Engine::with_config(
        PolicySnapshot::compile(policy, 1).unwrap(),
        rustwalld_dns_core::EngineConfig::default(),
        telemetry,
    ));
    let server = Server::bind(config, engine.clone()).await.unwrap();
    let addr = server.local_addr().unwrap();
    let cancel = CancellationToken::new();
    let task = tokio::spawn(server.run(cancel.clone()));
    (addr, engine, silent, cancel, task)
}
fn named(name: &str, kind: RecordType) -> Message {
    let mut request = query(kind);
    request.queries[0].set_name(Name::from_ascii(name).unwrap());
    request
}

#[tokio::test]
async fn upstream_waits_do_not_starve_local_answers() {
    let (addr, _engine, _silent, cancel, task) = slow_upstream_server(ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        max_udp_queries: 2,
        ..Default::default()
    })
    .await;
    // More slow misses than local worker slots, each waiting on the upstream.
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for index in 0..6 {
        let request = named(&format!("slow{index}.example."), RecordType::A);
        socket
            .send_to(&request.to_vec().unwrap(), addr)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    // Blocks, refusals and cache hits never wait on those upstream queries.
    assert_eq!(
        quick_udp(addr, &named("ads.blocked.example.", RecordType::A))
            .await
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(
        quick_udp(addr, &query(RecordType::ANY))
            .await
            .metadata
            .response_code,
        ResponseCode::Refused
    );
    cancel.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn full_upstream_wait_limit_sheds_misses_with_servfail() {
    let (addr, engine, _silent, cancel, task) = slow_upstream_server(ServerConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        max_udp_upstream_waits: 1,
        ..Default::default()
    })
    .await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .send_to(
            &named("first.example.", RecordType::A).to_vec().unwrap(),
            addr,
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    // The one wait slot is taken; a second miss (even for the same name) is
    // answered at once instead of queueing behind it.
    for name in ["second.example.", "first.example."] {
        assert_eq!(
            quick_udp(addr, &named(name, RecordType::A))
                .await
                .metadata
                .response_code,
            ResponseCode::ServFail
        );
    }
    let metrics = engine.telemetry().metrics.snapshot();
    assert_eq!(metrics.forward_overloads, 2);
    assert_eq!(metrics.failures, 2);
    assert_eq!(
        quick_udp(addr, &named("x.blocked.example.", RecordType::A))
            .await
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );
    cancel.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn edns_options_are_ignored_and_never_forwarded() {
    use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsOption};
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = upstream.local_addr().unwrap();
    let forwarded = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = forwarded.clone();
    let mock = tokio::spawn(async move {
        let mut bytes = vec![0; 4096];
        loop {
            let (len, peer) = upstream.recv_from(&mut bytes).await.unwrap();
            let request = Message::from_vec(&bytes[..len]).unwrap();
            seen.lock()
                .unwrap()
                .push(request.edns.as_ref().map(|e| e.options().as_ref().len()));
            upstream
                .send_to(&answer(&request).to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let mut config = PolicyConfigSet::default();
    config.upstreams[0].addresses = vec![address];
    config.upstreams[0].timeout_ms = 500;
    let (telemetry, mut events) = Telemetry::channel(16);
    let engine = rustwalld_dns_core::Engine::with_config(
        PolicySnapshot::compile(config, 1).unwrap(),
        rustwalld_dns_core::EngineConfig::default(),
        telemetry,
    );
    let client = "127.0.0.1".parse().unwrap();
    use rustwalld_dns_core::QuerySource;
    for (cookie, source) in [(1_u8, QuerySource::Upstream), (2, QuerySource::Cache)] {
        let mut request = query(RecordType::A);
        let mut edns = hickory_proto::op::Edns::new();
        edns.set_max_payload(1232);
        // DNS COOKIE (RFC 7873), Client Subnet (RFC 7871) and Padding (RFC 7830).
        edns.options_mut()
            .insert(EdnsOption::Unknown(10, vec![cookie; 8]));
        edns.options_mut()
            .insert(EdnsOption::Subnet(ClientSubnet::new(
                "198.51.100.0".parse().unwrap(),
                24,
                0,
            )));
        edns.options_mut()
            .insert(EdnsOption::Unknown(12, vec![0; 16]));
        request.edns = Some(edns);
        let reply = Message::from_vec(
            &engine
                .answer(&request.to_vec().unwrap(), client, Transport::Udp)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert_eq!(reply.answers.len(), 1);
        assert!(reply.edns.unwrap().options().as_ref().is_empty());
        // Options do not partition the cache: a new cookie still hits.
        assert_eq!(events.try_recv().unwrap().source, source);
    }
    assert_eq!(*forwarded.lock().unwrap(), vec![Some(0)]);
    mock.abort();
}
