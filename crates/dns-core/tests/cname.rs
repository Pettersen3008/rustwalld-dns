#![allow(clippy::unwrap_used)]
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, CNAME},
    },
};
use rustwalld_dns_core::{
    Engine, EngineConfig, PublicationTarget, Transport, reply, telemetry::Telemetry,
};
use rustwalld_dns_filter::{Action, ListInput};
use rustwalld_dns_policy::{PolicyConfigSet, PolicySnapshot};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::net::UdpSocket;

#[tokio::test]
async fn cached_aliases_follow_each_generation_and_preserve_block_provenance() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counts = hits.clone();
    let mock = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        loop {
            let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let request = Message::from_vec(&buffer[..len]).unwrap();
            counts.fetch_add(1, Ordering::Relaxed);
            let mut response = reply(&request, ResponseCode::NoError);
            response.add_answer(Record::from_rdata(
                request.queries[0].name().clone(),
                60,
                RData::CNAME(CNAME(Name::from_ascii("tracking.test.").unwrap())),
            ));
            response.add_answer(Record::from_rdata(
                Name::from_ascii("tracking.test.").unwrap(),
                60,
                RData::A(A("192.0.2.1".parse().unwrap())),
            ));
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let mut config = PolicyConfigSet::default();
    config.upstreams[0].addresses = vec![address];
    config.policies[0].lists = vec![ListInput {
        syntax: Default::default(),
        name: "privacy".into(),
        action: Action::Block,
        rules: "tracking.test".into(),
    }];
    let (telemetry, mut events) = Telemetry::channel(32);
    let (engine, controller) = Engine::controlled(
        PolicySnapshot::compile(config.clone(), 1).unwrap(),
        EngineConfig::default(),
        telemetry,
    );
    controller
        .prepare(
            PolicySnapshot::compile(config.clone(), 2).unwrap(),
            PublicationTarget::Shadow,
            controller.version(),
        )
        .unwrap()
        .commit();
    let mut request = Message::new(42, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(
        Name::from_ascii("alias.test.").unwrap(),
        RecordType::A,
    ));
    for transport in [Transport::Udp, Transport::Tcp] {
        let response = engine
            .answer(
                &request.to_vec().unwrap(),
                "127.0.0.1".parse().unwrap(),
                transport,
            )
            .await
            .unwrap();
        let response = Message::from_vec(&response).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
        assert!(response.answers.is_empty());
        let event = events.recv().await.unwrap();
        assert_eq!(event.matched_domain.as_deref(), Some("tracking.test"));
        assert_eq!(event.decision.action, Action::Block);
        assert!(!event.shadow.unwrap().differs);
        assert_eq!(event.generation, 1);
    }
    assert_eq!(hits.load(Ordering::Relaxed), 1);
    config.policies[0].lists[0]
        .rules
        .push_str("\n@@=alias.test");
    controller
        .prepare(
            PolicySnapshot::compile(config.clone(), 3).unwrap(),
            PublicationTarget::Active,
            controller.version(),
        )
        .unwrap()
        .commit();
    let response = engine
        .answer(
            &request.to_vec().unwrap(),
            "127.0.0.1".parse().unwrap(),
            Transport::Udp,
        )
        .await
        .unwrap();
    assert_eq!(Message::from_vec(&response).unwrap().answers.len(), 2);
    assert_eq!(hits.load(Ordering::Relaxed), 1);
    assert!(events.recv().await.unwrap().matched_domain.is_none());
    config.policies[0].lists[0].rules = "tracking.test".into();
    controller
        .prepare(
            PolicySnapshot::compile(config, 4).unwrap(),
            PublicationTarget::Active,
            controller.version(),
        )
        .unwrap()
        .commit();
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
    assert_eq!(hits.load(Ordering::Relaxed), 1);
    assert_eq!(events.recv().await.unwrap().generation, 4);
    mock.abort();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), mock)
            .await
            .unwrap()
            .unwrap_err()
            .is_cancelled()
    );
}

#[tokio::test]
async fn local_records_aliases_external_routes_and_block_modes_use_the_engine() {
    use rustwalld_dns_policy::{BlockMode, DomainRoute, LocalData, LocalRecord, Rewrite};
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counts = hits.clone();
    let mock = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        loop {
            let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let request = Message::from_vec(&buffer[..len]).unwrap();
            assert_eq!(
                request.queries[0].name(),
                &Name::from_ascii("external.test.").unwrap()
            );
            counts.fetch_add(1, Ordering::Relaxed);
            let mut response = reply(&request, ResponseCode::NoError);
            response.add_answer(Record::from_rdata(
                request.queries[0].name().clone(),
                60,
                RData::A(A("192.0.2.7".parse().unwrap())),
            ));
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut config = PolicyConfigSet::default();
    config.upstreams[0].addresses = vec![silent.local_addr().unwrap()];
    let mut route = config.upstreams[0].clone();
    route.name = "internal".into();
    route.addresses = vec![address];
    config.upstreams.push(route);
    config.policies[0].routes = vec![DomainRoute {
        domain: "test".into(),
        upstream: "internal".into(),
    }];
    config.policies[0].rewrites = vec![Rewrite {
        domain: "nas.home.arpa".into(),
        addresses: vec!["192.0.2.10".parse().unwrap()],
        ttl: 42,
    }];
    config.policies[0].dns_records = vec![
        LocalRecord {
            domain: "alias.home.arpa".into(),
            ttl: 25,
            data: LocalData::Cname {
                target: "nas.home.arpa".into(),
            },
        },
        LocalRecord {
            domain: "external.home.arpa".into(),
            ttl: 40,
            data: LocalData::Cname {
                target: "external.test".into(),
            },
        },
        LocalRecord {
            domain: "10.2.0.192.in-addr.arpa".into(),
            ttl: 42,
            data: LocalData::Ptr {
                target: "nas.home.arpa".into(),
            },
        },
        LocalRecord {
            domain: "_acme-challenge.home.arpa".into(),
            ttl: 1,
            data: LocalData::Txt {
                text: "challenge".into(),
            },
        },
    ];
    config.policies[0].lists = vec![ListInput {
        syntax: Default::default(),
        name: "deny".into(),
        action: Action::Block,
        rules: "blocked.test".into(),
    }];
    let (telemetry, _events) = Telemetry::channel(64);
    let (engine, controller) = Engine::controlled(
        PolicySnapshot::compile(config.clone(), 1).unwrap(),
        EngineConfig::default(),
        telemetry,
    );
    let request = |domain: &str, kind| {
        let mut request = Message::new(43, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(Name::from_ascii(domain).unwrap(), kind));
        request.to_vec().unwrap()
    };
    let ip = "127.0.0.1".parse().unwrap();
    let response = Message::from_vec(
        &engine
            .answer(
                &request("alias.home.arpa", RecordType::A),
                ip,
                Transport::Udp,
            )
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(response.answers.len(), 2);
    assert_eq!(response.answers[0].ttl, 25);
    assert_eq!(response.answers[1].ttl, 42);
    let response = Message::from_vec(
        &engine
            .answer(
                &request("10.2.0.192.in-addr.arpa", RecordType::PTR),
                ip,
                Transport::Tcp,
            )
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(response.answers[0].data.record_type(), RecordType::PTR);
    for _ in 0..2 {
        let response = Message::from_vec(
            &engine
                .answer(
                    &request("external.home.arpa", RecordType::A),
                    ip,
                    Transport::Tcp,
                )
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            response.queries[0].name(),
            &Name::from_ascii("external.home.arpa.").unwrap()
        );
        assert_eq!(response.answers.len(), 2);
        assert_eq!(
            response.answers[1].name,
            Name::from_ascii("external.test.").unwrap()
        );
    }
    assert_eq!(hits.load(Ordering::Relaxed), 1);
    for (generation, mode, code, answers) in [
        (2, BlockMode::NullIp, ResponseCode::NoError, 1),
        (3, BlockMode::NoData, ResponseCode::NoError, 0),
        (4, BlockMode::NxDomain, ResponseCode::NXDomain, 0),
    ] {
        config.policies[0].block_mode = mode;
        controller
            .prepare(
                PolicySnapshot::compile(config.clone(), generation).unwrap(),
                PublicationTarget::Active,
                controller.version(),
            )
            .unwrap()
            .commit();
        let response = Message::from_vec(
            &engine
                .answer(&request("blocked.test", RecordType::A), ip, Transport::Udp)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(response.metadata.response_code, code);
        assert_eq!(response.answers.len(), answers);
        if let Some(answer) = response.answers.first() {
            assert_eq!(answer.data, RData::A(A(std::net::Ipv4Addr::UNSPECIFIED)));
        }
    }
    mock.abort();
    let _ = mock.await;
}
