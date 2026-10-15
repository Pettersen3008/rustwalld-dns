#![allow(clippy::unwrap_used)]
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, AAAA, CNAME},
    },
};
use rustwalld_dns_core::{
    Engine, EngineConfig, Prepared, PublicationTarget, Transport, reply, telemetry::Telemetry,
};
use rustwalld_dns_filter::{Action, ListInput};
use rustwalld_dns_policy::{
    AddressFamily, DomainRoute, LocalData, LocalRecord, PolicyConfigSet, PolicySnapshot,
    UpstreamProfile,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::net::UdpSocket;
fn record(domain: &str, data: LocalData) -> LocalRecord {
    LocalRecord {
        domain: domain.into(),
        ttl: 60,
        data,
    }
}
fn request(domain: &str, kind: RecordType) -> Vec<u8> {
    let mut request = Message::query();
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(Name::from_ascii(domain).unwrap(), kind));
    request.to_vec().unwrap()
}
async fn answer(engine: &Engine, domain: &str, kind: RecordType, transport: Transport) -> Message {
    Message::from_vec(
        &engine
            .answer(
                &request(domain, kind),
                "127.0.0.1".parse().unwrap(),
                transport,
            )
            .await
            .unwrap(),
    )
    .unwrap()
}
#[tokio::test]
async fn passthrough_preserves_filtering_routes_cache_shadow_and_pending_generations() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let counts = calls.clone();
    let mock = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        loop {
            let (len, peer) = socket.recv_from(&mut bytes).await.unwrap();
            let request = Message::from_vec(&bytes[..len]).unwrap();
            let query = &request.queries[0];
            assert!(matches!(
                query.name().to_ascii().as_str(),
                "split.test."
                    | "pending.test."
                    | "response.test."
                    | "allowed.test."
                    | "alias.test."
            ));
            counts.fetch_add(1, Ordering::SeqCst);
            let mut response = reply(&request, ResponseCode::NoError);
            if query.name().to_ascii() == "response.test." {
                response.add_answer(Record::from_rdata(
                    query.name().clone(),
                    600,
                    RData::CNAME(CNAME(Name::from_ascii("tracking.test.").unwrap())),
                ));
            }
            let data = match query.query_type() {
                RecordType::A => RData::A(A("192.0.2.20".parse().unwrap())),
                RecordType::AAAA => RData::AAAA(AAAA("2001:db8::20".parse().unwrap())),
                other => panic!("unexpected type {other}"),
            };
            let owner = if query.name().to_ascii() == "response.test." {
                Name::from_ascii("tracking.test.").unwrap()
            } else {
                query.name().clone()
            };
            response.add_answer(Record::from_rdata(owner, 600, data));
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let mut config = PolicyConfigSet::default();
    config.upstreams[0].addresses = vec!["127.0.0.1:9".parse().unwrap()];
    config.upstreams[0].timeout_ms = 50;
    config.upstreams.push(UpstreamProfile {
        name: "local-route".into(),
        addresses: vec![address],
        timeout_ms: 100,
        transport: Default::default(),
    });
    config.policies[0].routes.push(DomainRoute {
        domain: "test".into(),
        upstream: "local-route".into(),
    });
    config.policies[0].lists = vec![ListInput {
        name: "privacy".into(),
        action: Action::Block,
        rules: "=blocked.test\n=allowed.test\n=tracking.test\n@@=allowed.test".into(),
        syntax: Default::default(),
    }];
    config.policies[0].dns_records = vec![
        record(
            "split.test",
            LocalData::A {
                address: "192.0.2.10".parse().unwrap(),
            },
        ),
        record(
            "split.test",
            LocalData::Passthrough {
                family: AddressFamily::Aaaa,
            },
        ),
        record(
            "alias.test",
            LocalData::Cname {
                target: "split.test".into(),
            },
        ),
    ];
    for domain in [
        "pending.test",
        "blocked.test",
        "allowed.test",
        "response.test",
    ] {
        config.policies[0].dns_records.push(record(
            domain,
            LocalData::Passthrough {
                family: AddressFamily::A,
            },
        ));
    }
    let (telemetry, mut events) = Telemetry::channel(64);
    let (engine, controller) = Engine::controlled(
        PolicySnapshot::compile(config.clone(), 1).unwrap(),
        EngineConfig::default(),
        telemetry,
    );
    for transport in [Transport::Udp, Transport::Tcp] {
        let local = answer(&engine, "split.test", RecordType::A, transport).await;
        assert!(matches!(&local.answers[0].data,RData::A(value) if value.0.octets()[3]==10));
        let forwarded = answer(&engine, "split.test", RecordType::AAAA, transport).await;
        assert!(
            matches!(&forwarded.answers[0].data,RData::AAAA(value) if value.0=="2001:db8::20".parse::<std::net::Ipv6Addr>().unwrap())
        );
        let alias = answer(&engine, "alias.test", RecordType::AAAA, transport).await;
        assert_eq!(alias.answers.len(), 1);
        assert_eq!(
            &alias.answers[0].name,
            &Name::from_ascii("alias.test.").unwrap()
        );
        for kind in [RecordType::MX, RecordType::CNAME, RecordType::AAAA] {
            assert!(
                answer(&engine, "blocked.test", kind, transport)
                    .await
                    .answers
                    .is_empty()
            );
        }
        assert_eq!(
            answer(&engine, "blocked.test", RecordType::A, transport)
                .await
                .response_code,
            ResponseCode::NXDomain
        );
        assert_eq!(
            answer(&engine, "allowed.test", RecordType::A, transport)
                .await
                .response_code,
            ResponseCode::NoError
        );
        assert_eq!(
            answer(&engine, "response.test", RecordType::A, transport)
                .await
                .response_code,
            ResponseCode::NXDomain
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    while events.try_recv().is_ok() {}
    let pending = match engine.prepare(
        &request("pending.test", RecordType::A),
        "127.0.0.1".parse().unwrap(),
        Transport::Udp,
    ) {
        Prepared::Forward(value) => value,
        _ => panic!("expected pending"),
    };
    let mut next = config.clone();
    next.policies[0]
        .dns_records
        .retain(|record| record.domain != "pending.test");
    next.policies[0].dns_records.push(record(
        "pending.test",
        LocalData::A {
            address: "192.0.2.99".parse().unwrap(),
        },
    ));
    controller
        .prepare(
            PolicySnapshot::compile(next.clone(), 2).unwrap(),
            PublicationTarget::Shadow,
            controller.version(),
        )
        .unwrap()
        .commit();
    let old = answer(&engine, "pending.test", RecordType::A, Transport::Udp).await;
    assert!(matches!(&old.answers[0].data,RData::A(value) if value.0.octets()[3]==20));
    let event = events.recv().await.unwrap();
    assert!(event.shadow.unwrap().differs);
    controller
        .prepare(
            PolicySnapshot::compile(next, 3).unwrap(),
            PublicationTarget::Active,
            controller.version(),
        )
        .unwrap()
        .commit();
    let old = Message::from_vec(&engine.forward(pending).await.unwrap()).unwrap();
    assert!(matches!(&old.answers[0].data,RData::A(value) if value.0.octets()[3]==20));
    let new = answer(&engine, "pending.test", RecordType::A, Transport::Tcp).await;
    assert!(matches!(&new.answers[0].data,RData::A(value) if value.0.octets()[3]==99));
    controller
        .prepare(
            PolicySnapshot::compile(config.clone(), 4).unwrap(),
            PublicationTarget::Active,
            controller.version(),
        )
        .unwrap()
        .commit();
    let reused = answer(&engine, "pending.test", RecordType::A, Transport::Udp).await;
    assert!(matches!(&reused.answers[0].data,RData::A(value) if value.0.octets()[3]==20));
    assert_eq!(calls.load(Ordering::SeqCst), 5);
    config.policies[0].lists[0]
        .rules
        .push_str("\n=pending.test");
    controller
        .prepare(
            PolicySnapshot::compile(config, 5).unwrap(),
            PublicationTarget::Active,
            controller.version(),
        )
        .unwrap()
        .commit();
    assert_eq!(
        answer(&engine, "pending.test", RecordType::A, Transport::Udp)
            .await
            .response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(calls.load(Ordering::SeqCst), 5);
    mock.abort();
}
