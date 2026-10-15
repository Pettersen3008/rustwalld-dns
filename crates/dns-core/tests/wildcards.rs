#![allow(clippy::unwrap_used)]
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, AAAA},
    },
};
use rustwalld_dns_core::{
    Engine, EngineConfig, Prepared, PublicationTarget, Transport, reply, telemetry::Telemetry,
};
use rustwalld_dns_filter::{Action, ListInput};
use rustwalld_dns_policy::{LocalData, LocalRecord, PolicyConfigSet, PolicySnapshot};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::net::UdpSocket;
fn local(domain: &str, data: LocalData) -> LocalRecord {
    LocalRecord {
        domain: domain.into(),
        ttl: 60,
        data,
    }
}
fn request(name: &str, kind: RecordType) -> Vec<u8> {
    let mut req = Message::query();
    req.metadata.recursion_desired = true;
    req.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    req.to_vec().unwrap()
}
async fn answer(engine: &Engine, name: &str, kind: RecordType, transport: Transport) -> Message {
    Message::from_vec(
        &engine
            .answer(
                &request(name, kind),
                "127.0.0.1".parse().unwrap(),
                transport,
            )
            .await
            .unwrap(),
    )
    .unwrap()
}
#[tokio::test]
async fn wildcard_wire_answers_preserve_concrete_owner_case_types_and_policy_generations() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let hits = calls.clone();
    let mock = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        loop {
            let (len, peer) = socket.recv_from(&mut bytes).await.unwrap();
            let req = Message::from_vec(&bytes[..len]).unwrap();
            hits.fetch_add(1, Ordering::SeqCst);
            let q = &req.queries[0];
            let data = match q.query_type() {
                RecordType::A => RData::A(A("192.0.2.199".parse().unwrap())),
                RecordType::AAAA => RData::AAAA(AAAA("2001:db8::199".parse().unwrap())),
                other => panic!("unexpected {other}"),
            };
            let mut resp = reply(&req, ResponseCode::NoError);
            resp.add_answer(Record::from_rdata(q.name().clone(), 60, data));
            socket.send_to(&resp.to_vec().unwrap(), peer).await.unwrap();
        }
    });
    let mut config = PolicyConfigSet::default();
    config.upstreams[0].addresses = vec![address];
    config.policies[0].lists = vec![ListInput {
        name: "privacy".into(),
        action: Action::Block,
        rules: "lab.test".into(),
        syntax: Default::default(),
    }];
    config.policies[0].dns_records = vec![
        local(
            "*.lab.test",
            LocalData::A {
                address: "192.0.2.10".parse().unwrap(),
            },
        ),
        local(
            "*.lab.test",
            LocalData::Aaaa {
                address: "2001:db8::a".parse().unwrap(),
            },
        ),
        local(
            "*.deep.lab.test",
            LocalData::A {
                address: "192.0.2.20".parse().unwrap(),
            },
        ),
        local(
            "fixed.lab.test",
            LocalData::A {
                address: "192.0.2.30".parse().unwrap(),
            },
        ),
    ];
    let (telemetry, mut events) = Telemetry::channel(64);
    let (engine, controller) = Engine::controlled(
        PolicySnapshot::compile(config.clone(), 1).unwrap(),
        EngineConfig::default(),
        telemetry,
    );
    for transport in [Transport::Udp, Transport::Tcp] {
        for (name, kind, marker) in [
            ("X.LAB.TEST.", RecordType::A, 10),
            ("x.deep.lab.test", RecordType::A, 20),
            ("fixed.lab.test", RecordType::A, 30),
            ("fixed.lab.test", RecordType::AAAA, 10),
            ("x.deep.lab.test", RecordType::AAAA, 10),
            (r"x\.deep.lab.test", RecordType::A, 10),
        ] {
            let response = answer(&engine, name, kind, transport).await;
            assert_eq!(response.response_code, ResponseCode::NoError);
            assert_eq!(response.answers.len(), 1);
            assert!(!response.answers[0].name.is_wildcard());
            assert_eq!(response.answers[0].name, response.queries[0].name().clone());
            if name == "X.LAB.TEST." {
                assert_eq!(response.answers[0].name.to_ascii(), name);
            }
            match &response.answers[0].data {
                RData::A(ip) => assert_eq!(ip.0.octets()[3], marker),
                RData::AAAA(ip) => assert_eq!(ip.0.segments()[7], u16::from(marker)),
                other => panic!("unexpected {other:?}"),
            }
        }
        for kind in [
            RecordType::CNAME,
            RecordType::TXT,
            RecordType::MX,
            RecordType::DS,
            RecordType::Unknown(65400),
        ] {
            let response = answer(&engine, "x.lab.test", kind, transport).await;
            assert_eq!(response.response_code, ResponseCode::NoError);
            assert!(response.answers.is_empty());
        }
        assert_eq!(
            answer(&engine, "lab.test", RecordType::A, transport)
                .await
                .response_code,
            ResponseCode::NXDomain
        );
        assert_eq!(
            answer(&engine, "badlab.test", RecordType::A, transport)
                .await
                .answers
                .len(),
            1
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    while events.try_recv().is_ok() {}
    let mut empty = config.clone();
    empty.policies[0].dns_records.clear();
    controller
        .prepare(
            PolicySnapshot::compile(empty.clone(), 2).unwrap(),
            PublicationTarget::Active,
            controller.version(),
        )
        .unwrap()
        .commit();
    // Use an unblocked outside-name lookup that was admitted before wildcard publication.
    let pending = match engine.prepare(
        &request("pending.test", RecordType::A),
        "127.0.0.1".parse().unwrap(),
        Transport::Udp,
    ) {
        Prepared::Forward(p) => p,
        _ => panic!("expected pending"),
    };
    config.policies[0].dns_records.push(local(
        "*.test",
        LocalData::A {
            address: "192.0.2.40".parse().unwrap(),
        },
    ));
    controller
        .prepare(
            PolicySnapshot::compile(config.clone(), 3).unwrap(),
            PublicationTarget::Shadow,
            controller.version(),
        )
        .unwrap()
        .commit();
    let response = answer(&engine, "x.lab.test", RecordType::A, Transport::Udp).await;
    assert_eq!(response.response_code, ResponseCode::NXDomain);
    assert!(events.recv().await.unwrap().shadow.unwrap().differs);
    controller
        .prepare(
            PolicySnapshot::compile(config.clone(), 4).unwrap(),
            PublicationTarget::Active,
            controller.version(),
        )
        .unwrap()
        .commit();
    let pinned = Message::from_vec(&engine.forward(pending).await.unwrap()).unwrap();
    assert!(matches!(&pinned.answers[0].data,RData::A(ip) if ip.0.octets()[3]==199));
    let current = answer(&engine, "pending.test", RecordType::A, Transport::Tcp).await;
    assert!(matches!(&current.answers[0].data,RData::A(ip) if ip.0.octets()[3]==40));
    controller
        .prepare(
            PolicySnapshot::compile(empty, 5).unwrap(),
            PublicationTarget::Active,
            controller.version(),
        )
        .unwrap()
        .commit();
    let reused = answer(&engine, "pending.test", RecordType::A, Transport::Udp).await;
    assert!(matches!(&reused.answers[0].data,RData::A(ip) if ip.0.octets()[3]==199));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    mock.abort();
}

#[tokio::test]
async fn shadow_reports_rewrite_address_ttl_and_template_changes_but_not_identical_answers() {
    let mut config = PolicyConfigSet::default();
    config.upstreams[0].addresses = vec!["127.0.0.1:9".parse().unwrap()];
    config.policies[0].dns_records = vec![local(
        "*.lab.test",
        LocalData::A {
            address: "192.0.2.10".parse().unwrap(),
        },
    )];
    let (telemetry, mut events) = Telemetry::channel(16);
    let (engine, controller) = Engine::controlled(
        PolicySnapshot::compile(config.clone(), 1).unwrap(),
        EngineConfig::default(),
        telemetry,
    );
    for (index, change) in ["identical", "address", "ttl", "template", "family"]
        .into_iter()
        .enumerate()
    {
        let mut next = config.clone();
        match change {
            "address" => {
                next.policies[0].dns_records[0].data = LocalData::A {
                    address: "192.0.2.11".parse().unwrap(),
                }
            }
            "ttl" => next.policies[0].dns_records[0].ttl = 30,
            "template" => next.policies[0].dns_records[0].domain = "*.test".into(),
            "family" => {
                next.policies[0].dns_records[0].data = LocalData::Aaaa {
                    address: "2001:db8::1".parse().unwrap(),
                }
            }
            _ => {}
        }
        controller
            .prepare(
                PolicySnapshot::compile(next, index as u64 + 2).unwrap(),
                PublicationTarget::Shadow,
                controller.version(),
            )
            .unwrap()
            .commit();
        let active = answer(&engine, "x.lab.test", RecordType::A, Transport::Udp).await;
        assert!(matches!(&active.answers[0].data,RData::A(ip) if ip.0.octets()[3]==10));
        assert_eq!(
            events.recv().await.unwrap().shadow.unwrap().differs,
            change != "identical",
            "{change}"
        );
    }
}

#[tokio::test]
async fn typed_wildcard_wire_owners_shadow_ttl_and_large_rrsets_are_bounded() {
    for (kind, data) in [
        (
            RecordType::TXT,
            LocalData::Txt {
                text: "fixture".into(),
            },
        ),
        (
            RecordType::PTR,
            LocalData::Ptr {
                target: "nas.home.arpa".into(),
            },
        ),
        (
            RecordType::MX,
            LocalData::Mx {
                preference: 10,
                exchange: "mail.home.arpa".into(),
            },
        ),
        (
            RecordType::SRV,
            LocalData::Srv {
                priority: 1,
                weight: 2,
                port: 8443,
                target: ".".into(),
            },
        ),
    ] {
        let mut config = PolicyConfigSet::default();
        config.upstreams[0].addresses = vec!["127.0.0.1:9".parse().unwrap()];
        config.policies[0].dns_records = vec![local("*.lab.test", data)];
        let (telemetry, mut events) = Telemetry::channel(16);
        let (engine, controller) = Engine::controlled(
            PolicySnapshot::compile(config.clone(), 1).unwrap(),
            EngineConfig::default(),
            telemetry,
        );
        for (index, ttl) in [60, 30].into_iter().enumerate() {
            let mut next = config.clone();
            next.policies[0].dns_records[0].ttl = ttl;
            controller
                .prepare(
                    PolicySnapshot::compile(next, index as u64 + 2).unwrap(),
                    PublicationTarget::Shadow,
                    controller.version(),
                )
                .unwrap()
                .commit();
            for transport in [Transport::Udp, Transport::Tcp] {
                let wire = answer(&engine, "NaS.Deep.Lab.Test", kind, transport).await;
                assert_eq!(wire.answers.len(), 1);
                assert_eq!(wire.answers[0].name.to_ascii(), "NaS.Deep.Lab.Test.");
                assert_eq!(wire.answers[0].ttl, 60);
                assert_eq!(wire.answers[0].record_type(), kind);
                assert_eq!(
                    events.recv().await.unwrap().shadow.unwrap().differs,
                    ttl != 60
                );
            }
        }
    }
    let mut config = PolicyConfigSet::default();
    config.upstreams[0].addresses = vec!["127.0.0.1:9".parse().unwrap()];
    config.policies[0].dns_records = (0..32)
        .map(|i| {
            local(
                "*.lab.test",
                LocalData::Txt {
                    text: format!("{i:02}{}", "x".repeat(253)),
                },
            )
        })
        .collect();
    let (telemetry, _events) = Telemetry::channel(16);
    let engine = Engine::with_config(
        PolicySnapshot::compile(config, 1).unwrap(),
        EngineConfig::default(),
        telemetry,
    );
    let udp = answer(&engine, "Deep.Lab.Test", RecordType::TXT, Transport::Udp).await;
    assert!(udp.metadata.truncation);
    assert!(udp.to_vec().unwrap().len() <= 1232);
    let tcp = answer(&engine, "Deep.Lab.Test", RecordType::TXT, Transport::Tcp).await;
    assert!(!tcp.metadata.truncation);
    assert_eq!(tcp.answers.len(), 32);
    for wire in [udp, tcp] {
        assert!(
            wire.answers
                .iter()
                .all(|record| record.name.to_ascii() == "Deep.Lab.Test.")
        );
    }
}
