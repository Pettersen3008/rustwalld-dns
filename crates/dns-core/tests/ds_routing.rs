#![allow(clippy::unwrap_used)]
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{Name, RData, Record, RecordType, rdata::A},
};
use rustwalld_dns_core::{
    Engine, EngineConfig, Prepared, PublicationTarget, Transport, reply, telemetry::Telemetry,
};
use rustwalld_dns_policy::{
    DomainRoute, DsRouting, LocalData, LocalRecord, PolicyConfigSet, PolicySnapshot,
    UpstreamProfile,
};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::net::UdpSocket;
async fn mock(marker: u16) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let counts = calls.clone();
    let task = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        loop {
            let (len, peer) = socket.recv_from(&mut bytes).await.unwrap();
            let request = Message::from_vec(&bytes[..len]).unwrap();
            counts.fetch_add(1, Ordering::SeqCst);
            let question = &request.queries[0];
            assert!(matches!(
                question.name().to_ascii().as_str(),
                "child.test." | "pending.test." | "deep.child.test."
            ));
            let data = match question.query_type() {
                RecordType::DS => {
                    let mut data = marker.to_be_bytes().to_vec();
                    data.extend([8, 2]);
                    data.extend([marker as u8; 32]);
                    RData::Unknown {
                        code: RecordType::DS,
                        rdata: hickory_proto::rr::rdata::NULL::with(data),
                    }
                }
                RecordType::A => RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, marker as u8))),
                other => panic!("unexpected mock type {other}"),
            };
            let mut response = reply(&request, ResponseCode::NoError);
            response.add_answer(Record::from_rdata(question.name().clone(), 600, data));
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    (address, calls, task)
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
fn ds_marker(response: &Message) -> u16 {
    match &response.answers.last().unwrap().data {
        RData::Unknown {
            code: RecordType::DS,
            rdata,
        } => u16::from_be_bytes([rdata.anything[0], rdata.anything[1]]),
        other => panic!("expected DS, got {other:?}"),
    }
}
#[tokio::test]
async fn parent_ds_routing_preserves_questions_cache_types_filters_aliases_and_pinned_generations()
{
    let (parent, parent_calls, parent_task) = mock(10).await;
    let (child, child_calls, child_task) = mock(20).await;
    let mut config = PolicyConfigSet::default();
    config.upstreams[0].addresses = vec![parent];
    config.upstreams.push(UpstreamProfile {
        name: "child".into(),
        addresses: vec![child],
        timeout_ms: 100,
        transport: Default::default(),
    });
    config.policies[0].routes = vec![
        DomainRoute {
            domain: "child.test".into(),
            upstream: "child".into(),
        },
        DomainRoute {
            domain: "pending.test".into(),
            upstream: "child".into(),
        },
    ];
    config.policies[0]
        .lists
        .push(rustwalld_dns_filter::ListInput {
            name: "original-name".into(),
            rules: "=blocked.child.test".into(),
            action: rustwalld_dns_filter::Action::Block,
            syntax: Default::default(),
        });
    config.policies[0].dns_records = vec![
        LocalRecord {
            domain: "local.child.test".into(),
            ttl: 60,
            data: LocalData::A {
                address: "192.0.2.99".parse().unwrap(),
            },
        },
        LocalRecord {
            domain: "alias.test".into(),
            ttl: 60,
            data: LocalData::Cname {
                target: "child.test".into(),
            },
        },
    ];
    let (telemetry, _events) = Telemetry::channel(32);
    let (engine, controller) = Engine::controlled(
        PolicySnapshot::compile(config.clone(), 1).unwrap(),
        EngineConfig::default(),
        telemetry,
    );
    assert_eq!(
        ds_marker(&answer(&engine, "child.test", RecordType::DS, Transport::Udp).await),
        20
    );
    let pending = match engine.prepare(
        &request("pending.test", RecordType::DS),
        "127.0.0.1".parse().unwrap(),
        Transport::Udp,
    ) {
        Prepared::Forward(pending) => pending,
        _ => panic!("expected pending lookup"),
    };
    config.policies[0].ds_routing = DsRouting::Parent;
    controller
        .prepare(
            PolicySnapshot::compile(config.clone(), 2).unwrap(),
            PublicationTarget::Shadow,
            controller.version(),
        )
        .unwrap()
        .commit();
    assert_eq!(
        ds_marker(&answer(&engine, "child.test", RecordType::DS, Transport::Tcp).await),
        20
    );
    assert_eq!(parent_calls.load(Ordering::SeqCst), 0);
    controller
        .prepare(
            PolicySnapshot::compile(config.clone(), 3).unwrap(),
            PublicationTarget::Active,
            controller.version(),
        )
        .unwrap()
        .commit();
    let old = Message::from_vec(&engine.forward(pending).await.unwrap()).unwrap();
    assert_eq!(ds_marker(&old), 20);
    for transport in [Transport::Udp, Transport::Tcp] {
        let response = answer(&engine, "child.test", RecordType::DS, transport).await;
        assert_eq!(
            response.queries[0].name(),
            &Name::from_ascii("child.test.").unwrap()
        );
        assert_eq!(response.queries[0].query_type(), RecordType::DS);
        assert_eq!(ds_marker(&response), 10);
    }
    assert_eq!(parent_calls.load(Ordering::SeqCst), 1);
    let mut flagged = Message::from_vec(&request("child.test", RecordType::DS)).unwrap();
    flagged.metadata.checking_disabled = true;
    let mut edns = hickory_proto::op::Edns::new();
    edns.set_dnssec_ok(true);
    flagged.edns = Some(edns);
    for _ in 0..2 {
        let response = Message::from_vec(
            &engine
                .answer(
                    &flagged.to_vec().unwrap(),
                    "127.0.0.1".parse().unwrap(),
                    Transport::Udp,
                )
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(ds_marker(&response), 10);
        assert!(response.metadata.checking_disabled);
    }
    assert_eq!(parent_calls.load(Ordering::SeqCst), 2); // DO/CD differs from the previous cache key.

    assert_eq!(
        ds_marker(&answer(&engine, "pending.test", RecordType::DS, Transport::Udp).await),
        10
    );
    assert_eq!(
        ds_marker(&answer(&engine, "deep.child.test", RecordType::DS, Transport::Udp).await),
        20
    );
    let a = answer(&engine, "child.test", RecordType::A, Transport::Tcp).await;
    assert!(matches!(&a.answers[0].data,RData::A(address) if address.0.octets()[3]==20));
    let before = parent_calls.load(Ordering::SeqCst) + child_calls.load(Ordering::SeqCst);
    assert_eq!(
        answer(
            &engine,
            "blocked.child.test",
            RecordType::DS,
            Transport::Udp
        )
        .await
        .response_code,
        ResponseCode::NXDomain
    );
    assert!(
        answer(&engine, "local.child.test", RecordType::DS, Transport::Tcp)
            .await
            .answers
            .is_empty()
    );
    assert_eq!(
        parent_calls.load(Ordering::SeqCst) + child_calls.load(Ordering::SeqCst),
        before
    );
    let alias = answer(&engine, "alias.test", RecordType::DS, Transport::Udp).await;
    assert_eq!(alias.answers.len(), 2);
    assert_eq!(ds_marker(&alias), 10);
    assert_eq!(parent_calls.load(Ordering::SeqCst), 3);
    assert_eq!(child_calls.load(Ordering::SeqCst), 4);
    config.policies[0].ds_routing = DsRouting::Question;
    controller
        .prepare(
            PolicySnapshot::compile(config, 4).unwrap(),
            PublicationTarget::Active,
            controller.version(),
        )
        .unwrap()
        .commit();
    assert_eq!(
        ds_marker(&answer(&engine, "child.test", RecordType::DS, Transport::Udp).await),
        20
    );
    assert_eq!(child_calls.load(Ordering::SeqCst), 4); // Same resolver identity safely reuses its raw DS answer.
    parent_task.abort();
    child_task.abort();
}
