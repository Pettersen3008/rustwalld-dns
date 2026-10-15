#![allow(clippy::unwrap_used)]
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, AAAA, CNAME, NULL},
    },
};
use rustwalld_dns_core::{
    Engine, EngineConfig, PublicationTarget, Transport, reply, telemetry::Telemetry,
};
use rustwalld_dns_filter::{Action, ListInput, RuleSyntax};
use rustwalld_dns_policy::{PolicyConfigSet, PolicySnapshot};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::{
    net::UdpSocket,
    sync::Notify,
    time::{Duration, timeout},
};
fn config(address: std::net::SocketAddr, rules: &str) -> PolicyConfigSet {
    let mut config = PolicyConfigSet::default();
    config.upstreams[0].addresses = vec![address];
    config.upstreams[0].timeout_ms = 1000;
    config.policies[0].lists = vec![ListInput {
        name: "v4".into(),
        action: Action::Block,
        syntax: RuleSyntax::AdguardV4,
        rules: rules.into(),
    }];
    config
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
async fn typed_question_alias_address_caches_and_inflight_snapshots_preserve_raw_data() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let received = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let got = received.clone();
    let go = release.clone();
    let mock = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        loop {
            let (len, peer) = socket.recv_from(&mut bytes).await.unwrap();
            let request = Message::from_vec(&bytes[..len]).unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            let question = &request.queries[0];
            if question.name().to_ascii() == "pending.test." {
                got.notify_one();
                go.notified().await;
            }
            let mut response = reply(&request, ResponseCode::NoError);
            response.metadata.authentic_data = true;
            let alias = question.name().to_ascii() != "direct.test.";
            let owner = if alias {
                Name::from_ascii("canon.test.").unwrap()
            } else {
                question.name().clone()
            };
            if alias {
                response.add_answer(Record::from_rdata(
                    question.name().clone(),
                    600,
                    RData::CNAME(CNAME(owner.clone())),
                ));
            }
            let data = if question.query_type() == RecordType::AAAA {
                RData::AAAA(AAAA("2001:db8::1".parse().unwrap()))
            } else {
                RData::A(A("192.0.2.1".parse().unwrap()))
            };
            response.add_answer(Record::from_rdata(owner.clone(), 600, data));
            let mut signature = vec![0, 1, 8, 2];
            signature.extend(600u32.to_be_bytes());
            signature.extend(2_000_000_000u32.to_be_bytes());
            signature.extend(1_000_000_000u32.to_be_bytes());
            signature.push(0);
            signature.extend([1; 16]);
            response.add_answer(Record::from_rdata(
                owner,
                600,
                RData::Unknown {
                    code: RecordType::RRSIG,
                    rdata: NULL::with(signature),
                },
            ));
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let mut policy = config(
        address,
        "||direct.test^$dnstype=AAAA\n||canon.test^$dnstype=~CNAME",
    );
    let (telemetry, mut events) = Telemetry::channel(64);
    let (engine, controller) = Engine::controlled(
        PolicySnapshot::compile(policy.clone(), 1).unwrap(),
        EngineConfig::default(),
        telemetry,
    );
    for transport in [Transport::Udp, Transport::Tcp] {
        assert_eq!(
            answer(&engine, "direct.test.", RecordType::A, transport)
                .await
                .metadata
                .response_code,
            ResponseCode::NoError
        );
        assert_eq!(
            answer(&engine, "direct.test.", RecordType::AAAA, transport)
                .await
                .metadata
                .response_code,
            ResponseCode::NXDomain
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    for _ in 0..4 {
        let event = events.recv().await.unwrap();
        assert_eq!(
            event.decision.action,
            if event.qtype == 28 {
                Action::Block
            } else {
                Action::Allow
            }
        );
    }
    let allowed = answer(&engine, "alias.test.", RecordType::A, Transport::Udp).await;
    assert!(
        allowed
            .answers
            .iter()
            .any(|record| record.record_type() == RecordType::RRSIG)
    );
    assert!(!allowed.metadata.authentic_data);
    events.recv().await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    policy.policies[0].lists[0].rules =
        "||direct.test^$dnstype=AAAA\n||canon.test^$dnstype=CNAME".into();
    controller
        .prepare(
            PolicySnapshot::compile(policy.clone(), 2).unwrap(),
            PublicationTarget::Active,
            controller.version(),
        )
        .unwrap()
        .commit();
    let blocked = answer(&engine, "alias.test.", RecordType::A, Transport::Tcp).await;
    assert_eq!(blocked.metadata.response_code, ResponseCode::NXDomain);
    assert!(blocked.answers.is_empty());
    assert!(!blocked.metadata.authentic_data);
    let event = events.recv().await.unwrap();
    assert_eq!(event.matched_type, Some(5));
    assert_eq!(event.qtype, 1);
    assert_eq!(event.matched_domain.as_deref(), Some("canon.test"));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    policy.policies[0].lists[0].rules =
        "||canon.test^$dnstype=~CNAME\n/^192\\.0\\.2\\.1$/$dnstype=A".into();
    controller
        .prepare(
            PolicySnapshot::compile(policy.clone(), 3).unwrap(),
            PublicationTarget::Active,
            controller.version(),
        )
        .unwrap()
        .commit();
    assert_eq!(
        answer(&engine, "alias.test.", RecordType::A, Transport::Udp)
            .await
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );
    let event = events.recv().await.unwrap();
    assert_eq!(event.matched_type, Some(1));
    assert_eq!(event.matched_domain.as_deref(), Some("192.0.2.1"));
    policy.policies[0].lists[0].rules =
        "||canon.test^$dnstype=~CNAME\n/^192\\.0\\.2\\.1$/$dnstype=AAAA".into();
    controller
        .prepare(
            PolicySnapshot::compile(policy.clone(), 4).unwrap(),
            PublicationTarget::Active,
            controller.version(),
        )
        .unwrap()
        .commit();
    let allowed = answer(&engine, "alias.test.", RecordType::A, Transport::Tcp).await;
    assert!(
        allowed
            .answers
            .iter()
            .any(|record| record.record_type() == RecordType::RRSIG)
    );
    events.recv().await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let pending_packet = request("pending.test.", RecordType::A);
    let pending = engine.answer(
        &pending_packet,
        "127.0.0.1".parse().unwrap(),
        Transport::Udp,
    );
    tokio::pin!(pending);
    tokio::select! {_=received.notified()=>{},_=&mut pending=>panic!("mock did not hold pending query")};
    policy.policies[0].lists[0].rules = "||canon.test^$dnstype=CNAME".into();
    controller
        .prepare(
            PolicySnapshot::compile(policy.clone(), 5).unwrap(),
            PublicationTarget::Active,
            controller.version(),
        )
        .unwrap()
        .commit();
    release.notify_one();
    let result = timeout(Duration::from_secs(2), pending)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        Message::from_vec(&result).unwrap().metadata.response_code,
        ResponseCode::NoError
    );
    assert_eq!(events.recv().await.unwrap().generation, 4);
    assert_eq!(
        answer(&engine, "pending.test.", RecordType::A, Transport::Udp)
            .await
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(events.recv().await.unwrap().generation, 5);
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    mock.abort();
}
