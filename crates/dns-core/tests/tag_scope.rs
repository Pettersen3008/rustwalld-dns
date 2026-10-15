#![allow(clippy::unwrap_used)]
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, AAAA, CNAME},
    },
};
use rustwalld_dns_core::{
    Engine, EngineConfig, PublicationTarget, Transport, reply, telemetry::Telemetry,
};
use rustwalld_dns_filter::{Action, ListInput, RuleSyntax};
use rustwalld_dns_policy::{Binding, PolicyConfigSet, PolicySnapshot};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::{
    net::UdpSocket,
    sync::Notify,
    time::{Duration, timeout},
};
fn packet(domain: &str, kind: RecordType) -> Vec<u8> {
    let mut q = Message::query();
    q.metadata.recursion_desired = true;
    q.add_query(Query::query(Name::from_ascii(domain).unwrap(), kind));
    q.to_vec().unwrap()
}
async fn answer(engine: &Engine, client: &str, domain: &str, kind: RecordType) -> Message {
    Message::from_vec(
        &engine
            .answer(
                &packet(domain, kind),
                client.parse().unwrap(),
                Transport::Udp,
            )
            .await
            .unwrap(),
    )
    .unwrap()
}
#[tokio::test]
async fn tag_cache_response_scopes_shared_raw_answers_and_pinned_tags_survive_publication() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let calls = count.clone();
    let received = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let got = received.clone();
    let go = release.clone();
    let mock = tokio::spawn(async move {
        let mut buf = [0; 4096];
        loop {
            let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
            let q = Message::from_vec(&buf[..len]).unwrap();
            calls.fetch_add(1, Ordering::SeqCst);
            let query = &q.queries[0];
            if query.name().to_ascii() == "pending.test." {
                got.notify_one();
                go.notified().await;
            }
            let mut response = reply(&q, ResponseCode::NoError);
            let owner = if query.name().to_ascii().contains("direct") {
                query.name().clone()
            } else {
                Name::from_ascii("canon.test.").unwrap()
            };
            if owner != *query.name() {
                response.add_answer(Record::from_rdata(
                    query.name().clone(),
                    600,
                    RData::CNAME(CNAME(owner.clone())),
                ));
            }
            response.add_answer(Record::from_rdata(
                owner,
                600,
                if query.query_type() == RecordType::AAAA {
                    RData::AAAA(AAAA("2001:db8::10".parse().unwrap()))
                } else {
                    RData::A(A("192.0.2.10".parse().unwrap()))
                },
            ));
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let mut config = PolicyConfigSet {
        allowed_clients: vec!["127.0.0.0/24".parse().unwrap()],
        ..Default::default()
    };
    config.upstreams[0].addresses = vec![address];
    config.upstreams[0].timeout_ms = 1000;
    config.bindings = vec![
        Binding {
            name: "Kids".into(),
            network: "127.0.0.1/32".parse().unwrap(),
            policy: "default".into(),
            filter_tags: vec!["user_child".into()],
            metadata: None,
        },
        Binding {
            name: "Adults".into(),
            network: "127.0.0.2/32".parse().unwrap(),
            policy: "default".into(),
            filter_tags: vec!["user_admin".into()],
            metadata: None,
        },
    ];
    config.policies[0].lists=vec![ListInput{name:"v5".into(),syntax:RuleSyntax::AdguardV6,action:Action::Block,rules:"||direct.test^$ctag=user_child,dnstype=AAAA\n||canon.test^$ctag=user_child,dnstype=CNAME\n/^192\\.0\\.2\\.10$/$ctag=user_admin,dnstype=A\n@@||allowed.test^$ctag=user_child".into()}];
    let (telemetry, mut events) = Telemetry::channel(64);
    let (engine, control) = Engine::controlled(
        PolicySnapshot::compile(config.clone(), 1).unwrap(),
        EngineConfig::default(),
        telemetry,
    );
    for _ in 0..2 {
        for (client, kind, rcode) in [
            ("127.0.0.1", RecordType::AAAA, ResponseCode::NXDomain),
            ("127.0.0.2", RecordType::AAAA, ResponseCode::NoError),
            ("127.0.0.1", RecordType::A, ResponseCode::NoError),
        ] {
            assert_eq!(
                answer(&engine, client, "direct.test.", kind)
                    .await
                    .metadata
                    .response_code,
                rcode
            );
            let event = events.recv().await.unwrap();
            assert_eq!(event.matched_type, None);
        }
    }
    assert_eq!(count.load(Ordering::SeqCst), 2);
    for (client, kind, rcode, matched) in [
        ("127.0.0.1", RecordType::A, ResponseCode::NXDomain, Some(5)),
        ("127.0.0.2", RecordType::A, ResponseCode::NXDomain, Some(1)),
        ("127.0.0.3", RecordType::A, ResponseCode::NoError, None),
        ("127.0.0.4", RecordType::A, ResponseCode::NoError, None),
    ] {
        assert_eq!(
            answer(&engine, client, "alias.test.", kind)
                .await
                .metadata
                .response_code,
            rcode
        );
        let event = events.recv().await.unwrap();
        assert_eq!(event.matched_type, matched);
        if client == "127.0.0.4" {
            assert!(event.decision_cached);
        }
    }
    assert_eq!(count.load(Ordering::SeqCst), 3);
    assert_eq!(
        answer(&engine, "127.0.0.1", "allowed.test.", RecordType::A)
            .await
            .metadata
            .response_code,
        ResponseCode::NoError
    );
    events.recv().await.unwrap();
    // Shadow must use its own filtering tags, not the active client's tags.
    let mut shadow = config.clone();
    shadow.bindings[0].filter_tags = vec!["user_regular".into()];
    control
        .prepare(
            PolicySnapshot::compile(shadow.clone(), 2).unwrap(),
            PublicationTarget::Shadow,
            control.version(),
        )
        .unwrap()
        .commit();
    assert_eq!(
        answer(&engine, "127.0.0.1", "alias.test.", RecordType::A)
            .await
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );
    let event = events.recv().await.unwrap();
    assert_eq!(event.shadow.unwrap().decision.action, Action::Allow);
    // A pending query retains the original binding tags through active publication.
    let bytes = packet("pending.test.", RecordType::A);
    let pending = engine.answer(&bytes, "127.0.0.1".parse().unwrap(), Transport::Tcp);
    tokio::pin!(pending);
    tokio::select! {_=received.notified()=>{},_=&mut pending=>panic!("mock did not hold request")};
    control
        .prepare(
            PolicySnapshot::compile(shadow, 3).unwrap(),
            PublicationTarget::Active,
            control.version(),
        )
        .unwrap()
        .commit();
    release.notify_one();
    let response = timeout(Duration::from_secs(2), pending)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        Message::from_vec(&response).unwrap().metadata.response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(events.recv().await.unwrap().generation, 1);
    assert_eq!(
        answer(&engine, "127.0.0.1", "pending.test.", RecordType::A)
            .await
            .metadata
            .response_code,
        ResponseCode::NoError
    );
    assert_eq!(events.recv().await.unwrap().generation, 3);
    mock.abort();
}
