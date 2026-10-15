#![allow(clippy::unwrap_used)]
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, CNAME},
    },
};
use rustwalld_dns_core::{
    Engine, EngineConfig, PublicationTarget, Transport, reply, telemetry::Telemetry,
};
use rustwalld_dns_filter::{Action, ListInput, RuleSyntax};
use rustwalld_dns_policy::{
    Binding, BlockedServices, PolicyConfigSet, PolicySnapshot, SafeSearchConfig,
    TemporaryException, YouTubeMode,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::net::UdpSocket;
struct Mock {
    address: std::net::SocketAddr,
    count: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Mock {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Mock {
    async fn start() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let hits = count.clone();
        let task = tokio::spawn(async move {
            let mut data = [0; 4096];
            loop {
                let (len, peer) = socket.recv_from(&mut data).await.unwrap();
                let request = Message::from_vec(&data[..len]).unwrap();
                hits.fetch_add(1, Ordering::Relaxed);
                let question = &request.queries[0];
                let mut response = reply(&request, ResponseCode::NoError);
                let name = if question.name().to_ascii() == "alias.test." {
                    let target = Name::from_ascii("www.youtube.com.").unwrap();
                    response.add_answer(Record::from_rdata(
                        question.name().clone(),
                        60,
                        RData::CNAME(CNAME(target.clone())),
                    ));
                    target
                } else {
                    question.name().clone()
                };
                response.add_answer(Record::from_rdata(
                    name,
                    60,
                    RData::A(A("192.0.2.10".parse().unwrap())),
                ));
                socket
                    .send_to(&response.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        Self {
            address,
            count,
            task,
        }
    }
    fn config(&self) -> PolicyConfigSet {
        let mut config = PolicyConfigSet::default();
        config.upstreams[0].addresses = vec![self.address];
        config.allowed_clients = vec!["127.0.0.0/8".parse().unwrap()];
        config
    }
}
fn services() -> BlockedServices {
    BlockedServices {
        catalog_version: 1,
        ids: vec!["youtube".into(), "tiktok".into()],
        schedule: None,
    }
}
async fn query(engine: &Engine, client: &str, domain: &str, kind: RecordType) -> Message {
    let mut request = Message::query();
    request.metadata.id = 72;
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(Name::from_ascii(domain).unwrap(), kind));
    let response = Message::from_vec(
        &engine
            .answer(
                &request.to_vec().unwrap(),
                client.parse().unwrap(),
                Transport::Udp,
            )
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(response.metadata.id, 72);
    assert_eq!(
        response.queries[0].name().to_ascii().trim_end_matches('.'),
        request.queries[0].name().to_ascii().trim_end_matches('.')
    );
    response
}
#[tokio::test]
async fn service_client_scope_cached_cname_shadow_promotion_and_rollback_use_policy_generations() {
    let mock = Mock::start().await;
    let mut config = mock.config();
    let mut child = config.policies[0].clone();
    child.name = "child".into();
    child.blocked_services = Some(services());
    child.safe_search = Some(SafeSearchConfig {
        youtube: YouTubeMode::Strict,
        ..Default::default()
    });
    config.policies.push(child);
    config.bindings = vec![Binding {
        network: "127.0.0.2/32".parse().unwrap(),
        policy: "child".into(),
        name: "child device".into(),
        filter_tags: Vec::new(),
        metadata: None,
    }];
    let (telemetry, mut events) = Telemetry::channel(32);
    let (engine, control) = Engine::controlled(
        PolicySnapshot::compile(config.clone(), 1).unwrap(),
        EngineConfig::default(),
        telemetry,
    );
    assert_eq!(
        query(&engine, "127.0.0.1", "WWW.YouTube.Com.", RecordType::A)
            .await
            .metadata
            .response_code,
        ResponseCode::NoError
    );
    events.recv().await.unwrap();
    let before = mock.count.load(Ordering::Relaxed);
    for kind in [
        RecordType::A,
        RecordType::AAAA,
        RecordType::CNAME,
        RecordType::HTTPS,
    ] {
        assert_eq!(
            query(&engine, "127.0.0.2", "www.youtube.com", kind)
                .await
                .metadata
                .response_code,
            ResponseCode::NXDomain
        );
        let event = events.recv().await.unwrap();
        assert_eq!(event.policy, 1);
        assert!(event.decision.rule.is_some());
    }
    assert_eq!(mock.count.load(Ordering::Relaxed), before);
    assert_eq!(
        query(&engine, "127.0.0.1", "alias.test", RecordType::A)
            .await
            .answers
            .len(),
        2
    );
    events.recv().await.unwrap();
    config.policies[0].blocked_services = Some(services());
    control
        .prepare(
            PolicySnapshot::compile(config.clone(), 2).unwrap(),
            PublicationTarget::Shadow,
            control.version(),
        )
        .unwrap()
        .commit();
    assert_eq!(
        query(&engine, "127.0.0.1", "www.youtube.com", RecordType::A)
            .await
            .metadata
            .response_code,
        ResponseCode::NoError
    );
    assert!(events.recv().await.unwrap().shadow.unwrap().differs);
    control
        .prepare(
            PolicySnapshot::compile(config.clone(), 3).unwrap(),
            PublicationTarget::Active,
            control.version(),
        )
        .unwrap()
        .commit();
    let before = mock.count.load(Ordering::Relaxed);
    assert_eq!(
        query(&engine, "127.0.0.1", "www.youtube.com", RecordType::A)
            .await
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );
    events.recv().await.unwrap();
    assert_eq!(
        query(&engine, "127.0.0.1", "alias.test", RecordType::A)
            .await
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );
    let event = events.recv().await.unwrap();
    assert_eq!(event.matched_domain.as_deref(), Some("www.youtube.com"));
    assert!(event.decision.rule.is_some());
    assert_eq!(mock.count.load(Ordering::Relaxed), before);
    config.policies[0].blocked_services = None;
    control
        .prepare(
            PolicySnapshot::compile(config, 4).unwrap(),
            PublicationTarget::Active,
            control.version(),
        )
        .unwrap()
        .commit();
    assert_eq!(
        query(&engine, "127.0.0.1", "alias.test", RecordType::A)
            .await
            .answers
            .len(),
        2
    );
    assert_eq!(
        query(&engine, "127.0.0.2", "www.youtube.com", RecordType::A)
            .await
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );
}
#[tokio::test]
async fn service_allow_local_and_expiring_temporary_overrides_keep_existing_semantics() {
    let mock = Mock::start().await;
    let mut config = mock.config();
    config.policies[0].blocked_services = Some(services());
    config.policies[0].lists = vec![ListInput {
        name: "allow".into(),
        action: Action::Allow,
        syntax: RuleSyntax::Native,
        rules: "=support.tiktok.com".into(),
    }];
    config.policies[0].rewrites = vec![rustwalld_dns_policy::Rewrite {
        domain: "local.youtube.com".into(),
        addresses: vec!["192.0.2.99".parse().unwrap()],
        ttl: 60,
    }];
    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 2;
    config.policies[0].temporary_exceptions = vec![TemporaryException {
        name: "repair".into(),
        domain: "www.youtube.com".into(),
        expires_at: expiry,
        clients: vec![],
        include_subdomains: false,
    }];
    let (telemetry, _) = Telemetry::channel(16);
    let (engine, _) = Engine::controlled(
        PolicySnapshot::compile(config, 1).unwrap(),
        EngineConfig::default(),
        telemetry,
    );
    assert_eq!(
        query(&engine, "127.0.0.1", "support.tiktok.com", RecordType::A)
            .await
            .metadata
            .response_code,
        ResponseCode::NoError
    );
    let local = query(&engine, "127.0.0.1", "local.youtube.com", RecordType::A).await;
    assert!(
        matches!(&local.answers[0].data,RData::A(ip) if ip.0=="192.0.2.99".parse::<std::net::Ipv4Addr>().unwrap())
    );
    let temporary = query(&engine, "127.0.0.1", "www.youtube.com", RecordType::A).await;
    assert_eq!(temporary.metadata.response_code, ResponseCode::NoError);
    assert!(temporary.answers[0].ttl <= 2);
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let before = mock.count.load(Ordering::Relaxed);
    assert_eq!(
        query(&engine, "127.0.0.1", "www.youtube.com", RecordType::A)
            .await
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(mock.count.load(Ordering::Relaxed), before);
}

#[tokio::test]
async fn expanded_groups_block_without_upstream_and_allow_neighbors_scoped_clients_and_pauses() {
    let mock = Mock::start().await;
    let mut config = mock.config();
    let mut child = config.policies[0].clone();
    child.name = "child".into();
    child.blocked_services = Some(BlockedServices {
        catalog_version: 2,
        ids: rustwalld_dns_policy::service_catalog_for_version(2)
            .unwrap()
            .iter()
            .map(|group| group.id.into())
            .collect(),
        schedule: None,
    });
    child.lists.push(ListInput {
        name: "support".into(),
        action: Action::Allow,
        syntax: RuleSyntax::Native,
        rules: "=help.netflix.com".into(),
    });
    config.policies.push(child);
    config.bindings.push(Binding {
        name: "child".into(),
        network: "127.0.0.2/32".parse().unwrap(),
        policy: "child".into(),
        filter_tags: Vec::new(),
        metadata: None,
    });
    let (engine, control) = Engine::controlled(
        PolicySnapshot::compile(config.clone(), 1).unwrap(),
        EngineConfig::default(),
        Telemetry::channel(8).0,
    );
    for group in rustwalld_dns_policy::service_catalog_for_version(2).unwrap() {
        for name in group.suffixes.iter().chain(group.exact_names) {
            assert_eq!(
                query(&engine, "127.0.0.2", name, RecordType::AAAA)
                    .await
                    .metadata
                    .response_code,
                ResponseCode::NXDomain
            );
        }
    }
    assert_eq!(mock.count.load(Ordering::Relaxed), 0);
    for (client, domain) in [
        ("127.0.0.1", "www.netflix.com"),
        ("127.0.0.2", "notnetflix.com"),
        ("127.0.0.2", "help.netflix.com"),
        ("127.0.0.2", "google.com"),
    ] {
        assert_eq!(
            query(&engine, client, domain, RecordType::A)
                .await
                .metadata
                .response_code,
            ResponseCode::NoError
        );
    }
    let count = mock.count.load(Ordering::Relaxed);
    config.policies[1]
        .blocked_services
        .as_mut()
        .unwrap()
        .schedule = Some(rustwalld_dns_policy::WeeklySchedule {
        time_zone: "UTC".into(),
        mode: rustwalld_dns_policy::ScheduleMode::Block,
        windows: vec![],
    });
    control
        .prepare(
            PolicySnapshot::compile(config, 2).unwrap(),
            PublicationTarget::Active,
            control.version(),
        )
        .unwrap()
        .commit();
    assert_eq!(
        query(&engine, "127.0.0.2", "www.netflix.com", RecordType::A)
            .await
            .metadata
            .response_code,
        ResponseCode::NoError
    );
    assert_eq!(mock.count.load(Ordering::Relaxed), count); // Existing raw answer rechecked under scheduled service-off.
}
