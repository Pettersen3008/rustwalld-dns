#![allow(clippy::unwrap_used)]
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, AAAA, CNAME},
    },
};
use rustwalld_dns_core::{
    Engine, EngineConfig, PublicationTarget, Transport, reply,
    telemetry::{QuerySource, Telemetry},
};
use rustwalld_dns_filter::{Action, ListInput};
use rustwalld_dns_policy::{
    Binding, PolicyConfigSet, PolicySnapshot, SafeSearchConfig, YouTubeMode,
};
use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{net::UdpSocket, task::JoinHandle};
struct Mock {
    address: SocketAddr,
    count: Arc<AtomicUsize>,
    mode: Arc<AtomicUsize>,
    names: Arc<Mutex<Vec<String>>>,
    job: JoinHandle<()>,
}
impl Drop for Mock {
    fn drop(&mut self) {
        self.job.abort();
    }
}
impl Mock {
    async fn start() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let mode = Arc::new(AtomicUsize::new(0));
        let names = Arc::new(Mutex::new(Vec::new()));
        let (hits, state, queries) = (count.clone(), mode.clone(), names.clone());
        let job = tokio::spawn(async move {
            let mut buffer = [0; 4096];
            loop {
                let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
                let request = Message::from_vec(&buffer[..len]).unwrap();
                let question = &request.queries[0];
                let name = question.name().to_ascii().to_ascii_lowercase();
                {
                    let mut names = queries.lock().unwrap();
                    if names.len() < 128 {
                        names.push(name.clone());
                    }
                }
                hits.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(10)).await;
                let mut response = reply(
                    &request,
                    if state.load(Ordering::Relaxed) == 1 {
                        ResponseCode::ServFail
                    } else {
                        ResponseCode::NoError
                    },
                );
                if state.load(Ordering::Relaxed) == 2 {
                    response.add_answer(Record::from_rdata(
                        question.name().clone(),
                        60,
                        RData::CNAME(CNAME(Name::from_ascii("www.google.com.").unwrap())),
                    ));
                } else if response.metadata.response_code == ResponseCode::NoError {
                    let safe = name.starts_with("forcesafesearch.")
                        || name.starts_with("strict.")
                        || name.starts_with("safe.")
                        || name.starts_with("restrict");
                    let data = match question.query_type() {
                        RecordType::A => {
                            Some(RData::A(A(if safe { "192.0.2.20" } else { "192.0.2.10" }
                                .parse()
                                .unwrap())))
                        }
                        RecordType::AAAA => Some(RData::AAAA(AAAA(
                            if safe { "2001:db8::20" } else { "2001:db8::10" }
                                .parse()
                                .unwrap(),
                        ))),
                        _ => None,
                    };
                    if let Some(data) = data {
                        response.add_answer(Record::from_rdata(question.name().clone(), 60, data));
                    }
                }
                socket
                    .send_to(&response.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        Self {
            address,
            count,
            mode,
            names,
            job,
        }
    }
    fn config(&self) -> PolicyConfigSet {
        let mut config = PolicyConfigSet {
            allowed_clients: vec!["127.0.0.0/8".parse().unwrap()],
            ..Default::default()
        };
        config.upstreams[0].addresses = vec![self.address];
        config
    }
}
fn settings() -> SafeSearchConfig {
    SafeSearchConfig {
        google: true,
        bing: true,
        duckduckgo: true,
        youtube: YouTubeMode::Strict,
        ..Default::default()
    }
}
async fn query(engine: &Engine, client: &str, domain: &str, kind: RecordType) -> Message {
    let mut request = Message::query();
    request.metadata.id = 42;
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(Name::from_ascii(domain).unwrap(), kind));
    let bytes = engine
        .answer(
            &request.to_vec().unwrap(),
            client.parse().unwrap(),
            Transport::Udp,
        )
        .await
        .unwrap();
    let answer = Message::from_vec(&bytes).unwrap();
    assert_eq!(answer.metadata.id, 42);
    assert_eq!(
        answer.queries[0].name().to_ascii().trim_end_matches('.'),
        request.queries[0].name().to_ascii().trim_end_matches('.')
    );
    answer
}
#[tokio::test]
async fn client_scope_aaaa_cname_cache_and_country_coalescing_use_only_provider_targets() {
    let mock = Mock::start().await;
    let mut config = mock.config();
    let mut child = config.policies[0].clone();
    child.name = "child".into();
    child.safe_search = Some(settings());
    config.policies.push(child);
    config.bindings = vec![Binding {
        network: "127.0.0.2/32".parse().unwrap(),
        policy: "child".into(),
        name: "child device".into(),
        filter_tags: Vec::new(),
        metadata: None,
    }];
    let (telemetry, mut events) = Telemetry::channel(64);
    let (engine, _) = Engine::controlled(
        PolicySnapshot::compile(config, 1).unwrap(),
        EngineConfig::default(),
        telemetry,
    );
    let normal = query(&engine, "127.0.0.1", "www.google.com", RecordType::A).await;
    assert!(
        matches!(&normal.answers[0].data,RData::A(ip) if ip.0=="192.0.2.10".parse::<std::net::Ipv4Addr>().unwrap())
    );
    let first = query(&engine, "127.0.0.2", "WWW.Google.Com.", RecordType::A).await;
    assert_eq!(first.answers.len(), 2);
    assert!(
        matches!(&first.answers[0].data,RData::CNAME(target) if target.0.to_ascii()=="forcesafesearch.google.com.")
    );
    let before = mock.count.load(Ordering::Relaxed);
    let cached = query(&engine, "127.0.0.2", "www.google.no", RecordType::A).await;
    assert_eq!(cached.answers.len(), 2);
    assert_eq!(mock.count.load(Ordering::Relaxed), before);
    let ipv6 = query(&engine, "127.0.0.2", "www.google.com", RecordType::AAAA).await;
    assert!(
        matches!(&ipv6.answers[1].data,RData::AAAA(ip) if ip.0=="2001:db8::20".parse::<std::net::Ipv6Addr>().unwrap())
    );
    let before = mock.count.load(Ordering::Relaxed);
    let cname = query(&engine, "127.0.0.2", "www.google.com", RecordType::CNAME).await;
    assert_eq!(cname.answers.len(), 1);
    assert_eq!(mock.count.load(Ordering::Relaxed), before);
    assert_eq!(events.recv().await.unwrap().source, QuerySource::Upstream);
    for _ in 0..4 {
        assert_eq!(events.recv().await.unwrap().source, QuerySource::SafeSearch);
    }
    // Different original owners share a cold provider flight, with private prefixes.
    let before = mock.count.load(Ordering::Relaxed);
    let (one, two) = tokio::join!(
        query(&engine, "127.0.0.2", "www.bing.com", RecordType::A),
        query(&engine, "127.0.0.2", "edgeservices.bing.com", RecordType::A)
    );
    assert_eq!(one.answers[0].name.to_ascii(), "www.bing.com.");
    assert_eq!(two.answers[0].name.to_ascii(), "edgeservices.bing.com.");
    assert_eq!(mock.count.load(Ordering::Relaxed) - before, 1);
}
#[tokio::test]
async fn filter_blocks_provider_blocks_loops_and_outages_never_unblock_search() {
    let mock = Mock::start().await;
    let mut config = mock.config();
    config.policies[0].safe_search = Some(settings());
    config.policies[0].lists = vec![ListInput {
        name: "privacy".into(),
        action: Action::Block,
        rules: "www.google.com".into(),
        syntax: Default::default(),
    }];
    let (telemetry, mut events) = Telemetry::channel(32);
    let (engine, control) = Engine::controlled(
        PolicySnapshot::compile(config.clone(), 1).unwrap(),
        EngineConfig::default(),
        telemetry,
    );
    assert_eq!(
        query(&engine, "127.0.0.1", "www.google.com", RecordType::A)
            .await
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(mock.count.load(Ordering::Relaxed), 0);
    assert_eq!(events.recv().await.unwrap().source, QuerySource::Blocked);
    config.policies[0].lists[0].rules = "forcesafesearch.google.com".into();
    control
        .prepare(
            PolicySnapshot::compile(config.clone(), 2).unwrap(),
            PublicationTarget::Active,
            control.version(),
        )
        .unwrap()
        .commit();
    assert_eq!(
        query(&engine, "127.0.0.1", "www.google.com", RecordType::A)
            .await
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );
    let event = events.recv().await.unwrap();
    assert_eq!(
        event.matched_domain.as_deref(),
        Some("forcesafesearch.google.com")
    );
    assert_eq!(event.source, QuerySource::Blocked);
    config.policies[0].lists.clear();
    mock.mode.store(2, Ordering::Relaxed);
    control
        .prepare(
            PolicySnapshot::compile(config.clone(), 3).unwrap(),
            PublicationTarget::Active,
            control.version(),
        )
        .unwrap()
        .commit();
    assert_eq!(
        query(&engine, "127.0.0.1", "www.google.com", RecordType::AAAA)
            .await
            .metadata
            .response_code,
        ResponseCode::ServFail
    );
    assert_eq!(events.recv().await.unwrap().source, QuerySource::Failure);
    mock.mode.store(1, Ordering::Relaxed);
    control
        .prepare(
            PolicySnapshot::compile(config, 4).unwrap(),
            PublicationTarget::Active,
            control.version(),
        )
        .unwrap()
        .commit();
    assert_eq!(
        query(&engine, "127.0.0.1", "www.google.com", RecordType::HTTPS)
            .await
            .metadata
            .response_code,
        ResponseCode::ServFail
    );
    assert_eq!(events.recv().await.unwrap().source, QuerySource::Failure);
    assert!(
        mock.names
            .lock()
            .unwrap()
            .iter()
            .all(|name| name == "forcesafesearch.google.com.")
    );
}
#[tokio::test]
async fn shadow_changes_and_fresh_generations_do_not_reuse_an_unrestricted_answer() {
    let mock = Mock::start().await;
    let mut config = mock.config();
    let (telemetry, mut events) = Telemetry::channel(32);
    let (engine, control) = Engine::controlled(
        PolicySnapshot::compile(config.clone(), 1).unwrap(),
        EngineConfig::default(),
        telemetry,
    );
    query(&engine, "127.0.0.1", "www.youtube.com", RecordType::A).await;
    events.recv().await.unwrap();
    config.policies[0].safe_search = Some(settings());
    control
        .prepare(
            PolicySnapshot::compile(config.clone(), 2).unwrap(),
            PublicationTarget::Shadow,
            control.version(),
        )
        .unwrap()
        .commit();
    let still_normal = query(&engine, "127.0.0.1", "www.youtube.com", RecordType::A).await;
    assert_eq!(still_normal.answers.len(), 1);
    assert!(events.recv().await.unwrap().shadow.unwrap().differs);
    control
        .prepare(
            PolicySnapshot::compile(config.clone(), 3).unwrap(),
            PublicationTarget::Active,
            control.version(),
        )
        .unwrap()
        .commit();
    let strict = query(&engine, "127.0.0.1", "www.youtube.com", RecordType::A).await;
    assert!(
        matches!(&strict.answers[0].data,RData::CNAME(target) if target.0.to_ascii()=="restrict.youtube.com.")
    );
    events.recv().await.unwrap();
    config.policies[0].safe_search.as_mut().unwrap().youtube = YouTubeMode::Moderate;
    control
        .prepare(
            PolicySnapshot::compile(config.clone(), 4).unwrap(),
            PublicationTarget::Shadow,
            control.version(),
        )
        .unwrap()
        .commit();
    query(&engine, "127.0.0.1", "www.youtube.com", RecordType::A).await;
    assert!(events.recv().await.unwrap().shadow.unwrap().differs);
    control
        .prepare(
            PolicySnapshot::compile(config.clone(), 5).unwrap(),
            PublicationTarget::Active,
            control.version(),
        )
        .unwrap()
        .commit();
    let moderate = query(&engine, "127.0.0.1", "www.youtube.com", RecordType::A).await;
    assert!(
        matches!(&moderate.answers[0].data,RData::CNAME(target) if target.0.to_ascii()=="restrictmoderate.youtube.com.")
    );
    events.recv().await.unwrap();
    config.policies[0].safe_search = None;
    control
        .prepare(
            PolicySnapshot::compile(config, 6).unwrap(),
            PublicationTarget::Active,
            control.version(),
        )
        .unwrap()
        .commit();
    assert_eq!(
        query(&engine, "127.0.0.1", "www.youtube.com", RecordType::A)
            .await
            .answers
            .len(),
        1
    );
}

#[tokio::test]
async fn temporary_filter_allow_keeps_safesearch_and_clamps_alias_ttl_until_expiry() {
    let mock = Mock::start().await;
    let mut config = mock.config();
    config.policies[0].safe_search = Some(settings());
    config.policies[0].lists = vec![ListInput {
        name: "block-search".into(),
        action: Action::Block,
        rules: "www.google.com".into(),
        syntax: Default::default(),
    }];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    config.policies[0].temporary_exceptions = vec![rustwalld_dns_policy::TemporaryException {
        name: "repair".into(),
        domain: "www.google.com".into(),
        expires_at: now + 2,
        clients: vec![],
        include_subdomains: false,
    }];
    let (telemetry, mut events) = Telemetry::channel(16);
    let (engine, control) = Engine::controlled(
        PolicySnapshot::compile(config.clone(), 1).unwrap(),
        EngineConfig::default(),
        telemetry,
    );
    control
        .prepare(
            PolicySnapshot::compile(config, 2).unwrap(),
            PublicationTarget::Shadow,
            control.version(),
        )
        .unwrap()
        .commit();
    let allowed = query(&engine, "127.0.0.1", "www.google.com", RecordType::A).await;
    assert_eq!(allowed.answers.len(), 2);
    assert!(allowed.answers.iter().all(|record| record.ttl <= 2));
    let event = events.recv().await.unwrap();
    assert_eq!(event.source, QuerySource::SafeSearch);
    assert!(event.temporary_exception.is_some());
    assert!(!event.shadow.unwrap().differs);
    tokio::time::sleep(Duration::from_millis(2100)).await;
    assert_eq!(
        query(&engine, "127.0.0.1", "www.google.com", RecordType::A)
            .await
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );
    let event = events.recv().await.unwrap();
    assert_eq!(event.source, QuerySource::Blocked);
    assert!(!event.shadow.unwrap().differs);
    assert_eq!(mock.count.load(Ordering::Relaxed), 1);
}
#[tokio::test]
async fn ordinary_local_aliases_keep_filter_precedence_but_reject_external_loops() {
    let mock = Mock::start().await;
    let mut config = mock.config();
    config.policies[0].dns_records = vec![rustwalld_dns_policy::LocalRecord {
        domain: "www.google.com".into(),
        ttl: 60,
        data: rustwalld_dns_policy::LocalData::Cname {
            target: "forcesafesearch.google.com".into(),
        },
    }];
    config.policies[0].lists = vec![ListInput {
        name: "deny".into(),
        action: Action::Block,
        rules: "www.google.com\nforcesafesearch.google.com".into(),
        syntax: Default::default(),
    }];
    let (telemetry, mut events) = Telemetry::channel(16);
    let (engine, _) = Engine::controlled(
        PolicySnapshot::compile(config, 1).unwrap(),
        EngineConfig::default(),
        telemetry,
    );
    assert_eq!(
        query(&engine, "127.0.0.1", "www.google.com", RecordType::A)
            .await
            .metadata
            .response_code,
        ResponseCode::NoError
    );
    assert_eq!(events.recv().await.unwrap().source, QuerySource::Rewrite);
    mock.mode.store(2, Ordering::Relaxed);
    assert_eq!(
        query(&engine, "127.0.0.1", "www.google.com", RecordType::AAAA)
            .await
            .metadata
            .response_code,
        ResponseCode::ServFail
    );
    assert_eq!(events.recv().await.unwrap().source, QuerySource::Failure);
    let counters = engine.telemetry().metrics.snapshot();
    assert_eq!(counters.rewrites, 1);
    assert_eq!(counters.failures, 1);
}
