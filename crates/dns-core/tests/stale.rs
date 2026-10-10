#![allow(clippy::unwrap_used)]
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{Name, RData, Record, RecordType, rdata::A},
};
use rustwalld_dns_core::{
    Action, Engine, EngineConfig, ListInput, PolicyConfigSet, PolicySnapshot, Prepared,
    PublicationTarget, Rewrite, ServeStale, TemporaryException, Transport,
    telemetry::{QuerySource, Telemetry},
};
use rustwalld_dns_resolver::response_cache::CacheKey;
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{net::UdpSocket, task::JoinHandle};

struct Mock {
    address: SocketAddr,
    mode: Arc<AtomicU8>,
    hits: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}
impl Mock {
    async fn start(ip: &str) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let mode = Arc::new(AtomicU8::new(0));
        let hits = Arc::new(AtomicUsize::new(0));
        let (observed_mode, counts) = (mode.clone(), hits.clone());
        let ip = ip.parse().unwrap();
        let task = tokio::spawn(async move {
            let mut buffer = [0; 4096];
            loop {
                let Ok((len, peer)) = socket.recv_from(&mut buffer).await else {
                    return;
                };
                counts.fetch_add(1, Ordering::Relaxed);
                let current = observed_mode.load(Ordering::Relaxed);
                if current == 2 {
                    continue;
                }
                let request = Message::from_vec(&buffer[..len]).unwrap();
                let mut response = request.into_response();
                if current == 1 {
                    response.metadata.response_code = ResponseCode::ServFail;
                } else {
                    response.add_answer(Record::from_rdata(
                        response.queries[0].name().clone(),
                        u32::from(current != 3),
                        RData::A(A(ip)),
                    ));
                }
                let _ = socket.send_to(&response.to_vec().unwrap(), peer).await;
            }
        });
        Self {
            address,
            mode,
            hits,
            task,
        }
    }
}
impl Drop for Mock {
    fn drop(&mut self) {
        self.task.abort();
    }
}
fn query() -> Message {
    let mut request = Message::new(7, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(
        Name::from_ascii("stale.test.").unwrap(),
        RecordType::A,
    ));
    request
}
fn policy(addresses: Vec<SocketAddr>) -> PolicyConfigSet {
    let mut config = PolicyConfigSet::default();
    config.upstreams[0].addresses = addresses;
    config.upstreams[0].timeout_ms = 40;
    config
}
fn settings(seconds: u64) -> EngineConfig {
    EngineConfig {
        cache_entries: 64,
        max_inflight: 8,
        serve_stale: ServeStale::new(Duration::from_secs(seconds)).unwrap(),
        ..Default::default()
    }
}
async fn answer(engine: &Engine) -> Message {
    Message::from_vec(
        &engine
            .answer(
                &query().to_vec().unwrap(),
                "127.0.0.1".parse().unwrap(),
                Transport::Udp,
            )
            .await
            .unwrap(),
    )
    .unwrap()
}
fn seed_expired(engine: &Engine) {
    let request = query();
    let key = CacheKey::new(&request, engine.active().upstreams()[0].id()).unwrap();
    let mut response = request.into_response();
    response.add_answer(Record::from_rdata(
        key.query.name().clone(),
        1,
        RData::A(A("192.0.2.1".parse().unwrap())),
    ));
    engine
        .resolver()
        .cache
        .insert(key, response, Instant::now() - Duration::from_secs(2));
}

#[tokio::test]
async fn outage_uses_stale_only_when_enabled_and_recovers_to_fresh() {
    for enabled in [false, true] {
        let first = Mock::start("192.0.2.1").await;
        let second = Mock::start("192.0.2.2").await;
        let (telemetry, mut events) = Telemetry::channel(16);
        let engine = Engine::with_config(
            PolicySnapshot::compile(policy(vec![first.address, second.address]), 1).unwrap(),
            settings(if enabled { 60 } else { 0 }),
            telemetry,
        );
        assert_eq!(answer(&engine).await.answers[0].ttl, 1);
        assert_eq!(events.try_recv().unwrap().source, QuerySource::Upstream);
        assert_eq!(answer(&engine).await.answers[0].ttl, 1);
        assert_eq!(events.try_recv().unwrap().source, QuerySource::Cache);
        first.mode.store(1, Ordering::Relaxed);
        second.mode.store(2, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(1050)).await;
        let response = answer(&engine).await;
        if enabled {
            assert_eq!(response.answers[0].ttl, 30);
            assert_eq!(
                response.answers[0].data,
                RData::A(A("192.0.2.1".parse().unwrap()))
            );
            assert_eq!(events.try_recv().unwrap().source, QuerySource::Stale);
            assert_eq!(engine.telemetry().metrics.snapshot().stale_answers, 1);
        } else {
            assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
            assert_eq!(events.try_recv().unwrap().source, QuerySource::Failure);
            assert_eq!(engine.telemetry().metrics.snapshot().stale_answers, 0);
        }
        assert_eq!(first.hits.load(Ordering::Relaxed), 2);
        assert_eq!(second.hits.load(Ordering::Relaxed), 1);
        first.mode.store(0, Ordering::Relaxed);
        assert_eq!(answer(&engine).await.answers[0].ttl, 1);
        assert_eq!(events.try_recv().unwrap().source, QuerySource::Upstream);
    }
}
#[tokio::test]
async fn fresh_fallback_wins_and_a_zero_ttl_refresh_invalidates_stale_data() {
    let first = Mock::start("192.0.2.1").await;
    let second = Mock::start("192.0.2.2").await;
    let (telemetry, mut events) = Telemetry::channel(16);
    let engine = Engine::with_config(
        PolicySnapshot::compile(policy(vec![first.address, second.address]), 1).unwrap(),
        settings(60),
        telemetry,
    );
    seed_expired(&engine);
    first.mode.store(1, Ordering::Relaxed);
    let fresh = answer(&engine).await;
    assert_eq!(
        fresh.answers[0].data,
        RData::A(A("192.0.2.2".parse().unwrap()))
    );
    assert_eq!(fresh.answers[0].ttl, 1);
    assert_eq!(events.try_recv().unwrap().source, QuerySource::Upstream);
    seed_expired(&engine);
    first.mode.store(3, Ordering::Relaxed);
    assert_eq!(answer(&engine).await.answers[0].ttl, 0);
    assert!(engine.resolver().cache.is_empty());
    first.mode.store(1, Ordering::Relaxed);
    second.mode.store(1, Ordering::Relaxed);
    assert_eq!(
        answer(&engine).await.metadata.response_code,
        ResponseCode::ServFail
    );
    assert_eq!(engine.telemetry().metrics.snapshot().stale_answers, 0);
}
#[tokio::test]
async fn coalesced_outage_waiters_receive_private_stale_answers() {
    let mock = Mock::start("192.0.2.1").await;
    mock.mode.store(2, Ordering::Relaxed);
    let (telemetry, mut events) = Telemetry::channel(16);
    let engine = Arc::new(Engine::with_config(
        PolicySnapshot::compile(policy(vec![mock.address]), 1).unwrap(),
        settings(60),
        telemetry,
    ));
    seed_expired(&engine);
    let mut tasks = vec![];
    for id in 0..10 {
        let engine = engine.clone();
        tasks.push(tokio::spawn(async move {
            let mut request = query();
            request.metadata.id = id;
            let response = Message::from_vec(
                &engine
                    .answer(
                        &request.to_vec().unwrap(),
                        "127.0.0.1".parse().unwrap(),
                        Transport::Udp,
                    )
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(response.metadata.id, id);
            assert_eq!(response.answers[0].ttl, 30);
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(mock.hits.load(Ordering::Relaxed), 1);
    assert_eq!(engine.telemetry().metrics.snapshot().stale_answers, 10);
    for _ in 0..10 {
        assert_eq!(events.try_recv().unwrap().source, QuerySource::Stale);
    }
}
#[tokio::test]
async fn stale_data_cannot_bypass_new_blocks_rewrites_or_upstream_identity() {
    let mock = Mock::start("192.0.2.1").await;
    mock.mode.store(1, Ordering::Relaxed);
    let mut config = policy(vec![mock.address]);
    let (telemetry, mut events) = Telemetry::channel(16);
    let (engine, control) = Engine::controlled(
        PolicySnapshot::compile(config.clone(), 1).unwrap(),
        settings(60),
        telemetry,
    );
    seed_expired(&engine);
    config.policies[0].lists.push(ListInput {
        name: "block".into(),
        action: Action::Block,
        rules: "stale.test".into(),
    });
    control
        .prepare(
            PolicySnapshot::compile(config.clone(), 2).unwrap(),
            PublicationTarget::Active,
            control.version(),
        )
        .unwrap()
        .commit();
    assert_eq!(
        answer(&engine).await.metadata.response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(events.try_recv().unwrap().source, QuerySource::Blocked);
    assert_eq!(mock.hits.load(Ordering::Relaxed), 0);
    config.policies[0].rewrites.push(Rewrite {
        domain: "stale.test".into(),
        addresses: vec!["192.0.2.99".parse().unwrap()],
        ttl: 45,
    });
    control
        .prepare(
            PolicySnapshot::compile(config.clone(), 3).unwrap(),
            PublicationTarget::Active,
            control.version(),
        )
        .unwrap()
        .commit();
    assert_eq!(
        answer(&engine).await.answers[0].data,
        RData::A(A("192.0.2.99".parse().unwrap()))
    );
    assert_eq!(events.try_recv().unwrap().source, QuerySource::Rewrite);
    assert_eq!(mock.hits.load(Ordering::Relaxed), 0);
    config.policies[0].rewrites.clear();
    config.policies[0].lists.clear();
    let other = Mock::start("192.0.2.2").await;
    other.mode.store(1, Ordering::Relaxed);
    config.upstreams[0].addresses.push(other.address);
    control
        .prepare(
            PolicySnapshot::compile(config.clone(), 4).unwrap(),
            PublicationTarget::Active,
            control.version(),
        )
        .unwrap()
        .commit();
    assert_eq!(
        answer(&engine).await.metadata.response_code,
        ResponseCode::ServFail
    );
    assert_eq!(events.try_recv().unwrap().source, QuerySource::Failure);
    // Restoring exactly the original content identity can use its still-retained entry.
    config.upstreams[0].addresses.pop();
    control
        .prepare(
            PolicySnapshot::compile(config, 5).unwrap(),
            PublicationTarget::Active,
            control.version(),
        )
        .unwrap()
        .commit();
    assert_eq!(answer(&engine).await.answers[0].ttl, 30);
    assert_eq!(events.try_recv().unwrap().source, QuerySource::Stale);
}
#[tokio::test]
async fn stale_ttl_is_capped_by_exception_and_pending_answer_cannot_cross_expiry() {
    let mock = Mock::start("192.0.2.1").await;
    mock.mode.store(1, Ordering::Relaxed);
    let mut config = policy(vec![mock.address]);
    config.policies[0].lists.push(ListInput {
        name: "block".into(),
        action: Action::Block,
        rules: "stale.test".into(),
    });
    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 2;
    config.policies[0]
        .temporary_exceptions
        .push(TemporaryException {
            name: "repair".into(),
            domain: "stale.test".into(),
            expires_at: expiry,
        });
    let (telemetry, mut events) = Telemetry::channel(16);
    let engine = Engine::with_config(
        PolicySnapshot::compile(config, 1).unwrap(),
        settings(60),
        telemetry,
    );
    seed_expired(&engine);
    assert!(answer(&engine).await.answers[0].ttl <= 2);
    assert_eq!(events.try_recv().unwrap().source, QuerySource::Stale);
    let Prepared::Forward(pending) = engine.prepare(
        &query().to_vec().unwrap(),
        "127.0.0.1".parse().unwrap(),
        Transport::Udp,
    ) else {
        panic!("expected expired cache miss");
    };
    let remaining = (UNIX_EPOCH + Duration::from_secs(expiry))
        .duration_since(SystemTime::now())
        .unwrap_or_default();
    tokio::time::sleep(remaining + Duration::from_millis(20)).await;
    let response = Message::from_vec(&engine.forward(pending).await.unwrap()).unwrap();
    assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    assert!(response.answers.is_empty());
    assert_eq!(events.try_recv().unwrap().source, QuerySource::Blocked);
    assert_eq!(engine.telemetry().metrics.snapshot().stale_answers, 1);
    assert_eq!(
        answer(&engine).await.metadata.response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(mock.hits.load(Ordering::Relaxed), 2);
}
#[tokio::test]
async fn overload_shedding_and_shutdown_never_trigger_stale_fallback() {
    let mock = Mock::start("192.0.2.1").await;
    let (telemetry, _events) = Telemetry::channel(16);
    let engine = Engine::with_config(
        PolicySnapshot::compile(policy(vec![mock.address]), 1).unwrap(),
        settings(60),
        telemetry,
    );
    seed_expired(&engine);
    let Prepared::Forward(pending) = engine.prepare(
        &query().to_vec().unwrap(),
        "127.0.0.1".parse().unwrap(),
        Transport::Udp,
    ) else {
        panic!("expected miss");
    };
    let rejected = Message::from_vec(&engine.reject(pending).unwrap()).unwrap();
    assert_eq!(rejected.metadata.response_code, ResponseCode::ServFail);
    engine.resolver().shutdown();
    assert_eq!(
        answer(&engine).await.metadata.response_code,
        ResponseCode::ServFail
    );
    assert_eq!(mock.hits.load(Ordering::Relaxed), 0);
    assert_eq!(engine.telemetry().metrics.snapshot().stale_answers, 0);
}

#[tokio::test]
async fn cancellation_of_an_upstream_flight_is_not_an_outage() {
    let mock = Mock::start("192.0.2.1").await;
    mock.mode.store(2, Ordering::Relaxed);
    let (telemetry, _events) = Telemetry::channel(16);
    let engine = Arc::new(Engine::with_config(
        PolicySnapshot::compile(policy(vec![mock.address]), 1).unwrap(),
        settings(60),
        telemetry,
    ));
    seed_expired(&engine);
    let caller = {
        let engine = engine.clone();
        tokio::spawn(async move { answer(&engine).await })
    };
    tokio::time::timeout(Duration::from_secs(1), async {
        while mock.hits.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    engine.resolver().shutdown();
    assert_eq!(
        caller.await.unwrap().metadata.response_code,
        ResponseCode::ServFail
    );
    assert_eq!(engine.telemetry().metrics.snapshot().stale_answers, 0);
    tokio::time::timeout(Duration::from_secs(1), async {
        while engine.resolver().inflight() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn resolver_admission_overload_does_not_use_stale() {
    let mock = Mock::start("192.0.2.1").await;
    let (telemetry, _events) = Telemetry::channel(16);
    let mut limits = settings(60);
    limits.max_inflight = 0;
    let engine = Engine::with_config(
        PolicySnapshot::compile(policy(vec![mock.address]), 1).unwrap(),
        limits,
        telemetry,
    );
    seed_expired(&engine);
    assert_eq!(
        answer(&engine).await.metadata.response_code,
        ResponseCode::ServFail
    );
    assert_eq!(mock.hits.load(Ordering::Relaxed), 0);
    assert_eq!(engine.resolver().metrics.snapshot().overloads, 1);
    assert_eq!(engine.telemetry().metrics.snapshot().stale_answers, 0);
}

#[tokio::test]
async fn stale_age_is_checked_after_the_outage_wait() {
    let mock = Mock::start("192.0.2.1").await;
    mock.mode.store(2, Ordering::Relaxed);
    let mut config = policy(vec![mock.address]);
    config.upstreams[0].timeout_ms = 250;
    let (telemetry, _events) = Telemetry::channel(16);
    let mut limits = settings(60);
    limits.serve_stale = ServeStale::new(Duration::from_millis(100)).unwrap();
    let engine = Engine::with_config(
        PolicySnapshot::compile(config, 1).unwrap(),
        limits,
        telemetry,
    );
    let request = query();
    let key = CacheKey::new(&request, engine.active().upstreams()[0].id()).unwrap();
    let mut response = request.into_response();
    response.add_answer(Record::from_rdata(
        key.query.name().clone(),
        1,
        RData::A(A("192.0.2.1".parse().unwrap())),
    ));
    engine.resolver().cache.insert(
        key.clone(),
        response,
        Instant::now() - Duration::from_millis(1001),
    );
    assert!(
        engine
            .resolver()
            .cache
            .stale(&key, Instant::now(), limits.serve_stale)
            .is_some()
    );
    assert_eq!(
        answer(&engine).await.metadata.response_code,
        ResponseCode::ServFail
    );
    assert_eq!(engine.telemetry().metrics.snapshot().stale_answers, 0);
}
