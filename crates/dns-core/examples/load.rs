//! Reproducible loopback benchmark. No public DNS or application I/O.
#![allow(clippy::unwrap_used)]
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{Name, RData, Record, RecordType, rdata::A},
};
use rustwalld_dns_core::{Engine, Server, ServerConfig, reply, telemetry::Telemetry};
use rustwalld_dns_filter::{Action, ListInput};
use rustwalld_dns_policy::{PolicyConfigSet, PolicySnapshot};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, time::timeout};
use tokio_util::sync::CancellationToken;
fn request(domain: &str) -> Vec<u8> {
    let mut request = Message::query();
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(
        Name::from_ascii(domain).unwrap(),
        RecordType::A,
    ));
    request.to_vec().unwrap()
}
async fn client(addr: SocketAddr) -> UdpSocket {
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(addr).await.unwrap();
    client
}
async fn exchange(client: &UdpSocket, bytes: &[u8]) -> u64 {
    let start = Instant::now();
    client.send(bytes).await.unwrap();
    let mut buffer = [0; 1232];
    let len = timeout(Duration::from_secs(2), client.recv(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    let message = Message::from_vec(&buffer[..len]).unwrap();
    assert!(matches!(
        message.metadata.response_code,
        ResponseCode::NoError | ResponseCode::NXDomain
    ));
    start.elapsed().as_micros() as u64
}
fn report(name: &str, mut samples: Vec<u64>, start: Instant, upstream: u64) {
    samples.sort_unstable();
    let n = samples.len();
    let quantile = |q: f64| samples[((n - 1) as f64 * q).ceil() as usize];
    println!(
        "{name}: n={n} p50={} p95={} p99={} p99.9={} us throughput={:.0}/s upstream={upstream}",
        quantile(0.5),
        quantile(0.95),
        quantile(0.99),
        quantile(0.999),
        n as f64 / start.elapsed().as_secs_f64()
    );
}
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = upstream.local_addr().unwrap();
    let hits = Arc::new(AtomicU64::new(0));
    let counts = hits.clone();
    let mock = tokio::spawn(async move {
        let mut bytes = vec![0; 65535];
        loop {
            let (len, peer) = upstream.recv_from(&mut bytes).await.unwrap();
            let request = Message::from_vec(&bytes[..len]).unwrap();
            counts.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(25)).await;
            let mut response = reply(&request, ResponseCode::NoError);
            response.add_answer(Record::from_rdata(
                request.queries[0].name().clone(),
                3600,
                RData::A(A("192.0.2.1".parse().unwrap())),
            ));
            upstream
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let mut config = PolicyConfigSet::default();
    config.upstreams[0].addresses = vec![address];
    config.policies[0].lists.push(ListInput {
        name: "bench".into(),
        action: Action::Block,
        rules: "blocked.test".into(),
    });
    let (telemetry, _events) = Telemetry::channel(4096);
    let (engine, control) = Engine::controlled(
        PolicySnapshot::compile(config.clone(), 1).unwrap(),
        rustwalld_dns_core::EngineConfig {
            cache_entries: 4096,
            decision_entries: 4096,
            max_inflight: 256,
            ..Default::default()
        },
        telemetry,
    );
    let engine = Arc::new(engine);
    let server = Server::bind(
        ServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            max_udp_queries: 1024,
            ..Default::default()
        },
        engine.clone(),
    )
    .await
    .unwrap();
    let addr = server.local_addr().unwrap();
    let stop = CancellationToken::new();
    let service = tokio::spawn(server.run(stop.clone()));
    let socket = client(addr).await;
    for (name, domain) in [
        ("decision_blocked", "x.blocked.test."),
        ("dns_cache", "cached.test."),
    ] {
        let bytes = request(domain);
        exchange(&socket, &bytes).await;
        let before = hits.load(Ordering::Relaxed);
        let start = Instant::now();
        let mut samples = Vec::with_capacity(5000);
        for _ in 0..5000 {
            samples.push(exchange(&socket, &bytes).await);
        }
        let upstream = hits.load(Ordering::Relaxed) - before;
        assert_eq!(upstream, 0);
        report(name, samples, start, upstream);
    }
    let before = hits.load(Ordering::Relaxed);
    let start = Instant::now();
    let mut samples = Vec::new();
    for i in 0..50 {
        samples.push(exchange(&socket, &request(&format!("cold{i}.test."))).await);
    }
    report(
        "uncached_upstream_25ms_fixture",
        samples,
        start,
        hits.load(Ordering::Relaxed) - before,
    );
    let before = hits.load(Ordering::Relaxed);
    let start = Instant::now();
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..128 {
        tasks.spawn(async move {
            let socket = client(addr).await;
            exchange(&socket, &request("burst.test.")).await
        });
    }
    let mut samples = Vec::new();
    while let Some(sample) = tasks.join_next().await {
        samples.push(sample.unwrap());
    }
    let exchanges = hits.load(Ordering::Relaxed) - before;
    assert_eq!(exchanges, 1);
    report("128_duplicate_misses", samples, start, exchanges);
    let before = hits.load(Ordering::Relaxed);
    let start = Instant::now();
    let reload_control = control.clone();
    let reload = tokio::task::spawn_blocking(move || {
        let mut rules = String::from("blocked.test\n");
        for i in 0..100000 {
            use std::fmt::Write;
            writeln!(rules, "=rule{i}.bench").unwrap();
        }
        config.policies[0].lists[0].rules = rules;
        let started = Instant::now();
        let snapshot = PolicySnapshot::compile(config, 2).unwrap();
        let promotion = Instant::now();
        reload_control
            .prepare(
                snapshot,
                rustwalld_dns_core::PublicationTarget::Active,
                reload_control.version(),
            )
            .unwrap()
            .commit();
        println!(
            "reload compile_ms={} atomic_store_us={}",
            started.elapsed().as_millis(),
            promotion.elapsed().as_micros()
        );
    });
    let bytes = request("x.blocked.test.");
    let mut samples = Vec::new();
    for _ in 0..5000 {
        samples.push(exchange(&socket, &bytes).await);
    }
    reload.await.unwrap();
    report(
        "reload_during_blocked_traffic",
        samples,
        start,
        hits.load(Ordering::Relaxed) - before,
    );
    assert!(engine.resolver().cache.len() <= 4096);
    assert_eq!(engine.resolver().inflight(), 0);
    println!(
        "telemetry_dropped={}",
        engine.telemetry().metrics.snapshot().dropped_events
    );
    stop.cancel();
    service.await.unwrap().unwrap();
    mock.abort();
}
