//! Local-only UDP latency during assertion-gated compilation and publication.
//! compile_load <rules> <workers: 0|2|4> [reloads: 1..32]; bounded four clients and two DNS workers.
#![allow(clippy::unwrap_used)]
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{Name, RData, Record, RecordType, rdata::A},
};
use rustwalld_dns_core::{
    Engine, EngineConfig, PublicationTarget, Server, ServerConfig, reply, telemetry::Telemetry,
};
use rustwalld_dns_filter::{Action, ListInput, ParallelCompiler};
use rustwalld_dns_policy::{Assertion, PolicyConfigSet, PolicySnapshot};
use std::{
    error::Error,
    fmt::Write,
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, time::timeout};
use tokio_util::sync::CancellationToken;
#[path = "support/latency.rs"]
mod latency;
use latency::Histogram;
// Nested executors must also shut down safely on benchmark error paths.
struct DnsExecutor {
    handle: tokio::runtime::Handle,
    runtime: Option<tokio::runtime::Runtime>,
}
impl std::ops::Deref for DnsExecutor {
    type Target = tokio::runtime::Handle;
    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}
impl Drop for DnsExecutor {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}
fn request(domain: &str) -> Vec<u8> {
    let mut message = Message::query();
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(
        Name::from_ascii(domain).unwrap(),
        RecordType::A,
    ));
    message.to_vec().unwrap()
}
async fn exchange(socket: &UdpSocket, bytes: &[u8], blocked: bool) -> u64 {
    let start = Instant::now();
    socket.send(bytes).await.unwrap();
    let mut buffer = [0; 1232];
    let size = timeout(Duration::from_secs(2), socket.recv(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    let elapsed = start.elapsed().as_nanos() as u64;
    let response = Message::from_vec(&buffer[..size]).unwrap();
    let expected = Message::from_vec(bytes).unwrap();
    assert_eq!(response.queries, expected.queries);
    assert_eq!(response.metadata.id, expected.metadata.id);
    assert_eq!(
        response.metadata.response_code,
        if blocked {
            ResponseCode::NXDomain
        } else {
            ResponseCode::NoError
        }
    );
    assert_eq!(response.answers.len(), usize::from(!blocked));
    if !blocked {
        assert_eq!(
            response.answers[0].data,
            RData::A(A("192.0.2.1".parse().unwrap()))
        );
        assert!(response.answers[0].ttl > 0);
    }
    elapsed
}
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let size: usize = args.next().ok_or("missing size")?.parse()?;
    let workers: usize = args.next().ok_or("missing workers")?.parse()?;
    let reloads: u64 = args.next().unwrap_or_else(|| "1".into()).parse()?;
    if args.next().is_some()
        || !(1..=32).contains(&reloads)
        || !(1000..=10_000_000).contains(&size)
        || ![0, 2, 4].contains(&workers)
    {
        return Err("expected <rules: 1000..10000000> <workers: 0|2|4> [reloads: 1..32]".into());
    }
    let compiler = (workers != 0).then(|| ParallelCompiler::new(workers).unwrap());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let dns = DnsExecutor {
        handle: runtime.handle().clone(),
        runtime: Some(runtime),
    };
    let upstream = dns
        .spawn(async { UdpSocket::bind("127.0.0.1:0").await })
        .await??;
    let upstream_addr = upstream.local_addr()?;
    let hits = Arc::new(AtomicU64::new(0));
    let counts = hits.clone();
    let mock = dns.spawn(async move {
        let mut bytes = [0; 1232];
        loop {
            let (len, peer) = upstream.recv_from(&mut bytes).await.unwrap();
            let query = Message::from_vec(&bytes[..len]).unwrap();
            counts.fetch_add(1, Ordering::Relaxed);
            let mut response = reply(&query, ResponseCode::NoError);
            response.add_answer(Record::from_rdata(
                query.queries[0].name().clone(),
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
    config.upstreams[0].addresses = vec![upstream_addr];
    config.policies[0].lists.push(ListInput {
        name: "fixture".into(),
        action: Action::Block,
        rules: "blocked.test".into(),
    });
    config.assertions = vec![Assertion {
        client: "127.0.0.1".parse()?,
        domain: "x.blocked.test".into(),
        expected: Action::Block,
    }];
    let (telemetry, _events) = Telemetry::channel(1);
    let (engine, control) = Engine::controlled(
        PolicySnapshot::compile(config.clone(), 1)?,
        EngineConfig {
            cache_entries: 4096,
            decision_entries: 4096,
            max_inflight: 256,
            ..Default::default()
        },
        telemetry,
    );
    let engine = Arc::new(engine);
    let dns_engine = engine.clone();
    let server = dns
        .spawn(async move {
            Server::bind(
                ServerConfig {
                    listen: "127.0.0.1:0".parse().unwrap(),
                    ..Default::default()
                },
                dns_engine,
            )
            .await
        })
        .await??;
    let address = server.local_addr()?;
    let stop = CancellationToken::new();
    let service = dns.spawn(server.run(stop.clone()));
    // Generate the candidate before the baseline or compilation measurement.
    for i in 1..size {
        writeln!(config.policies[0].lists[0].rules, "\n=rule{i}.bench")?;
    }
    let phase = Arc::new(AtomicU8::new(0));
    let mut clients = tokio::task::JoinSet::new();
    for _ in 0..4 {
        let phase = phase.clone();
        clients.spawn(async move {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            socket.connect(address).await.unwrap();
            let packets = [request("x.blocked.test."), request("cached.test.")];
            let mut samples: [Histogram; 3] = std::array::from_fn(|_| Histogram::new());
            let mut index = 0;
            loop {
                let before = phase.load(Ordering::Acquire);
                if before == 4 {
                    break;
                }
                let latency = exchange(&socket, &packets[index], index == 0).await;
                index = 1 - index;
                let after = phase.load(Ordering::Acquire);
                // Include requests crossing the start/end of compilation.
                let measured = if before == 2 || after == 2 {
                    2
                } else if before == after {
                    before
                } else {
                    0
                };
                if (1..=3).contains(&measured) {
                    let out = &mut samples[measured as usize - 1];
                    out.record(latency);
                }
            }
            samples
        });
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    phase.store(1, Ordering::Release);
    tokio::time::sleep(Duration::from_millis(250)).await;
    let stage = phase.clone();
    let (compile_ns, publish_ns) = tokio::task::spawn_blocking(move || {
        stage.store(2, Ordering::Release);
        let (mut compile_ns, mut publish_ns) = (0, 0);
        for generation in 2..=reloads + 1 {
            // Clone outside compilation timing. The histogram also observes
            // cloning, publication and retired-generation destruction.
            let candidate = config.clone();
            let begin = Instant::now();
            let snapshot = match &compiler {
                None => PolicySnapshot::compile(candidate, generation).unwrap(),
                Some(compiler) => {
                    PolicySnapshot::compile_parallel(candidate, generation, compiler).unwrap()
                }
            };
            compile_ns += begin.elapsed().as_nanos();
            let begin = Instant::now();
            let retired = control
                .prepare(snapshot, PublicationTarget::Active, control.version())
                .unwrap()
                .commit();
            publish_ns += begin.elapsed().as_nanos();
            drop(retired);
        }
        stage.store(3, Ordering::Release);
        (compile_ns, publish_ns)
    })
    .await?;
    tokio::time::sleep(Duration::from_millis(250)).await;
    phase.store(4, Ordering::Release);
    let mut samples: [Histogram; 3] = std::array::from_fn(|_| Histogram::new());
    while let Some(result) = clients.join_next().await {
        for (out, input) in samples.iter_mut().zip(result?) {
            out.merge(input);
        }
    }
    println!(
        "rules={size} workers={workers} reloads={reloads} compile_ns={compile_ns} publish_ns={publish_ns} upstream={} generation={}",
        hits.load(Ordering::Relaxed),
        engine.snapshot().generation()
    );
    assert_eq!(engine.snapshot().generation(), reloads + 1);
    assert_eq!(
        hits.load(Ordering::Relaxed),
        reloads + 1,
        "one warm miss per generation, flights deduplicated"
    );
    assert_eq!(engine.resolver().inflight(), 0);
    for (name, values) in ["baseline", "compile", "after"]
        .into_iter()
        .zip(&mut samples)
    {
        values.report(name);
    }
    stop.cancel();
    service.await??;
    mock.abort();
    let _ = mock.await;
    Ok(())
}
