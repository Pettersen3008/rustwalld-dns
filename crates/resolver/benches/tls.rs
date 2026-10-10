#![allow(clippy::unwrap_used)]
#[path = "../tests/support/tls.rs"]
mod fixture;
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{Name, RecordType},
};
use rustwalld_dns_resolver::Forwarder;
use std::time::Duration;
fn tls(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let mock = runtime.block_on(fixture::Mock::start(0));
    let new = || {
        Forwarder::with_transport(vec![mock.address], Duration::from_secs(1), &mock.transport)
            .unwrap()
    };
    let mut request = Message::new(1, MessageType::Query, OpCode::Query);
    request.add_query(Query::query(
        Name::from_ascii("benchmark.test.").unwrap(),
        RecordType::A,
    ));
    let warm = new();
    runtime.block_on(warm.resolve(&request)).unwrap();
    let mut group = c.benchmark_group("dot_loopback");
    group.throughput(Throughput::Elements(1));
    group.bench_function("warm", |b| {
        b.iter(|| runtime.block_on(warm.resolve(&request)).unwrap())
    });
    // Root/config compilation is excluded; each fresh forwarder has a new
    // rustls session cache, so cold includes TCP + full TLS handshake + DNS.
    group.bench_function("cold", |b| {
        b.iter_batched(
            new,
            |f| runtime.block_on(f.resolve(&request)).unwrap(),
            BatchSize::SmallInput,
        )
    });
    group.finish();
    let delayed = runtime.block_on(fixture::Mock::start(10));
    let forwarder = std::sync::Arc::new(
        Forwarder::with_transport(
            vec![delayed.address],
            Duration::from_secs(5),
            &delayed.transport,
        )
        .unwrap(),
    );
    runtime.block_on(forwarder.resolve(&request)).unwrap();
    let mut group = c.benchmark_group("dot_concurrent");
    group.sample_size(10);
    for clients in [8_u64, 32] {
        group.throughput(Throughput::Elements(clients));
        group.bench_function(format!("{clients}_queries_10ms_server"), |b| {
            b.iter(|| {
                runtime.block_on(async {
                    let tasks: Vec<_> = (0..clients)
                        .map(|_| {
                            let forwarder = forwarder.clone();
                            let query = request.clone();
                            tokio::spawn(async move { forwarder.resolve(&query).await })
                        })
                        .collect();
                    for task in tasks {
                        task.await.unwrap().unwrap();
                    }
                })
            })
        });
    }
    group.finish();
}
criterion_group!(benches, tls);
criterion_main!(benches);
