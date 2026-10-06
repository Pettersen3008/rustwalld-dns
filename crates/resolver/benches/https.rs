#![allow(clippy::unwrap_used)]
#[path = "../tests/support/https.rs"]
mod fixture;
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{Name, RecordType},
};
use rustwalld_dns_resolver::Forwarder;
use std::time::Duration;
fn https(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let mock = runtime.block_on(fixture::Mock::start(0));
    let new = || {
        Forwarder::with_transport(vec![mock.address], Duration::from_secs(2), &mock.transport)
            .unwrap()
    };
    let mut query = Message::new(0, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(
        Name::from_ascii("benchmark.test.").unwrap(),
        RecordType::A,
    ));
    let warm = new();
    runtime.block_on(warm.resolve(&query)).unwrap();
    let mut group = c.benchmark_group("doh_loopback");
    group.throughput(Throughput::Elements(1));
    group.bench_function("warm", |b| {
        b.iter(|| runtime.block_on(warm.resolve(&query)).unwrap())
    });
    group.bench_function("cold", |b| {
        b.iter_batched(
            new,
            |f| runtime.block_on(f.resolve(&query)).unwrap(),
            BatchSize::SmallInput,
        )
    });
    group.finish();
}
criterion_group!(benches, https);
criterion_main!(benches);
