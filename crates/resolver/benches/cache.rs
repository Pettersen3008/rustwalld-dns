#![allow(clippy::unwrap_used)]
use criterion::{Criterion, criterion_group, criterion_main};
use hickory_proto::{
    op::{Message, Query},
    rr::{Name, RData, Record, RecordType, rdata::A},
};
use rustwalld_dns_resolver::{
    Forwarder,
    cache::BoundedCache,
    response_cache::{CacheKey, ResponseCache},
};
use std::time::{Duration, Instant};
fn bench(c: &mut Criterion) {
    let mut request = Message::query();
    request.add_query(Query::query(
        Name::from_ascii("bench.example.").unwrap(),
        RecordType::A,
    ));
    let upstream = Forwarder::new(vec!["127.0.0.1:9".parse().unwrap()], Duration::from_secs(1))
        .unwrap()
        .id();
    let key = CacheKey::new(&request, upstream).unwrap();
    let mut response = request.into_response();
    response.add_answer(Record::from_rdata(
        key.query.name().clone(),
        3600,
        RData::A(A("192.0.2.1".parse().unwrap())),
    ));
    let cache = ResponseCache::new(1000);
    let now = Instant::now();
    cache.insert(key.clone(), response, now);
    c.bench_function("response_cache_hit_message_clone", |b| {
        b.iter(|| std::hint::black_box(cache.get(std::hint::black_box(&key), now)))
    });
    let cache = BoundedCache::new(8192);
    for key in 0..1024_u64 {
        cache.insert(key, key);
    }
    let mut cursor = 0_u64;
    c.bench_function("bounded_cache_working_set_hit", |b| {
        b.iter(|| {
            cursor = (cursor + 1) % 1024;
            std::hint::black_box(cache.get(std::hint::black_box(&cursor)))
        })
    });
    assert_eq!(cache.len(), 1024);
    let cache = BoundedCache::new(1024);
    let mut cursor = 0_u64;
    for _ in 0..20000 {
        cache.insert(cursor, cursor);
        cursor += 1;
    }
    c.bench_function("bounded_cache_u64_churn", |b| {
        b.iter(|| {
            cursor = cursor.wrapping_add(1);
            cache.insert(std::hint::black_box(cursor), cursor);
        })
    });
    assert!(cache.len() <= 1024);
    // Decision-cache shape: owned domain keys, every insertion evicting.
    let names: Vec<String> = (0..65_536)
        .map(|index| format!("{index}.churn.example"))
        .collect();
    let cache = BoundedCache::new(4096);
    let mut next = 0;
    c.bench_function("bounded_cache_string_churn", |b| {
        b.iter(|| {
            next = (next + 1) % names.len();
            cache.insert(names[next].clone(), next);
        })
    });
    assert!(cache.len() <= 4096);
}
criterion_group!(benches, bench);
criterion_main!(benches);
