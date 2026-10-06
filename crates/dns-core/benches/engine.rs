#![allow(clippy::unwrap_used)]
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use dns_core::telemetry::Telemetry;
use hickory_proto::op::Message;
use std::time::Instant;
#[path = "support/fixtures.rs"]
mod fixtures;
use fixtures::setup;
fn bench(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (engine, blocked, cached) = setup(None);
    let client = "127.0.0.1".parse().unwrap();
    for (name, address) in [
        ("binding_select_ipv4", "127.0.0.1"),
        ("binding_select_ipv6", "2001:db8::1"),
        ("binding_select_mapped_ipv4", "::ffff:127.0.0.1"),
    ] {
        let address = address.parse().unwrap();
        c.bench_function(name, |b| {
            b.iter(|| {
                let snapshot = engine.active.load();
                std::hint::black_box(snapshot.select(std::hint::black_box(address)).policy.id)
            })
        });
    }
    for (name, bytes) in [
        ("decision_cache_blocked_wire", &blocked),
        ("dns_cache_hit_wire", &cached),
    ] {
        runtime.block_on(engine.answer(bytes, client, false));
        let allocations = allocation_counter::measure(|| {
            std::hint::black_box(runtime.block_on(engine.answer(bytes, client, false)));
        });
        eprintln!(
            "{name}: {} allocations / {} allocated bytes per warm query",
            allocations.count_total, allocations.bytes_total
        );
        c.bench_function(name, |b| {
            b.iter(|| {
                std::hint::black_box(runtime.block_on(engine.answer(
                    std::hint::black_box(bytes),
                    client,
                    false,
                )))
            })
        });
    }
    assert_eq!(
        engine
            .resolver
            .metrics
            .upstream_lookups
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    for (name, long_name) in [
        ("dns_cache_long_name_wire", true),
        ("dns_cache_dnssec_wire", false),
    ] {
        let (engine, bytes) = fixtures::dnssec_cache(long_name);
        let request = Message::from_vec(&bytes).unwrap();
        let warm = runtime
            .block_on(engine.answer(&bytes, client, false))
            .unwrap();
        let response = Message::from_vec(&warm).unwrap();
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.queries, request.queries);
        assert!(!response.metadata.truncation);
        let allocations = allocation_counter::measure(|| {
            std::hint::black_box(runtime.block_on(engine.answer(&bytes, client, false)));
        });
        eprintln!(
            "{name}: {} allocations / {} allocated bytes per warm query",
            allocations.count_total, allocations.bytes_total
        );
        c.bench_function(name, |b| {
            b.iter(|| std::hint::black_box(runtime.block_on(engine.answer(&bytes, client, false))))
        });
        assert_eq!(
            engine
                .resolver
                .metrics
                .upstream_lookups
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }
    for (name, domain, cached_path, expired) in [
        ("temporary_allow_dns_cache_wire", "cached.test", true, false),
        (
            "decision_cache_blocked_with_exceptions_wire",
            "other.test",
            false,
            false,
        ),
        (
            "expired_temporary_decision_cache_wire",
            "blocked.test",
            false,
            true,
        ),
    ] {
        let (engine, blocked, cached) = setup(Some(domain));
        if expired {
            assert!(
                engine.active.load().policies[0]
                    .temporary_allow(
                        domain,
                        Instant::now() + std::time::Duration::from_secs(3601)
                    )
                    .is_none()
            );
        }
        let bytes = if cached_path { cached } else { blocked };
        runtime.block_on(engine.answer(&bytes, client, false));
        let allocations = allocation_counter::measure(|| {
            std::hint::black_box(runtime.block_on(engine.answer(&bytes, client, false)));
        });
        eprintln!(
            "{name}: {} allocations / {} allocated bytes per warm query",
            allocations.count_total, allocations.bytes_total
        );
        c.bench_function(name, |b| {
            b.iter(|| {
                std::hint::black_box(runtime.block_on(engine.answer(
                    std::hint::black_box(&bytes),
                    client,
                    false,
                )))
            })
        });
        assert_eq!(
            engine
                .resolver
                .metrics
                .upstream_lookups
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }
    let (engine, blocked) = fixtures::rewrite();
    let response = runtime
        .block_on(engine.answer(&blocked, client, false))
        .unwrap();
    assert_eq!(Message::from_vec(&response).unwrap().answers.len(), 1);
    // Keep response parsing outside the allocation probe.
    let allocations = allocation_counter::measure(|| {
        std::hint::black_box(runtime.block_on(engine.answer(&blocked, client, false)));
    });
    eprintln!(
        "local_rewrite_wire: {} allocations / {} allocated bytes per query",
        allocations.count_total, allocations.bytes_total
    );
    c.bench_function("local_rewrite_wire", |b| {
        b.iter(|| std::hint::black_box(runtime.block_on(engine.answer(&blocked, client, false))))
    });
    assert_eq!(
        engine
            .resolver
            .metrics
            .upstream_lookups
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );

    for (name, cached_path, full) in [
        ("telemetry_empty_blocked_wire", false, false),
        ("telemetry_full_blocked_wire", false, true),
        ("telemetry_empty_dns_cache_wire", true, false),
        ("telemetry_full_dns_cache_wire", true, true),
    ] {
        let (mut engine, blocked, cached) = setup(None);
        let (telemetry, mut receiver) = Telemetry::channel(1);
        engine.telemetry = telemetry;
        let bytes = if cached_path { cached } else { blocked };
        runtime.block_on(engine.answer(&bytes, client, false));
        if !full {
            receiver.try_recv().unwrap();
        }
        let allocations = allocation_counter::measure(|| {
            std::hint::black_box(runtime.block_on(engine.answer(&bytes, client, false)));
        });
        eprintln!(
            "{name}: {} allocations / {} allocated bytes per warm query",
            allocations.count_total, allocations.bytes_total
        );
        c.bench_function(name, |b| {
            if full {
                b.iter(|| {
                    std::hint::black_box(runtime.block_on(engine.answer(&bytes, client, false)))
                });
            } else {
                // PerIteration guarantees an empty live queue for every answer.
                // Consume/drop the preceding event outside the timed call.
                b.iter_batched(
                    || {
                        receiver.try_recv().unwrap();
                    },
                    |()| {
                        std::hint::black_box(runtime.block_on(engine.answer(&bytes, client, false)))
                    },
                    BatchSize::PerIteration,
                );
            }
        });
        assert_eq!(
            engine
                .resolver
                .metrics
                .upstream_lookups
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }
}
criterion_group!(benches, bench);
criterion_main!(benches);
