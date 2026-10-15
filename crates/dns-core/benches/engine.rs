#![allow(clippy::unwrap_used)]
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use hickory_proto::op::Message;
use rustwalld_dns_core::{Transport, telemetry::Telemetry};
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
                std::hint::black_box(snapshot.select(std::hint::black_box(address)).policy.id())
            })
        });
    }
    for (name, bytes) in [
        ("decision_cache_blocked_wire", &blocked),
        ("dns_cache_hit_wire", &cached),
    ] {
        runtime.block_on(engine.answer(bytes, client, Transport::Udp));
        let allocations = allocation_counter::measure(|| {
            std::hint::black_box(runtime.block_on(engine.answer(bytes, client, Transport::Udp)));
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
                    Transport::Udp,
                )))
            })
        });
    }
    assert_eq!(engine.resolver().metrics.snapshot().upstream_lookups, 0);
    for (name, long_name) in [
        ("dns_cache_long_name_wire", true),
        ("dns_cache_dnssec_wire", false),
    ] {
        let (engine, bytes) = fixtures::dnssec_cache(long_name);
        let request = Message::from_vec(&bytes).unwrap();
        let warm = runtime
            .block_on(engine.answer(&bytes, client, Transport::Udp))
            .unwrap();
        let response = Message::from_vec(&warm).unwrap();
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.queries, request.queries);
        assert!(!response.metadata.truncation);
        let allocations = allocation_counter::measure(|| {
            std::hint::black_box(runtime.block_on(engine.answer(&bytes, client, Transport::Udp)));
        });
        eprintln!(
            "{name}: {} allocations / {} allocated bytes per warm query",
            allocations.count_total, allocations.bytes_total
        );
        c.bench_function(name, |b| {
            b.iter(|| {
                std::hint::black_box(runtime.block_on(engine.answer(
                    &bytes,
                    client,
                    Transport::Udp,
                )))
            })
        });
        assert_eq!(engine.resolver().metrics.snapshot().upstream_lookups, 0);
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
                engine.active.load().policies()[0]
                    .temporary_allow(
                        domain,
                        Instant::now() + std::time::Duration::from_secs(3601)
                    )
                    .is_none()
            );
        }
        let bytes = if cached_path { cached } else { blocked };
        runtime.block_on(engine.answer(&bytes, client, Transport::Udp));
        let allocations = allocation_counter::measure(|| {
            std::hint::black_box(runtime.block_on(engine.answer(&bytes, client, Transport::Udp)));
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
                    Transport::Udp,
                )))
            })
        });
        assert_eq!(engine.resolver().metrics.snapshot().upstream_lookups, 0);
    }
    let (engine, blocked) = fixtures::rewrite();
    let response = runtime
        .block_on(engine.answer(&blocked, client, Transport::Udp))
        .unwrap();
    assert_eq!(Message::from_vec(&response).unwrap().answers.len(), 1);
    // Keep response parsing outside the allocation probe.
    let allocations = allocation_counter::measure(|| {
        std::hint::black_box(runtime.block_on(engine.answer(&blocked, client, Transport::Udp)));
    });
    eprintln!(
        "local_rewrite_wire: {} allocations / {} allocated bytes per query",
        allocations.count_total, allocations.bytes_total
    );
    c.bench_function("local_rewrite_wire", |b| {
        b.iter(|| {
            std::hint::black_box(runtime.block_on(engine.answer(&blocked, client, Transport::Udp)))
        })
    });
    assert_eq!(engine.resolver().metrics.snapshot().upstream_lookups, 0);

    let (engine, blocked, cached, nodata) = passthrough();
    for (name, bytes, code, answer_count) in [
        (
            "passthrough_blocked_wire",
            &blocked,
            hickory_proto::op::ResponseCode::NXDomain,
            0,
        ),
        (
            "passthrough_cached_wire",
            &cached,
            hickory_proto::op::ResponseCode::NoError,
            1,
        ),
        (
            "passthrough_other_family_nodata_wire",
            &nodata,
            hickory_proto::op::ResponseCode::NoError,
            0,
        ),
    ] {
        let response = runtime
            .block_on(engine.answer(bytes, client, Transport::Udp))
            .unwrap();
        let response = Message::from_vec(&response).unwrap();
        assert_eq!(response.response_code, code);
        assert_eq!(response.answers.len(), answer_count);
        let allocations = allocation_counter::measure(|| {
            std::hint::black_box(runtime.block_on(engine.answer(bytes, client, Transport::Udp)));
        });
        eprintln!(
            "{name}: {} allocations / {} allocated bytes per warm query",
            allocations.count_total, allocations.bytes_total
        );
        c.bench_function(name, |b| {
            b.iter(|| {
                std::hint::black_box(runtime.block_on(engine.answer(bytes, client, Transport::Udp)))
            })
        });
    }
    assert_eq!(engine.resolver().metrics.snapshot().upstream_lookups, 0);

    let (engine, cases) = wildcard();
    for (name, bytes, count) in cases {
        let wire = runtime
            .block_on(engine.answer(&bytes, client, Transport::Udp))
            .unwrap();
        let response = Message::from_vec(&wire).unwrap();
        assert_eq!(response.answers.len(), count);
        for answer in &response.answers {
            assert_eq!(answer.name, response.queries[0].name().clone());
            assert!(!answer.name.is_wildcard());
        }
        let allocations = allocation_counter::measure(|| {
            std::hint::black_box(runtime.block_on(engine.answer(&bytes, client, Transport::Udp)));
        });
        eprintln!(
            "{name}: {} allocations / {} allocated bytes per warm query",
            allocations.count_total, allocations.bytes_total
        );
        c.bench_function(name, |b| {
            b.iter(|| {
                std::hint::black_box(runtime.block_on(engine.answer(
                    &bytes,
                    client,
                    Transport::Udp,
                )))
            })
        });
    }
    assert_eq!(engine.resolver().metrics.snapshot().upstream_lookups, 0);

    for (name, cached_path, full) in [
        ("telemetry_empty_blocked_wire", false, false),
        ("telemetry_full_blocked_wire", false, true),
        ("telemetry_empty_dns_cache_wire", true, false),
        ("telemetry_full_dns_cache_wire", true, true),
    ] {
        let (mut engine, blocked, cached) = setup(None);
        let (telemetry, mut receiver) = Telemetry::channel(1);
        engine = engine.with_telemetry(telemetry);
        let bytes = if cached_path { cached } else { blocked };
        runtime.block_on(engine.answer(&bytes, client, Transport::Udp));
        if !full {
            receiver.try_recv().unwrap();
        }
        let allocations = allocation_counter::measure(|| {
            std::hint::black_box(runtime.block_on(engine.answer(&bytes, client, Transport::Udp)));
        });
        eprintln!(
            "{name}: {} allocations / {} allocated bytes per warm query",
            allocations.count_total, allocations.bytes_total
        );
        c.bench_function(name, |b| {
            if full {
                b.iter(|| {
                    std::hint::black_box(runtime.block_on(engine.answer(
                        &bytes,
                        client,
                        Transport::Udp,
                    )))
                });
            } else {
                // PerIteration guarantees an empty live queue for every answer.
                // Consume/drop the preceding event outside the timed call.
                b.iter_batched(
                    || {
                        receiver.try_recv().unwrap();
                    },
                    |()| {
                        std::hint::black_box(runtime.block_on(engine.answer(
                            &bytes,
                            client,
                            Transport::Udp,
                        )))
                    },
                    BatchSize::PerIteration,
                );
            }
        });
        assert_eq!(engine.resolver().metrics.snapshot().upstream_lookups, 0);
    }
}

fn passthrough() -> (fixtures::Engine, Vec<u8>, Vec<u8>, Vec<u8>) {
    let (engine, blocked, cached) = setup(None);
    let mut config = engine.active.load().config().clone();
    for domain in ["blocked.test", "cached.test"] {
        config.policies[0]
            .dns_records
            .push(rustwalld_dns_policy::LocalRecord {
                domain: domain.into(),
                ttl: 60,
                data: rustwalld_dns_policy::LocalData::Passthrough {
                    family: rustwalld_dns_policy::AddressFamily::A,
                },
            });
    }
    engine.active.store(std::sync::Arc::new(
        rustwalld_dns_policy::PolicySnapshot::compile(config, 2).unwrap(),
    ));
    let mut nodata = Message::from_vec(&cached).unwrap();
    nodata.queries[0].set_query_type(hickory_proto::rr::RecordType::AAAA);
    (engine, blocked, cached, nodata.to_vec().unwrap())
}

type WildcardCase = (&'static str, Vec<u8>, usize);
fn wildcard() -> (fixtures::Engine, Vec<WildcardCase>) {
    let (engine, _, _) = setup(None);
    let mut config = engine.active.load().config().clone();
    for index in 0..1000 {
        config.policies[0]
            .dns_records
            .push(rustwalld_dns_policy::LocalRecord {
                domain: format!("*.zone{index}.test"),
                ttl: 60,
                data: rustwalld_dns_policy::LocalData::A {
                    address: "192.0.2.10".parse().unwrap(),
                },
            });
    }
    config.policies[0]
        .dns_records
        .push(rustwalld_dns_policy::LocalRecord {
            domain: "*.deep.zone999.test".into(),
            ttl: 60,
            data: rustwalld_dns_policy::LocalData::A {
                address: "192.0.2.20".parse().unwrap(),
            },
        });
    engine.active.store(std::sync::Arc::new(
        rustwalld_dns_policy::PolicySnapshot::compile(config, 2).unwrap(),
    ));
    let cases = [
        (
            "wildcard_address_1000_wire",
            "x.deep.zone999.test",
            hickory_proto::rr::RecordType::A,
            1,
        ),
        (
            "wildcard_nodata_1000_wire",
            "x.deep.zone999.test",
            hickory_proto::rr::RecordType::AAAA,
            0,
        ),
        (
            "wildcard_unmatched_1000_wire",
            "blocked.test",
            hickory_proto::rr::RecordType::A,
            0,
        ),
    ]
    .into_iter()
    .map(|(label, owner, kind, count)| {
        let mut query = Message::query();
        query.metadata.recursion_desired = true;
        query.add_query(hickory_proto::op::Query::query(
            hickory_proto::rr::Name::from_ascii(owner).unwrap(),
            kind,
        ));
        (label, query.to_vec().unwrap(), count)
    })
    .collect();
    (engine, cases)
}

criterion_group!(benches, bench);
criterion_main!(benches);
