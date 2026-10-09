#![allow(clippy::unwrap_used)]
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rustwalld_dns_filter::{Action, FilterSnapshot, ListInput};
fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("filter");
    let sizes = std::env::var("DNS_BENCH_SIZES").unwrap_or_else(|_| "100000".into());
    for size in sizes.split(',').map(|s| s.parse::<usize>().unwrap()) {
        assert!(
            (100..=10_000_000).contains(&size),
            "fixture size must be 100..=10000000"
        );
        let mut rules = String::new();
        for i in 0..size {
            use std::fmt::Write;
            if i % 2 == 0 {
                writeln!(rules, "=exact{i}.bench").unwrap();
            } else {
                writeln!(rules, "suffix{i}.bench").unwrap();
            }
        }
        let started = std::time::Instant::now();
        let filters = FilterSnapshot::compile(
            &[ListInput {
                name: "fixture".into(),
                action: Action::Block,
                rules,
            }],
            size + 1,
            usize::MAX,
        )
        .unwrap();
        eprintln!(
            "rules={} compile_ms={} payload_bytes_estimate={}",
            size,
            started.elapsed().as_millis(),
            filters.payload_bytes()
        );
        for (path, query) in [
            ("exact", "exact42.bench"),
            ("suffix", "x.suffix43.bench"),
            ("miss", "allowed.example"),
        ] {
            group.bench_with_input(BenchmarkId::new(path, size), &query, |b, q| {
                b.iter(|| std::hint::black_box(filters.evaluate(std::hint::black_box(q))))
            });
        }
        // Precompute a deterministic broad working set, with no formatting or
        // random-number generation inside the timed matcher call.
        let mut seed = 1u64;
        let queries: Vec<_> = (0..8192)
            .map(|_| {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                let index = (seed >> 32) as usize % size;
                if index.is_multiple_of(2) {
                    format!("exact{index}.bench")
                } else {
                    format!("x.suffix{index}.bench")
                }
            })
            .collect();
        group.bench_function(BenchmarkId::new("working_set", size), |b| {
            let mut index = 0;
            b.iter(|| {
                let query = &queries[index];
                index = (index + 1) % queries.len();
                std::hint::black_box(filters.evaluate(std::hint::black_box(query)))
            });
        });
        // Typical deployments add a small allowlist; every evaluation must then
        // rule out an allow at each label before honouring a block.
        let mixed = FilterSnapshot::compile(
            &[
                ListInput {
                    name: "fixture".into(),
                    action: Action::Block,
                    rules: (0..size)
                        .map(|i| {
                            if i % 2 == 0 {
                                format!("=exact{i}.bench\n")
                            } else {
                                format!("suffix{i}.bench\n")
                            }
                        })
                        .collect(),
                },
                ListInput {
                    name: "allow".into(),
                    action: Action::Allow,
                    rules: (0..64)
                        .map(|i| format!("@@allowed{i}.example\n=keep{i}.bench\n"))
                        .collect(),
                },
            ],
            size + 129,
            usize::MAX,
        )
        .unwrap();
        for (path, query) in [
            ("mixed_block_exact", "exact42.bench"),
            ("mixed_block_suffix", "a.b.x.suffix43.bench"),
            ("mixed_allow_suffix", "cdn.allowed7.example"),
            ("mixed_miss", "www.unlisted.example.org"),
        ] {
            group.bench_with_input(BenchmarkId::new(path, size), &query, |b, q| {
                b.iter(|| std::hint::black_box(mixed.evaluate(std::hint::black_box(q))))
            });
        }
    }
    group.finish();
}
criterion_group!(benches, bench);
criterion_main!(benches);
