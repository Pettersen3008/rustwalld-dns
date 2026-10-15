#![allow(clippy::unwrap_used)]
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rustwalld_dns_filter::{Action, ClientContext, FilterSnapshot, ListInput, RuleSyntax};
fn bench(c: &mut Criterion) {
    let mut scoped = c.benchmark_group("denyallow");
    for count in [1usize, 128, 512] {
        let rules = (0..count)
            .map(|i| {
                let domains = (0..15)
                    .map(|n| format!("excluded{i}-{n}.test"))
                    .collect::<Vec<_>>()
                    .join("|");
                format!("||test^$denyallow=safe.test|{domains}\n")
            })
            .collect::<String>();
        let snapshot = FilterSnapshot::compile(
            &[ListInput {
                name: "scoped".into(),
                action: Action::Block,
                syntax: RuleSyntax::AdguardV3,
                rules,
            }],
            1000,
            1024 * 1024,
        )
        .unwrap();
        assert_eq!(snapshot.evaluate("x.safe.test").action, Action::Allow);
        assert_eq!(snapshot.evaluate("blocked.test").action, Action::Block);
        let deep = "a.".repeat(120) + "safe.test";
        for (path, query) in [
            ("deep_excluded", deep.as_str()),
            ("excluded", "x.safe.test"),
            ("blocked", "blocked.test"),
            ("unrelated", "outside.example"),
        ] {
            scoped.bench_with_input(BenchmarkId::new(path, count), &query, |b, q| {
                b.iter(|| std::hint::black_box(snapshot.evaluate(std::hint::black_box(q))))
            });
        }
    }
    scoped.finish();
    let mut clients = c.benchmark_group("client_scope");
    for count in [1usize, 128, 512] {
        let rules = (0..count)
            .map(|i| {
                format!(
                    "||test^$client={}\n",
                    (0..16)
                        .map(|n| format!("192.{}.{}.0/24", i / 256, (i % 256 + n) % 256))
                        .collect::<Vec<_>>()
                        .join("|")
                )
            })
            .collect();
        let snapshot = FilterSnapshot::compile(
            &[ListInput {
                name: "clients".into(),
                syntax: RuleSyntax::AdguardV5,
                action: Action::Block,
                rules,
            }],
            1000,
            1024 * 1024,
        )
        .unwrap();
        let matched = ClientContext {
            ip: "192.0.0.1".parse().unwrap(),
            name: None,
        };
        let missed = ClientContext {
            ip: "198.51.100.1".parse().unwrap(),
            name: Some("Kids"),
        };
        for (label, ctx) in [("match", matched), ("miss", missed)] {
            clients.bench_function(BenchmarkId::new(label, count), |b| {
                b.iter(|| {
                    std::hint::black_box(snapshot.evaluate_client(
                        std::hint::black_box("blocked.test"),
                        1,
                        std::hint::black_box(ctx),
                    ))
                })
            });
            clients.bench_function(BenchmarkId::new(format!("partition_{label}"), count), |b| {
                b.iter(|| {
                    std::hint::black_box(snapshot.client_partition(std::hint::black_box(ctx)))
                })
            });
        }
    }
    let response = FilterSnapshot::compile(
        &[ListInput {
            name: "response".into(),
            syntax: RuleSyntax::AdguardV5,
            action: Action::Block,
            rules: (0..512)
                .map(|i| {
                    format!(
                        "/.*/$client={}\n",
                        (0..16)
                            .map(|n| format!("192.{}.{}.0/24", i / 256, (i % 256 + n) % 256))
                            .collect::<Vec<_>>()
                            .join("|")
                    )
                })
                .collect(),
        }],
        1000,
        1024 * 1024,
    )
    .unwrap();
    let missed = ClientContext {
        ip: "198.51.100.1".parse().unwrap(),
        name: None,
    };
    clients.bench_function("response_value_miss_512", |b| {
        b.iter(|| {
            std::hint::black_box(response.evaluate_value_client(
                std::hint::black_box("192.0.2.1"),
                1,
                std::hint::black_box(missed),
            ))
        })
    });
    clients.finish();
    let mut tags = c.benchmark_group("tag_scope");
    for count in [1usize, 128, 512] {
        let rules = (0..count)
            .map(|i| {
                let names = rustwalld_dns_filter::CLIENT_TAGS
                    .iter()
                    .take(9)
                    .enumerate()
                    .filter(|(n, _)| i & (1 << n) != 0)
                    .map(|(_, name)| *name)
                    .collect::<Vec<_>>();
                format!(
                    "||test^$ctag=user_child|~user_admin{}\n",
                    names
                        .iter()
                        .map(|name| format!("|{name}"))
                        .collect::<String>()
                )
            })
            .collect::<String>();
        let filters = FilterSnapshot::compile(
            &[ListInput {
                name: "tags".into(),
                syntax: RuleSyntax::AdguardV6,
                action: Action::Block,
                rules,
            }],
            1000,
            1024 * 1024,
        )
        .unwrap();
        let identity = ClientContext {
            ip: "192.0.2.1".parse().unwrap(),
            name: None,
        };
        let miss = identity.with_tags(rustwalld_dns_filter::ClientTags::default());
        let hit =
            identity.with_tags(rustwalld_dns_filter::ClientTags::compile(["user_child"]).unwrap());
        assert_eq!(filters.rules().len(), count);
        for (path, ctx) in [("match", hit), ("miss", miss)] {
            tags.bench_function(BenchmarkId::new(path, count), |b| {
                b.iter(|| {
                    std::hint::black_box(filters.evaluate_client(
                        std::hint::black_box("test"),
                        1,
                        std::hint::black_box(ctx),
                    ))
                })
            });
        }
        tags.bench_function(BenchmarkId::new("partition", count), |b| {
            b.iter(|| std::hint::black_box(filters.context_partition(std::hint::black_box(hit))))
        });
    }
    tags.finish();
    let mut typed = c.benchmark_group("dnstype");
    for count in [1usize, 128, 512] {
        let snapshot = FilterSnapshot::compile(
            &[ListInput {
                name: "typed".into(),
                action: Action::Block,
                syntax: RuleSyntax::AdguardV4,
                rules: (0..count)
                    .map(|i| {
                        format!("||test^$dnstype=A|AAAA,denyallow=safe.test|excluded{i}.test\n")
                    })
                    .collect(),
            }],
            1000,
            1024 * 1024,
        )
        .unwrap();
        for (path, query, kind) in [
            ("blocked", "blocked.test", 1),
            ("excluded", "safe.test", 28),
            ("wrong_type", "blocked.test", 5),
            ("deep_excluded", &("a.".repeat(120) + "safe.test"), 28),
        ] {
            typed.bench_function(BenchmarkId::new(path, count), |b| {
                b.iter(|| {
                    std::hint::black_box(
                        snapshot
                            .evaluate_type(std::hint::black_box(query), std::hint::black_box(kind)),
                    )
                })
            });
        }
    }
    let values = FilterSnapshot::compile(
        &[ListInput {
            name: "values".into(),
            action: Action::Block,
            syntax: RuleSyntax::AdguardV4,
            rules: (0..4096)
                .map(|i| format!("||192.0.{}.{}^\n", i / 256, i % 256))
                .collect(),
        }],
        5000,
        1024 * 1024,
    )
    .unwrap();
    for (path, value, kind) in [
        ("value_match", "192.0.2.1", 1),
        ("value_miss", "198.51.100.1", 1),
    ] {
        typed.bench_function(path, |b| {
            b.iter(|| {
                std::hint::black_box(
                    values.evaluate_value(std::hint::black_box(value), std::hint::black_box(kind)),
                )
            })
        });
    }
    typed.finish();
    let mut regex = c.benchmark_group("regex");
    for count in [8usize, 64, 512] {
        let rules = (0..count)
            .map(|index| format!("/^track{index}[a-z0-9]*\\.fixture$/\n"))
            .collect::<String>();
        let filters = FilterSnapshot::compile(
            &[ListInput {
                syntax: Default::default(),
                name: "regex-fixture".into(),
                action: Action::Block,
                rules,
            }],
            count + 1,
            1024 * 1024,
        )
        .unwrap();
        for (name, query) in [
            ("match", "track7suffix.fixture"),
            ("miss", "allowed.fixture"),
        ] {
            regex.bench_with_input(BenchmarkId::new(name, count), &query, |b, q| {
                b.iter(|| std::hint::black_box(filters.evaluate(std::hint::black_box(q))))
            });
        }
    }
    regex.finish();
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
                syntax: Default::default(),
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
                    syntax: Default::default(),
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
                    syntax: Default::default(),
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
