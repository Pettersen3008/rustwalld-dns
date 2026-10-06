#![allow(clippy::unwrap_used)]
use criterion::{BenchmarkId, Criterion, SamplingMode, criterion_group, criterion_main};
use rustwalld_dns_filter::{FilterSnapshot, ParallelCompiler};
use std::time::{Duration, Instant};
#[path = "support/compilation.rs"]
mod support;
fn bench(c: &mut Criterion) {
    let sizes = std::env::var("DNS_BENCH_SIZES").unwrap_or_else(|_| "1000,100000,1000000".into());
    let workloads = std::env::var("DNS_BENCH_WORKLOADS").unwrap_or_else(|_| "mixed".into());
    let workers = std::env::var("DNS_BENCH_WORKERS").unwrap_or_else(|_| "0,2,4".into());
    let workers: Vec<usize> = workers.split(',').map(|s| s.parse().unwrap()).collect();
    assert!(workers.iter().all(|value| [0, 2, 4].contains(value)));
    let mut group = c.benchmark_group("compilation");
    group
        .sample_size(20)
        .sampling_mode(SamplingMode::Flat)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(2));
    for workload in workloads.split(',') {
        for size in sizes.split(',').map(|s| s.parse::<usize>().unwrap()) {
            let lists = support::fixture(size, workload).unwrap();
            for &workers in &workers {
                let compiler = (workers != 0).then(|| ParallelCompiler::new(workers).unwrap());
                group.bench_function(
                    BenchmarkId::new(format!("{workload}/{workers}"), size),
                    |b| {
                        b.iter_custom(|iterations| {
                            let mut total = Duration::ZERO;
                            for _ in 0..iterations {
                                let start = Instant::now();
                                let snapshot = match &compiler {
                                    None => FilterSnapshot::compile(&lists, size + 1, usize::MAX)
                                        .unwrap(),
                                    Some(compiler) => {
                                        compiler.compile(&lists, size + 1, usize::MAX).unwrap()
                                    }
                                };
                                total += start.elapsed();
                                // Destruction, fixture generation and pool creation are excluded.
                                assert_eq!(snapshot.effective_rules(), size);
                                drop(std::hint::black_box(snapshot));
                            }
                            total
                        });
                    },
                );
            }
        }
    }
    group.finish();
}
criterion_group!(benches, bench);
criterion_main!(benches);
