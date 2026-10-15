# Performance measurement and regression policy

Correctness, security and bounded latency precede throughput. Profile a suspected
bottleneck before adding a parser, trie, worker pool or concurrency mechanism.
The initial local goals are blocked p50 below 20us/p99 below 100us and DNS cache
p99 below 150us. These are workload-dependent targets, not measured guarantees.

## Compare like workloads

State a hypothesis, save the baseline executable before edits, and change one
variable at a time. Match hardware, affinity, toolchain, profile, features, inputs,
history settings and instrumentation. Separate compiler upgrades from source
changes. Build each benchmark package separately to avoid dependency feature
unification. Build the shipping binary separately from examples/dev dependencies;
retain its SHA256 and release manifest with raw local evidence.

Run baseline/candidate/candidate/baseline serially with other jobs idle; retain all
runs, errors, unfavorable tails and uncertainty. Record CPU/OS/toolchain, scenario,
rule counts, input hash, warmups, sample size, p50/p95/p99/p99.9, throughput,
upstream exchanges, correctness, history drops and RSS/HWM where meaningful.
Measure allocator counts separately in a single-thread probe. Logical filter
payload is an estimate; RSS includes allocator retention and compiler transients.
CPU ticks have quantization error; insufficient ticks yield unknown, not zero.

Investigate repeated changes above 10%; a confirmed regression above 20% normally
blocks acceptance on a stable matched local fixture. Shared-host noise needs
repeats and explanation. External upstream latency never sets a hard local gate.
Absolute latency/zero-allocation claims require actual hardware/workload/allocator
proof. Generated LOC, synthetic throughput or a single favorable run is insufficient.

## Reusable local workloads

```sh
cargo bench -p rustwalld-dns-filter --bench matching --locked
DNS_BENCH_SIZES=100000,1000000,5000000,10000000 cargo bench -p rustwalld-dns-filter --bench matching --locked
cargo run --release --locked -p rustwalld-dns-filter --example footprint -- 1000000
cargo bench -p rustwalld-dns-core --bench engine --locked
cargo bench -p rustwalld-dns-resolver --locked
cargo run -p rustwalld-dns-core --release --locked --example load
python3 scripts/measure.py target/release/examples/load
cargo build --release --locked -p rustwalld-dns-core --example cpu_probe
python3 scripts/cpu-probe.py --output target/cpu-query.json
python3 scripts/metrics.py > target/source-metrics.json
```

Use compilation benchmarks and the [bounded compiler procedure](parallel-compilation.md)
for sequential/parallel comparisons. Keep default sequential builds and opt-in
owned pools distinct. Include 100k/1M/5M/10M datasets as resources permit; generate
large input locally. Shorter sizes/runs must be labeled, with remaining gaps.

Cover block/miss/cache/rewrite, maximum-length and escaped names, DO/CD, closed/
empty/full telemetry, coalescing/cancellation, reload and failed persistence where
relevant. Loopback mocks verify response/question/provenance and upstream counts
before latency is considered. Bound response CNAME/value work and full queues;
failed/partial responses never count as a speed improvement.

The real-process examples `resilience`, `encrypted_resilience`, `control_soak` and
`auth_resilience` exercise failure isolation; commands and scope are in
[operations](../operations/install.md). The existing CPU probe excludes allocation
instrumentation. scripts/compare-appliances.py runs pinned competitors with local
mocks and requires Linux cgroup v2, Docker and distinct physical cores. A
closed-loop comparison is not a maximum-capacity or universal product-speed claim.

The [representative soak protocol](soak.md) defines the distinct long-run target,
workload/oracle, fault windows, recorder bounds and acceptance prerequisites. Existing
short examples spawn local fixtures; they are not a remote representative-soak runner.
Their shared histogram uses a 2-second cap and 21,001 bins, retains uncapped maximum
and clipped counts, and excludes timeouts from reply quantiles. Preserve counts and
precision when comparing reports; a clipped or empty tail is not a latency pass.

## Retained design choices

Current code uses shared immutable filter strings, borrowed decision lookups,
miss-only owned forwarding requests, bounded CLOCK-style cache eviction and
ordinary safe maps. Hickory remains the parser/encoder. Rayon is opt-in and
compilation runs off DNS executors. Preserve those boundaries; rerun current
measurements before extending or replacing them.

The previous dated measurement essays are retired. Their complete text and the
uncommitted docs snapshot are recoverable via [the cleanup map](../archive.md).
They establish historical observations only. [DNS-004](../specs/DNS-004-baseline.md)
defines the next reproducible baseline and its remaining acceptance work.
