# Bounded parallel compilation

Rayon is useful for filter compilation, with workload-dependent gains. It is
**opt-in**: default library and appliance builds retain sequential compilation.
DNS correctness and latency take priority over faster reloads. The standalone
opt-in build owns two workers; library hosts can supply an owned 1–4-worker pool.
No query constructs a pool or submits Rayon work.

## Implementation and invariants

The compiler preserves ordered deduplication and ID assignment, provenance,
invalid-line statistics, limit errors, allow precedence and randomized HashMaps.
Parsing uses indexed batches of at most 8,192 content lines and 1 MiB of input.
Each batch joins before ordered results are committed. Raw-rule limits are checked
before parsing; oversized individual lines follow the existing parser alone.
Parsing below 64 KiB per list and index construction below 32,768 rules use the
sequential implementation. Independent redundancy checks run in the owned pool;
exact maps are built by action and suffix pruning remains ordered control work.

`ThreadPoolBuilder::num_threads` bounds workers and `ThreadPool::install` runs
nested work in that pool, without initializing the global pool. See
[Rayon's owned-pool API](https://docs.rs/rayon/1.12.0/rayon/struct.ThreadPool.html#method.install).
Construction errors are explicit; compilation is synchronous and joined before
returning. Snapshots do not retain the compiler. No unsafe, weaker hashing,
custom DNS parser or query-side locks are introduced.

Policy compilation and assertion reports share the backend. Every returned
policy generation passes the original validation/assertion gates. Runtime startup,
active/shadow restoration, checks and staging share one caller-supplied pool.
Mutation admission, durable commit ordering, burned generation IDs, cancellation
and shutdown drain remain unchanged. Offline CLI checks/maintenance remain
sequential. Hosts must bound admission and run compilation off their DNS executor.

Alternative: parallelizing complete policies is simpler for many independent
large policies, but does little for one large policy. Deduplication remains serial
because parallel IDs/provenance or sharded merge logic would add complexity and
memory. The previous CPU profile already identified substantial hashing/serial
work, which limits the expected benefit. Additional workers cannot eliminate it.

## Reproduce and use

```sh
cargo test -p rustwalld-dns-filter -p rustwalld-dns-policy --all-features --locked
DNS_BENCH_SIZES=1000,100000,1000000 DNS_BENCH_WORKLOADS=mixed,suffix,idna \
  cargo bench -p rustwalld-dns-filter --features parallel --bench compilation --locked
DNS_BENCH_SIZES=100000,1000000 DNS_BENCH_WORKERS=4,2,0 \
  cargo bench -p rustwalld-dns-filter --features parallel --bench compilation --locked
cargo build --release -p rustwalld-dns-filter --features parallel --example compile_compare --locked
# Run one fresh process per mode/size, serially. Workers 0 selects sequential.
target/release/examples/compile_compare 1000000 2 mixed
cargo build --release -p rustwalld-dns-core --features parallel-compilation --example compile_load --locked
target/release/examples/compile_load 1000000 2
target/release/examples/compile_load 100000 2 20
# Explicit standalone opt-in; owns two workers across its durable lifecycle.
cargo build --release -p rustwalld-dns --features parallel-compilation --locked
# Fresh binary/console build and manifest recording the opt-in feature:
python3 scripts/release.py --parallel-compilation
```

For embedding, enable filter/policy `parallel` or runtime `parallel-compilation`.
Construct `ParallelCompiler::new(2)`, use `PolicySnapshot::compile_parallel` /
`check_parallel`, or pass an `Arc` to `Runtime::start_with_compiler`. The existing
constructors retain sequential behavior even when another dependency enables the
feature. Choose a worker budget that leaves CPU capacity for DNS, then measure
representative traffic on the deployment host. Native activation and the 24–72-hour
network soak remain the existing release gates.
