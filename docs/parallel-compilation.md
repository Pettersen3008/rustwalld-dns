# Bounded parallel compilation

Rayon is useful for filter compilation, with workload-dependent gains. It is
**opt-in**: default library and appliance builds retain sequential compilation.
DNS correctness and latency take priority over faster reloads. The standalone
opt-in build owns two workers; library hosts can supply an owned 1–4-worker pool.
No query constructs a pool or submits Rayon work.

Checklist:

- [x] Save the unchanged compiler and shipping executable before editing.
- [x] Compare the original and refactored sequential compiler independently.
- [x] Implement bounded parsing/index work and differential contract coverage.
- [x] Measure sequential, two- and four-worker compilation and fresh-process RSS.
- [x] Measure UDP latency specifically during compilation/publication.
- [x] Verify extended reloads, runtime recovery, dependencies, fuzzing and MSRV.
- [x] Review and verify public consumers, archives and final artifacts.

## Implementation and invariants

The candidate preserves ordered deduplication and ID assignment, provenance,
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

## Measurements

2026-10-06, AMD Ryzen 7 9800X3D (8 cores/16 logical CPUs), Linux x86_64,
Rust 1.99.0, portable CPU settings, fat LTO, one codegen unit, unwind enabled.
Original source: `57a8f32c26466e30659c25dc248dc78b5eccbc54`.
Benchmarks run serially with our build/test/fuzz jobs idle. This is a shared
interactive desktop, without CPU isolation; background-load noise remains.
Evidence, saved executables and unfavorable launches stay in ignored
`target/rayon/`; generated large fixtures are not committed.

Fresh-process means of two launches per mode, ordered `0,2,4,4,2,0`:

| Mixed rules | Sequential | 2 workers | 4 workers | Peak RSS, sequential / 2 / 4 |
| --- | ---: | ---: | ---: | ---: |
| 1,000 | 0.260 ms | 0.298 ms | 0.291 ms | 2.9 / 2.9 / 3.0 MiB |
| 100,000 | 25.32 ms | 21.80 ms | 19.56 ms | 25.1 / 27.1 / 27.0 MiB |
| 1,000,000 | 424.97 ms | 386.95 ms | 362.44 ms | 285.9 / 309.9 / 311.0 MiB |
| 5,000,000 | 2,745.20 ms | 2,633.24 ms | 2,518.78 ms | 1,223.5 / 1,250.1 / 1,273.7 MiB |
| 10,000,000 | 6,042.09 ms | 5,849.19 ms | 5,583.65 ms | 2,442.6 / 2,471.0 / 2,493.3 MiB |

Mixed lists alternate exact and suffix rules, matching existing filter fixtures.
At 1M rules, suffix-only compilation measured 456.73 / 430.48 / 393.34 ms;
Unicode/IDNA exact rules measured 607.50 / 572.20 / 501.90 ms. At 100k Unicode
rules the two-worker saving was 26.6%, versus 13.9% for mixed rules. Workload and
size matter: this does not establish a universal speedup. New worker arenas may
retain allocator memory even after temporary parse results are freed.

Pool construction measured roughly 28–98 us, excluding subsequent allocator/TLS
warm-up. Input generation, pool construction and snapshot destruction are outside
compilation timing. RSS/HWM include input, snapshot, persistent workers and
allocator-retained transients. Payload estimates are identical across modes;
they are not allocator/RSS estimates.

Original/refactored sequential executables run `old,new,new,old` at every mixed
size. Mean compile times were 23.5/23.5 ms (100k), 427.5/421.5 ms (1M),
2735/2727.5 ms (5M), 6029.5/5944 ms (10M): no measured sequential regression.
The initial baseline is retained separately; an unusually slow 10M launch is
excluded from conclusions because overlap with preparation/build activity could
not be ruled out.

Criterion uses 20 flat samples and the same deterministic inputs. First mixed
means at 1M were 424.33 / 389.98 / 361.10 ms. A reversed-mode repeat is retained
separately, rather than choosing favorable samples. Small-list Criterion means
were 210.8 / 216.3 / 216.9 us: the owned-pool path offers no small-list benefit.
At 4,096 mixed rules, means were 0.926 / 0.820 / 0.755 ms; at 32,768 they
were 8.50 / 7.29 / 6.40 ms, also exercising work near the batch/index thresholds.
The benchmark excludes destruction using `iter_custom`, since destruction is a
separate cost; repeated measurements also exercise allocator retention. Fresh
processes complement those warm measurements.

Four UDP clients alternate blocked and response-cache queries against a two-worker
DNS executor and loopback mock upstream. Every reply is checked. Histograms cover
only the compile/publication window, including requests crossing its boundaries;
adjacent baseline/after windows last 250 ms. Quantiles are fixed-memory bucket
upper bounds: 10 ns resolution through 100 us, 1 us through 10 ms, then 1 ms
through 2 s. Counts are merged without discarding or sampling requests.

| Candidate rules | Compile-window p99, sequential / 2 / 4 |
| --- | ---: |
| 100k | 13.26 / 17.29 / 15.63 us |
| 1M | 15.32 / 15.25 / 15.47 us |
| 5M | 14.81 / 15.12 / 15.60 us |
| 10M | 14.91 / 14.98 / 14.97 us |

These are two-run means, not production guarantees. The short 100k windows show
an unfavorable tail result and substantial adjacent-window noise. Six further
launches each compile/publish 20 successive 100k-rule generations, reusing the
pool and retiring old generations. Mean compilation per generation is
24.27 / 20.68 / 18.53 ms; compile-window p99 is 14.15 / 14.62 / 15.04 us.
Every reply passes validation, exactly one mock lookup occurs per generation,
and the final generation is 21. Two-worker p99 rises 3.3% in these longer windows;
the unfavorable initial short-window results remain visible. Compilation is faster, but a blanket claim of
unchanged p99 would be unsupported. This is a reason to keep parallelism opt-in
and prefer two workers over a machine-sized/global pool.

Initial traffic measurements filled a per-client sample buffer at 5M rules;
that failed harness was replaced by tested bounded histograms. The first 10M
fixture also exceeded the unchanged rule limit by adding one sentinel rule;
the corrected fixture counts that sentinel within 10M. Those failures and valid
earlier measurements remain available. The initial 100k/1M/5M histogram fixture
had one extra sentinel; the final reproducer counts it within the requested size.

This follows the [iteration article's methodology](https://minimaxir.com/2026/09/agentic-iteration/):
preserve a true baseline, use heterogeneous inputs and a known-correct reference,
run serial Criterion measurements, retain regressions and avoid native-CPU flags.
An arbitrary speed target does not override this repository's DNS contracts.

## Final verification and limits

Formatting, strict all-target/all-feature Clippy, default and all-feature workspace
tests pass. Independent consumers run both default and optional modes, including
large-list staging, locked SQLite, caller cancellation, awaited shutdown, failed
assertions, shadow restoration, promotion and rollback under fresh IDs. All five
crate archives compile and their extracted public consumers pass. Rust 1.95 checks
all workspace targets/features; all-feature rustdoc and 14 Python tests pass.
Audit and deny pass, with existing duplicate-version warnings retained.

The differential filter fuzzer completed 44,025 inputs in 46 seconds, with generated
large seeds exercising batched parsing/indexing and varied rule limits. No crash
or sequential/parallel mismatch occurred. This bounded run is not exhaustive.

Matched filter query means at 100k/1M show exact -1.7/-3.0%, suffix +2.0/-0.7%,
and working-set +1.0/+1.5%. Initial miss results favor the candidate but have
visible baseline variability; they are not claimed as a query optimization.
Broad warm-wire means range from -1.3% to +6.9%, with cache/DNSSEC results needing
investigation. A focused 40-sample, longer `old,new,new,old` repeat measures blocked
-0.9%, cached +0.3%, DNSSEC cached +1.3%. Both sets remain available. Measured warm
allocation counts/bytes are unchanged: blocked 8/1,127, cached 10/1,149,
DNSSEC cached 11/1,421, maximum-name cached 31/6,163, rewrite 10/2,231.
These are the documented fixtures, not zero-allocation or general latency claims.

Actual default/optional binaries run counterbalanced resilience phases with 100k
rules, stalled HTTP/retrieval and failed persistence: no wrong answers or timeouts.
Three of the compilation phases have p99 15 us; the final sequential launch is
39 us and remains visible. These three-second phase percentiles include time
outside the brief compilation interval, unlike the compile-window histograms above.
Compiler request durations are 57/49/45/50 ms in sequential/parallel/parallel/
sequential order, including management parsing, validation and persistence.

The optional binary passes local encrypted-upstream failure/recovery and three
100k-rule control/restart cycles, finishing at durable generation 16. Settled RSS
is 84.0/87.2/110.0 MiB across those short cycles; do not infer a memory plateau
from them. The isolated `--network none` non-root installation rehearsal passes
UDP/TCP, DoT/DoH, conditional retrieval, scheduled shadow backup/promotion,
upgrade preservation and SQLite WAL recovery. Native sandbox activation and a
representative 24–72-hour network soak remain pending release gates.

Saved shipping hashes:

- Sequential: `f3c88e4a45e580484c00d6598d840dc6f563112a0ba9ccb7d50ac0858a615cbb`,
  11,886,184 bytes.
- Optional two-worker build: `ecc3aa66a837a70f36f1b88d45544a58cae21e391389dba9db4709c92665c299`,
  12,028,816 bytes.

Release manifests record the selected features and binary hash. Default normal
core/appliance dependency graphs contain no Rayon; enabling the optional feature
adds it only for control work. Build/test caches remain ignored. This verification
uses `CARGO_INCREMENTAL=0`, two build jobs and level-1 dev/test debug information
to limit disposable cache growth without changing release optimization. Saved
measurements/executables remain after disposable debug/MSRV/fuzz caches are cleaned.

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
