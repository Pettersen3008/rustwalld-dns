# Rust 1.99 and measured optimization

The development and release toolchain is pinned to Rust 1.99.0. The reusable
libraries retain their Rust 1.95 minimum: upgrading our compiler does not require
downstream consumers to upgrade theirs. Dependencies and Cargo.lock are unchanged.
The [official release announcement](https://blog.rust-lang.org/2026/10/01/Rust-1.99.0/)
documents the new C variadic and raw-pointer layout APIs. Neither is needed by
this DNS engine. Raw-pointer layout APIs still have safety preconditions; their
stabilization does not make arbitrary pointer operations safe.

## Experiments

Local evidence lives in ignored `target/rust-1.99/`. The unchanged source baseline
is commit `c2acfc023a61960a31f7fa096dae8d85ba5cd347`, with saved Rust 1.98.1
executables and hashes in `baseline.json`. Measurements use the same AMD Ryzen 7
9800X3D Linux workstation, portable CPU settings, one codegen unit and otherwise
unchanged dependencies, features and fixtures. Rust 1.98.1 uses LLVM 22.1.8;
Rust 1.99.0 uses LLVM 23.1.1.

Criterion runs use 20 samples, one-second warm-up and two-second measurement
windows, in baseline/candidate/candidate/baseline order. Each benchmark is built
by its own package selection, then copied before another Cargo build can change
feature unification. Builds, tests, fuzzing and containers remain idle during
timing. Raw logs, per-launch medians and executable hashes are retained, including
unfavorable results. Summary comparisons average the two launch medians. These
short runs on a shared, unpinned desktop are diagnostics, not throughput or tail
latency guarantees.

Three separate comparisons isolate the compiler upgrade, thin versus fat LTO,
and query-name normalization on Rust 1.99. Benchmark code and workloads are
unchanged. Warm allocator probes remain separate from timing and assert that no
upstream exchange occurred.

Compiler-only results (thin LTO, unchanged source):

| Workload | Rust 1.98.1 | Rust 1.99.0 | Change |
| --- | ---: | ---: | ---: |
| Warm blocked wire query | 642.1 ns | 604.5 ns | -5.9% |
| Warm DNS cache wire query | 945.6 ns | 914.6 ns | -3.3% |
| Maximum-length cached name | 2,175.0 ns | 2,144.7 ns | -1.4% |
| DNSSEC flag cache partition | 1,047.6 ns | 1,004.1 ns | -4.2% |
| Local rewrite | 728.7 ns | 692.1 ns | -5.0% |
| Broad filter working set, 100k rules | 56.4 ns | 55.8 ns | -1.0% |
| Warm loopback DoT | 14.04 us | 14.27 us | +1.6% |
| Cold loopback DoT | 214.87 us | 215.21 us | +0.2% |
| Warm loopback DoH | 16.25 us | 16.01 us | -1.5% |
| Cold loopback DoH | 253.74 us | 240.14 us | -5.4% |

IPv6 binding selection changed from 26.6 to 27.6 ns (+3.8%); response-message
cloning changed by +0.5%. The first old exact-filter launch was 20.44 ns versus
15.52 ns in the last old launch, while the two new launches were 14.69 and
14.76 ns. All are retained in `toolchain-summary.json`; their averaged -18.1%
comparison is not a reliable estimate of the compiler's exact-match benefit.
This illustrates why individual launches and mixed outcomes matter.

Before the name change, fat versus thin LTO on Rust 1.99 improved every measured
wire-query case by 4.6–8.0%: blocked queries 591.2 to 551.0 ns, cache hits 921.4
to 860.1 ns, long-name cache hits 2,150.0 to 2,050.2 ns and rewrites 694.0 to
645.4 ns. IPv4 binding selection slowed from 14.8 to 15.7 ns (+6.3%), and mapped
IPv4 selection from 23.5 to 24.4 ns (+3.9%). The independent filter/cache/transport
comparison measured warm DoH -3.3%, warm DoT -1.2%, cold DoH -0.8% and cold DoT
-0.7%; cache operations were within 0.5%. Filter misses slowed from 34.2 to
36.5 ns (+6.6%) and suffix lookup by +2.9%; broad filter working sets changed by
-0.8% and exact lookup by -3.4%. The default adopts fat LTO for its full-query
benefit, retaining the smaller lookup regressions rather than claiming every
operation improves.

Fresh-process filter compilation, unchanged source and thin LTO on both
toolchains, averages two launches per version and size:

| Rules | 1.98 compile | 1.99 compile | 1.99 RSS | 1.99 peak RSS |
| --- | ---: | ---: | ---: | ---: |
| 100k | 26.5 ms | 25.0 ms | 20,450 KiB | 26,136 KiB |
| 1M | 447.5 ms | 430.0 ms | 205,726 KiB | 292,010 KiB |
| 5M | 2,967.5 ms | 2,852.5 ms | 833,370 KiB | 1,252,528 KiB |
| 10M | 6,680.5 ms | 6,491.5 ms | 1,662,356 KiB | 2,500,152 KiB |

Logical payload bytes and effective-rule counts match at every size. At 1M and
above, RSS/peak differences were under 0.3%; the smaller 100k process was about
0.5 MiB larger. These synthetic fixtures exercise the filter library directly;
they do not measure a whole serving daemon, simultaneous live generations or
fat-LTO compilation. The large cases still require substantial memory.

A separate 199 Hz user-CPU `perf` sample of a Rust 1.99 thin-LTO profiling build
compiling 10M rules reported no lost samples. About 38.8% of self samples were in
SipHash's `Hasher::write`, and 28.7% in the compiled filter method; normalization
and IDNA functions had much smaller separately attributed shares. The process
includes fixture generation and snapshot destruction; inlining and unresolved
frames prevent a complete phase breakdown. This points toward avoiding redundant
hash/map work before introducing parallel parsing. It does not justify replacing
the randomized hasher, weakening collision resistance or adding a global pool.

## Query-name ownership

Previously each supported query called `Name::to_lowercase().to_ascii()`. The
first operation copies Hickory's label data and label boundaries, and can allocate
for long names. The engine now calls Hickory's `to_ascii()` directly and applies
`String::make_ascii_lowercase()` to that output in place. It still uses Hickory
for parsing, escaping, question preservation, response encoding and truncation.
The original request remains untouched.

In Hickory 0.26.3, ASCII letters are emitted literally and other bytes use
escaped punctuation or octal digits. Lowercasing the formatted text preserves
those escapes and label boundaries. A differential regression compares the new
operation against Hickory's previous operation for every byte value at the start,
middle and end of a label, maximum-length escaped names, 127-label names, roots
and relative/absolute names. Existing wire tests cover telemetry, mixed question
case, rewrites, temporary allows, shadow decisions and UDP truncation.

The warm maximum-length cache fixture falls from 32 allocations / 6,413 allocated
bytes to 31 / 6,163. It removes the 250-byte intermediate label-data copy. Short
blocked queries remain 8 / 1,127, ordinary cache hits remain 10 / 1,149, and DO/CD
cache hits remain 11 / 1,421. These are per-query allocator probes around the
current-thread fixture, not process RSS or a zero-allocation claim.

On Rust 1.99 with thin LTO, the source-only comparison measured blocked queries
at 590.8 versus 583.1 ns (-1.3%), ordinary cache hits at 919.8 versus 908.7 ns
(-1.2%), long-name cache hits at 2,165.3 versus 2,125.6 ns (-1.8%) and rewrites
at 700.7 versus 684.3 ns (-2.3%). Across wire cases the change was -0.1% to
-2.7%. These small timing differences need more stable measurements before
claiming a general speedup; the eliminated long-name allocation is concrete.

The final same-source comparison, including the name change on both sides,
confirms the fat-LTO choice. Blocked wire queries measured 580.2 to 535.9 ns
(-7.6%), cache hits 905.3 to 850.0 ns (-6.1%), long-name cache hits 2,132.8 to
2,062.8 ns (-3.3%) and rewrites 686.8 to 637.3 ns (-7.2%). Across the wire cases
the change was -3.1% to -7.8%; the small binding lookups slowed by 4.0–6.4%.
Allocation counts match between LTO variants, including the reduced long-name
count. Do not add percentages from separate experiments to claim a combined
speedup; each comparison has its own timing window and baseline.

Rust 1.99 deprecates `AtomicU64::fetch_update` in favor of its renamed API. The
single use in upstream timing keeps the existing operation with a statement-local
documented allowance to retain compatibility with Rust 1.95. Its arithmetic,
ordering and concurrency behavior are unchanged.

## Optimization decisions

The release profile uses Cargo's default `opt-level = 3`, fat LTO and one codegen
unit. Fat LTO replaces thin LTO based on the workload comparisons below. It may
increase build time and build memory; downstream users choose their own workspace
profiles, so these settings do not force fat LTO on consumers of our libraries.
More optimization flags do not guarantee lower DNS latency; compare them using
the actual engine. The [Cargo profile documentation](https://doc.rust-lang.org/cargo/reference/profiles.html)
also explains that `panic = "abort"` terminates the process and is ignored by
ordinary tests and benchmarks. Adopting it would change task failure and cleanup
behavior; it is not part of this performance slice. Portable builds retain their
default CPU target. Host-specific native builds need their own measurements and
must not be compared against a portable baseline as a source optimization.

Production unsafe remains forbidden. No measured need justifies changing that
contract or replacing the DNS parser. Safe ownership changes are easier to
verify and retain. If a future profile identifies a safety-check bottleneck,
first try a safe API; any proposed unsafe exception needs explicit invariants,
malformed-input coverage, audit and measured benefit before changing the contract.

Rayon is already a development-only transitive dependency of Criterion, not a
production worker pool. A possible future use is parallel compilation of large
filter inputs on the control executor. First profile parsing, IDNA normalization,
deduplication, redundancy detection and map construction separately. Parallel
parsing must preserve rule IDs, source order, limit/error behavior and provenance;
those affect observable policy explanations. Compare small and large inputs,
peak memory, compilation duration and DNS p99 during compilation. If justified,
use an explicit bounded pool rather than all available cores or a global pool.
[Rayon's pool API](https://docs.rs/rayon/latest/rayon/struct.ThreadPoolBuilder.html#method.num_threads)
supports an explicit thread bound. Ordinary query processing does not need
collection-level data parallelism.

The next performance experiments should use a measured workload: cold and warm
queries, broad cache working sets and churn, long/escaped names, encrypted
connection reuse and failures, telemetry pressure and compilation during traffic.
Choose the bottleneck from CPU profiles and latency evidence; retain changes only
when their benefit survives repeat measurements and correctness checks. This
follows the reproducible, constrained iteration approach in the
[linked article](https://minimaxir.com/2026/09/agentic-iteration/), without promising
an arbitrary speed multiplier.

## Repository artifacts

The pre-change audit found 237 tracked files totaling 1,797,631 bytes, with no
tracked Cargo outputs, node_modules, built console, SQLite databases, Python
bytecode or GitHub workflows. Local `target/` occupied about 70 GB and
`web/node_modules/` about 209 MB; both were already ignored. These directories
include recoverable baselines and verification evidence and were preserved.

The ignore rules now cover `target/` at every depth, including independent
consumer workspaces, the local root `config.toml` generated by the quick-start
commands, plus local `.env` and `.env.*` overrides. Environment
examples remain eligible for tracking. Keep Cargo/npm lockfiles, fuzz seeds,
benchmark/test source, license notices and consumer fixtures: these are useful
reproducibility and distribution material. Large synthetic filter datasets stay
generated locally. This change adds no `.github/` directory or CI/CD.

## Verification and limits

Formatting, strict workspace Clippy, workspace tests/doctests, warning-free
Rustdoc, targeted Rust 1.95 core tests, all three independent consumers, all five
compiled crate archives, optimized core/resolver protocol tests, Python checks,
dependency audit and deny checks passed. The existing DNS parser/roundtrip fuzz
target completed 1,329,382 executions in 21 seconds without a crash. A first
parallel workspace test build had a linker killed; the original log is retained
and the full retry with two build jobs passed.

The unchanged real-process resilience harness ran old/new/new/old, with three
seconds per phase, four loopback clients and a 2,000-rule candidate. All phases
had zero incorrect replies, timeouts or clipped latency samples. Final-build p99
was 15 us in every phase in both launches; the old launches were 15–16 us. This
covers warmed local queries, stalled HTTP clients, compilation, failed SQLite
persistence and stalled scheduled retrieval. Short local p99 measurements are
diagnostics rather than production guarantees or a maximum-capacity claim.

The encrypted local failure/recovery harness passed, as did three reload/restart
cycles with 100,000 rules per candidate. All upstreams and publishers were local
fixtures. The isolated non-root Docker deployment test passed with external
networking disabled, including UDP/TCP, authenticated DoT/DoH, conditional list
retrieval, scheduled publication, upgrade, backup and restore.

The final native executable is 11,881,992 bytes (about 11.3 MiB), versus
12,991,064 bytes for the saved 1.98 executable. Its SHA-256 is
`8ed28694f17a752e40c8acf80bae058a22b3222aba032005cb7b1592ba115a02`.
Release archives verify that exact binary and include this report. Native host
activation and the existing 24–72-hour representative-network soak remain
separate release gates; this work changes neither their status nor the protocol
limits.
