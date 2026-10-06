# Shared filter strings: measured memory reduction

The completed release's next performance slice removes repeated domain and
list-name allocations without changing matching semantics, hashing, policy
generations or DNS parsing. Keep the change only with lower measured memory,
preserved provenance/precedence and no material lookup regression.

Each compiled rule now owns an `Arc<str>` domain shared with its matcher-map key
and the compiler's temporary deduplication key. All provenance entries from one
list share one `Arc<str>` list name. DNS lookups borrow `&str`; they neither clone
these references nor acquire a new lock. Compilation and control-plane traces
may clone references. Rule IDs, source lines and redundant rules remain retained.

Alternative: store integer string-table offsets or replace the domain maps with
packed structures. Those require more representation and lifetime machinery.
Ordinary shared strings address the measured duplication first; no custom trie,
parser, unsafe code or dependency was introduced. The Rust fields `Rule.domain`
and `Source.list` change from `String` to `Arc<str>`; JSON remains ordinary strings
and configuration/history formats do not change.

The logical payload estimate counts shared character bytes once. It includes
rule/source structures and occupied key/value entries, but excludes allocator
and Arc headers, spare vector/map capacity, list statistics and map overhead.
It is computed once during compilation; the status API reads a stored `usize`.
Neither this estimate nor process RSS is an exact allocator attribution.

## Reproducible measurements

Linux example `footprint` generates the same deterministic all-unique fixture as
Criterion: half exact rules, half suffix rules, list name `fixture`. Run **one
dataset per process**. After compilation, raw input and the deduplication map have
been dropped; `/proc/self/status` reports current VmRSS and process VmHWM. RSS
still includes allocator-retained compiler allocations, runtime and executable
pages. Peak includes compiler transients. Do not call these snapshot-only bytes.

```sh
cargo build --release --locked -p filtering --example footprint
for size in 100000 1000000 5000000 10000000; do
  target/release/examples/footprint "$size"
done
DNS_BENCH_SIZES=100000,1000000,5000000,10000000 cargo bench --locked -p filtering --bench matching -- --sample-size 20 --warm-up-time 1 --measurement-time 1
```

The additional `working_set` benchmark cycles over 8,192 precomputed names
selected by a fixed-seed LCG from each full dataset, half exact and half suffix
hits in expectation. Formatting and random generation stay outside the timed
call. It is a broader fixed working set, not fully random traffic or a measurement
of DNS packet latency. Existing repeated exact/suffix/miss cases remain intact.

Local before/after artifacts are in `target/filter-memory/`: source/binary
baseline, footprint output, Criterion reports, gates, compiler fuzzing and
real-process resilience/reload reports. Builds, tests, fuzzing and container jobs
must finish before timed network or Criterion comparisons. Shared/unpinned host
results do not define an automated performance gate.

## Results (2026-10-06)

AMD Ryzen 7 9800X3D, 8 cores / 16 threads; Linux 7.2.5-3-omarchy;
rustc 1.98.1. Release uses thin LTO and one codegen unit. No CPU pinning.
All four sizes preserve the effective rule count.

| Rules | Before RSS, KiB | After RSS, KiB | Before peak, KiB | After peak, KiB |
| ---: | ---: | ---: | ---: | ---: |
| 100,000 | 31,056 | 19,876 | 37,960 | 25,412 |
| 1,000,000 | 316,060 | 205,164 | 419,404 | 292,064 |
| 5,000,000 | 1,405,736 | 832,480 | 1,885,496 | 1,250,324 |
| 10,000,000 | 2,809,896 | 1,662,284 | 3,770,604 | 2,498,976 |

At ten million rules, current process RSS falls **40.8%** and peak RSS falls
**33.7%**. The logical payload estimate changes from 1,637,777,780 to
1,143,888,897 bytes (163.8 to 114.4 estimated bytes/effective rule), counting
shared characters once and excluding the overheads described above.

Fresh-process compile times, before/after in ms, were 29/30, 513/573,
3,068/3,595 and 6,819/7,681. After includes the newly precomputed estimate;
earlier code calculated it outside compilation. Pinned repeats report different
timings. These observations do not establish a compile-time speedup.

Review moved the estimate scan out of status reads, then replaced per-source
name hashing with the existing per-list unique/duplicate counts. Lists without
valid rules retain no shared name allocation; duplicate-only lists still count.
The whole scan stays on the compiler, and later API reads return one stored value.

## Lookup comparison and review

Fixed-name cases in the first full 100k/1M/5M/10M comparison stayed within 8% of
baseline. The broader working set prompted additional investigation: one later
unpinned 10M comparison was +10.6%; short alternating repeats pinned to CPU 4
included a +21.5% mean outlier. Those runs are retained, not discarded.

Three one-million-rule pinned pairs measured mean lookup times of
62.8/66.6, 63.3/67.7 and 63.5/67.6 ns before/after: a repeatable **6–7% cost**.
The short 10M pairs were 99.9/98.9, 96.1/116.7 and 89.9/99.4 ns. To investigate,
two longer 10M pairs used 30 samples, 2-second warmup and 5-second measurement on
the same core: **98.7/99.6 ns (+0.9%)** and **96.5/96.2 ns (−0.3%)**.
The >20% short-run regression did not reproduce in the longer comparisons.
Keep the memory improvement without claiming a lookup speedup or a strict
shared-host latency guarantee. Automated regression gating still needs a stable
runner; full random traffic and filter-specific CPU attribution remain separate
work. A later [CPU/query probe](cpu-query.md) accounts for warmed local engine
paths independently of these rule-memory comparisons.

For investigation the old source and identical updated benchmark were copied
into an isolated workspace with the same lockfile, then compiled into a fresh
target directory. One fresh native build was killed by the host; a two-job retry
passed before timing. Old/new processes alternated with other project jobs idle.
The complete short/long results and failed build log remain under
`target/filter-memory/`; process memory tables use unpinned fresh-process runs.

## Real DNS and correctness

The final production-only binary has SHA-256
`56c10a501404aa1428161590dd2586d2778f79e6404838ad58ad765a06df000d`.
The saved original binary is
`ac8ea46d793be5c67b404f92c9a6d3e14c164c5c2894607ceea54a9215b8e1b8`.
Examples were built before the production binary and executed directly.

Four loopback clients alternate blocked/cache-hit queries, using a local mock
upstream and a 200,001-rule shadow compilation. Each phase lasts five seconds.
Original versus final p99/p99.9 (µs):

| Phase | Before p99 / p99.9 | After p99 / p99.9 |
| --- | ---: | ---: |
| Warm baseline | 19 / 43 | 18 / 34 |
| Stalled management HTTP | 20 / 49 | 18 / 36 |
| Shadow compilation | 20 / 62 | 18 / 37 |
| SQLite writer failure | 60 / 502 | 18 / 37 |
| Stalled scheduled HTTPS body | 47 / 344 | 18 / 36 |

Both runs have zero incorrect replies/timeouts and only two upstream exchanges.
The lower tails cannot be attributed solely to string storage on a shared host;
these are diagnostic failure/reload observations, not a network performance gate.

The final single-thread warm wire-engine benchmark reports about 0.614 µs for a
blocked decision-cache reply and 1.001 µs for a DNS-cache reply. These are
Criterion iteration timings, not network percentiles. Allocator probes remain
**10 allocations / 1,151 bytes** and **13 allocations / 1,259 bytes** respectively,
with zero upstream lookups. This slice makes no zero-allocation claim.

The final binary also completed three repeated control-plane recovery cycles
(12 phases, 24.4 seconds) with 100,001 rules: unchanged conditional checks,
shadow/promote, SQLite failure, unconditional recovery and durable restart.
History retention was 1,000 rows, 13 revisions, durable generation 16; sampled
cache/inflight/download slots and handles stayed within fixture bounds.
See [control-plane soak](control-plane-soak.md) for limits and methodology.

All 110 Rust tests, strict workspace Clippy, formatting, five installer tests,
audit/deny and final filter-compiler fuzzing (286,921 executions / 31 seconds)
pass. Exhaustive overlapping rule pairs, independent snapshot lifetimes and
existing JSON explanation/real DNS regression tests preserve behavior.
CI keeps a one-million-rule footprint with Criterion artifacts. Browser tests
are skipped for this slice because no console code or response format changes.
The rebuilt release bundle passes the clean-container non-root installation,
UDP/TCP, warm encrypted-upstream, conditional-list, upgrade and recovery smoke
test. Native systemd sandbox activation remains a deployment-host check; no
host service, firewall or public DNS configuration was changed.
