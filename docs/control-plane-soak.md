# Control-plane recovery soak

Goal: exercise repeated conditional retrieval, shadow review/promotion and SQLite
writer failures while real DNS clients keep receiving correct replies. Complete
when bounded measurement memory, phase correctness/recovery, sampled resources,
durable restart, short CI coverage and longer local evidence are verified.

Observed: the encrypted-upstream rehearsal already uses a bounded histogram;
the older management-failure example retains/sorts every latency sample. Long
runs therefore grow the measurement process itself. The downloaded-list slice
has short failure tests, but lacks repeated combined load/resource observations.

Design: share the existing histogram between example harnesses, preserving
microsecond buckets through 1 ms and 100 us upper bounds thereafter, capped at
2 s with explicit clipping counts and observed maxima. The recorded original
runs below used a 1 s ceiling; the appliance-comparison follow-up widened it
to cover the existing two-second query deadline. Replace management sample vectors. Add a
separate `control_soak` example rather than making the original scenario harder
to interpret. No production module, dependency, configuration or API changes.

The example starts one child daemon, one local UDP upstream and one private
HTTPS publisher. Two independent client lanes (permanent blocked and warm cached)
validate IDs, questions, flags, codes and A data. Each bounded cycle runs four
phases: unchanged conditional checks; changed shadow plus explicit promotion;
changed retrieval under a held SQLite writer lock; unconditional recovery,
asserted shadow promotion and subsequent 304 reuse. Marker queries verify that
shadow content does not change live DNS. Assert failure keeps active content and
no shadow, and telemetry failure/drops do not stop resolution. Check-now drives
existing scheduling faster than the minimum timer interval; no timer is shortened.
A generous source interval prevents unintended automatic attempts during the run.

Each phase records bounded per-lane histograms and before/after metrics. A single
observer samples the child RSS, FDs, threads, publisher sockets, API cache/inflight
counts and the single running/queued refresh slots. Keep initial/last/peak, not an unlimited sample list.
Quiescent samples per bounded cycle show whether resources settle; RSS is an
observation, not a portable pass/fail limit or proof against leaks. Assert finite
configured cache/inflight/download admission, eventual publisher socket disposal
and SQLite history/revision retention after shutdown. Restart without fetching
publisher data and check active content plus one full validator re-learning GET.

Alternative: extend encrypted_resilience with management/scheduler cases.
Rejected for now: that makes DNS upstream faults and control-plane costs hard to
attribute. Shared measurement logic is sufficient reuse; production behavior
stays isolated. Do not optimize DNS structures based on these measurements.

Verification: histogram boundary/merge tests; short real-process run and deliberate
wrong-answer fault to ensure the gate fails; existing workspace gates and a saved
production binary; repeated longer run with no concurrent builds/browser/fuzz/
container jobs; short CI report and optional manual long-run workflow. Preserve
binary hash, hardware, workload, latency/error/resource/transfer counters and
restart/durability evidence. UI, parser fuzz and dependency updates are deliberately
skipped because no product UI, protocol parser or dependency changes are planned.


## Method and checks

`control_soak` admits 1–16 cycles, 1–16 clients per lane, 1–500,000 generated
exact rules and a 100–60,000 ms minimum per phase. Traffic remains active until
control operations and the minimum duration have both finished. The failed-write
phase waits for a measured history write failure before releasing its external
SQLite lock; recovery requires persisted-event counters to resume. Per-phase
request counters reconcile all lane replies plus named-marker queries. DNS
failures/inflight overloads may not increase; clipped latencies, timeouts and
wrong replies fail the rehearsal. A deliberate corrupt-A-data mode must fail
specifically on the expected wrong-answer diagnostic, not any arbitrary error.

The child uses 16-entry decision/response caches, 32 inflight slots, 64 UDP query
slots, a 16-event telemetry queue and 1,000-row history. Repeated generations
exercise response-cache eviction. One HTTPS publisher is measured by child-owned
TCP FDs to its remote port: at most two sampled sockets (current plus retirement),
zero after each cycle. Native threads <=32 and FDs <=96 are generous fixture
checks, not product configuration limits. API observations show at most one
running refresh and one queued check. RSS is sampled without a pass/fail ceiling.
Sampling at 100 ms keeps only initial/last/peak; quiescent samples are bounded by
16 cycles. These observations do not prove instantaneous bounds or absence of
leaks. Benchmark clients/fixtures share the host's CPU with the child.

Histogram payload is fixed: 21,001 `u64` buckets per client (168,008 bytes), plus
aggregate histograms. The original management example now uses the same bounded
histogram while preserving its `responses`/latency JSON fields and adding clipping
counts. It adopts nearest-rank percentiles, microseconds through 1 ms and 100 us
upper-bound buckets above 1 ms. Long-duration memory therefore does not grow with
reply count. Fixture parsing and sockets still allocate; this is not a DNS
zero-allocation or CPU/query claim.

Build examples before the production binary and measure only after all builds,
fast tests, browser/fuzz/container work finish. The normal deployment CI runs two
300 ms cycles with 2,000 rules, preserves JSON/logs and rejects corrupted answers.
The optional manual Control-plane soak workflow accepts bounded numeric inputs,
quotes arguments and retains progress logs even if a later gate fails. No remote
workflow was triggered from the development workspace.

The first dry run exposed a fixture FQDN flag mismatch; fixture questions now
round-trip through Hickory without changing equality checks. A metrics-key typo
was corrected to the existing request counter. A two-cycle release run exposed
the short-run SQLite timing race described above; the lock now remains held until
history failure is observed. These were harness defects, not production changes.
The corrected short run, deliberate failure, existing encrypted-upstream
rehearsal, 108 Rust tests, formatting/strict Clippy, workflow YAML parsing and five
installer tests pass. UI, dependency/parser audits/fuzz and new transport work
are skipped because this slice changes only fixtures/CI/documentation.

## Management histogram comparison (2026-10-06)

AMD Ryzen 7 9800X3D, Linux 7.2.5-3-omarchy, rustc 1.98.1, shared/unpinned host.
Saved old and new release-mode harnesses used the same production-only binary,
SHA-256 `ac8ea46d793be5c67b404f92c9a6d3e14c164c5c2894607ceea54a9215b8e1b8`.
Four clients alternate blocked/cache-hit queries; five-second phases exercise
stalled management HTTP, a 200,001-rule shadow compile, SQLite failure and an
authenticated HTTPS body stall. Matched runs were sequential and quiet.

An external 100 ms `/proc/<harness-pid>/status` sampler observed peak **harness**
RSS 77,324 KiB before versus 14,500 KiB after; it excludes the appliance child and
includes fixture/controller allocations. It is sampled VmRSS, not allocator
attribution or a strict portable RSS gate. Latency p99 (µs):

| Phase | Before | After |
| --- | ---: | ---: |
| Baseline | 16 | 17 |
| Stalled HTTP | 17 | 17 |
| Compilation | 17 | 17 |
| Persistence failure | 17 | 17 |
| Stalled refresh | 17 | 17 |

No wrong replies/timeouts occurred. Do not attribute these small timing changes
to DNS improvements: the production binary is identical and the harness
aggregation/quantile method changed. Evidence under `target/control-soak/`:
`management-before-rss.json`, `management-after.json`, `old-harness-rss.json`,
`new-harness-rss.json`; `sample-rss.py` records the reproducible sampler. An initial
unsampled baseline (`management-before.json`) is retained separately.

Reproduce:

```sh
cargo build --release --locked -p rustwalld-dns --example resilience --example encrypted_resilience --example control_soak
cargo build --release --locked -p rustwalld-dns
TMPDIR="$PWD/target/tool-tmp" target/release/examples/control_soak --binary target/release/rustwalld-dns --phase-ms 8000 --cycles 10 --clients 2 --rules 100000 --output target/control-soak.json
```

Ensure `target/tool-tmp` exists before using it. Keep jobs idle during timed
sections. The manual workflow defaults match this command. This is a repeatable
local rehearsal; native systemd sandbox validation and hours/days of traffic on
the intended deployment host remain separate operator work.


## Ten-cycle local soak (2026-10-06)

Same hardware/binary as above; two clients per lane, 100,001 baseline rules,
eight-second minimum phases, ten cycles (40 phases), 320.473 s
elapsed. All 126,904,100 lane replies passed strict validation; no observed
timeouts, incorrect responses or clipped latencies. Per-phase request counters
reconciled the lane replies plus control marker queries. Healthy/failed/staged
checks were serialized through existing download admission and assertion gates.

| Lane | Phase p99 range | Phase p99.9 range |
| --- | ---: | ---: |
| Permanent block | 16–24 µs | 23–53 µs |
| Cache probe, including generation misses/evictions | 16–26 µs | 24–55 µs |

Sampled peaks across 3,162 observations: 15 response-cache
entries (configured limit 16), zero observed inflight entries (configured 32),
22 FDs, seven native threads, one publisher TCP socket, one running refresh.
No queued check was caught in a sample. Short-lived upstream lookups still
occurred; zero sampled inflight is not a claim of zero inflight work. The local
upstream observed 48 exchanges across promotions, marker probes and restart.
All publisher sockets were closed at each cycle's quiescent sample and shutdown.

Child RSS started at 61,824 KiB, reached 138,296 KiB and settled largely after
early cycles. End-of-cycle KiB: 129924, 136620, 138152, 138168, 138188, 138188, 138192, 138292, 138296, 138296.
Allocator/SQLite/runtime warm-up may contribute; it is not attributed by this
sampler. This short plateau cannot prove the absence of slow leaks. No RSS gate
or memory-per-effective-rule claim is made from whole-process measurements.

There were 73 authenticated publisher requests: initial full learning,
70 cycle requests and full re-learning/304 reuse after a real process restart.
Twenty changed candidates were explicitly promoted; ten attempted candidates
failed under held SQLite writer locks. Failures preserved the live policy and
left no shadow, while DNS continued and telemetry dropped/failed independently.
Each recovery required a full GET, successful assertion/durable shadow, explicit
promotion and subsequent HTTP 304. Durable generation 51 survived restart;
history retained 1,000 rows and revisions trimmed to 32 after exceeding
the retention window. Startup made no publisher request before explicit check-now.

Raw evidence: `target/control-soak/long-run.json`, progress/error log
`long-run.log`, and compact `summary.json`. No other builds, tests, fuzzing,
browser suites or container jobs ran during timed comparisons/soak. DNS production
code, dependencies and executable bytes are unchanged by this slice. Native
service sandbox activation and deployment-host hours/days of traffic remain
unverified here.
