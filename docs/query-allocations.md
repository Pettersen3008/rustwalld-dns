# Removing redundant query string copies

Automation note (2026-10-06): GitHub Actions and `.github/` were removed at
the maintainer's request. References to CI below describe historical verification;
run the documented commands locally and retain artifacts under `target/`.

Goal: reduce measured query allocations while preserving DNS replies, policy
generation isolation, event contents and nonblocking telemetry. Complete with
before/after allocator and timing evidence, protocol regressions, real-process
reload/failure testing and verified release packaging.

The engine previously allocated a normalized ASCII name for policy matching,
copied it into a decision-cache key even for rewrites/temporary allows, and copied
it again into query telemetry. Hickory still owns decoding, label escaping,
question preservation, response encoding and truncation.

After matching and shadow evaluation finish, the engine removes only the
trailing root dot and moves that existing normalized string into `QueryEvent`.
Decision keys are constructed only when the decision cache is actually used.
Key contents, lookup/insertion order, shard bounds and generation semantics do
not change. Expiry after an upstream wait still reevaluates the pinned policy.
Telemetry remains an owned event sent with `try_send` after response encoding;
full/closed queues drop events and increment the existing counter.

Alternative: change the cache representation to support borrowed composite keys
or redesign Hickory parsing/response buffers. Those require broader profiling
and correctness work. This slice instead changes ordinary string ownership; no
new dependency, custom parser, unsafe code, worker-local cache or lock was added.

Moving the string may retain formatting spare capacity in queued events. The
queue remains bounded and DNS names retain the library's length bounds. The
allocation probes count allocations and allocated bytes during an answer, not
the exact retained memory of a busy history queue. No zero-allocation claim.

## Fixtures and method

`crates/dns-core/benches/engine.rs` uses a single-thread Tokio executor, warmed
decision/DNS caches and no upstream exchanges. The fixture now uses only a
loopback endpoint even if an unexpected miss occurs; each scenario asserts zero
upstream lookups. Allocator probes run separately from timing and exclude
response parsing, fixture construction and unrelated async workers.

Existing closed-queue wire scenarios cover blocked, DNS-cache and temporary
exception paths. New scenarios cover a local rewrite plus live empty/full queues
for blocked and DNS-cache replies. Empty-queue timing uses Criterion
`BatchSize::PerIteration`: the preceding event is consumed/dropped outside the
timed call so every measured answer has an empty queue. Full-queue timing retains
one queued event. Compare before/after within a scenario; different batching and
destructor accounting make cross-scenario absolute times unsuitable comparisons.

```sh
cargo bench --locked -p rustwalld-dns-core --bench engine -- wire --sample-size 20 --warm-up-time 1 --measurement-time 1
```

Local artifacts are under `target/query-alloc/`, including saved source/binary,
Criterion baseline, allocator logs, checks and loopback/recovery reports. Timed
runs must have other project builds/tests/fuzz/container jobs idle. Synthetic
warm wire-engine iteration times are not network latency percentiles or an
absolute throughput claim.

Protocol cases cover mixed case, escaped dots/backslashes, raw zero/high octets,
root and maximum-length names, source/decision-cache/shadow/exception fields,
original question casing/IDs, legacy UDP truncation, invalid-question events and
full/closed queue accounting. The raw-label fixture initially tried the hostname
validator; it now uses Hickory's raw-label API. A longest mixed-case answer also
exposed expected legacy UDP truncation: large-answer cases use EDNS, with a
separate regression asserting the 512-byte truncated reply.

## Local measurements (2026-10-06)

AMD Ryzen 7 9800X3D (8 cores / 16 threads), Linux 7.2.5-3-omarchy,
rustc 1.98.1, release thin LTO / one codegen unit; shared, unpinned host.
Requests use the short names `blocked.test` and `cached.test`, IN A, generation
1 (rewrite uses generation 2). These are single warmed-query allocator probes,
not a guarantee for arbitrary DNS names, cold channels or cache misses.

| Scenario | Allocations before / after | Allocated bytes before / after | Mean iteration ns before / after |
| --- | ---: | ---: | ---: |
| Blocked decision-cache, closed queue | 10 / 9 | 1,151 / 1,139 | 619 / 611 |
| DNS cache, closed queue | 13 / 12 | 1,259 / 1,248 | 990 / 972 |
| Temporary allow, DNS cache | 13 / 11 | 1,259 / 1,237 | 1,010 / 1,012 |
| Blocked with unrelated exception | 10 / 9 | 1,151 / 1,139 | 626 / 623 |
| Expired exception, blocked | 10 / 9 | 1,151 / 1,139 | 632 / 622 |
| Local rewrite | 12 / 10 | 2,255 / 2,231 | 719 / 694 |
| Blocked, empty live queue | 10 / 9 | 1,151 / 1,139 | 647 / 641 |
| Blocked, full queue | 10 / 9 | 1,151 / 1,139 | 619 / 608 |
| DNS cache, empty live queue | 13 / 12 | 1,259 / 1,248 | 1,020 / 1,005 |
| DNS cache, full queue | 13 / 12 | 1,259 / 1,248 | 992 / 973 |

All timing comparisons stayed within 4% of baseline; this does not support an
absolute speed or throughput claim on other hardware. The allocation savings
are the reason to retain the change. No fixture performed an upstream lookup.

## Real-process verification

The production-only binary has SHA-256
`02ba4d5605aa3ed4b920a5919d5e46ff2ce3840bb5c8b708440434937df05925`;
the saved preceding release is
`56c10a501404aa1428161590dd2586d2778f79e6404838ad58ad765a06df000d`.
Examples were built separately before the production binary, then run directly
with other project jobs idle. Both binaries use the same current fixture.

Four clients alternate blocked and cached replies, with five-second phases and
a 200,001-rule shadow candidate. p99 / p99.9 (µs), before/after:

| Phase | Before | After |
| --- | ---: | ---: |
| Warm baseline | 15 / 22 | 15 / 21 |
| Stalled management HTTP | 15 / 21 | 15 / 21 |
| Shadow compilation | 16 / 22 | 15 / 20 |
| SQLite writer failure | 15 / 21 | 15 / 22 |
| Stalled scheduled HTTPS body | 15 / 21 | 15 / 21 |

Both runs have zero wrong replies/timeouts and two upstream exchanges. Network
results are diagnostic, not a strict latency gate or an allocation attribution.

Three control-plane recovery cycles with 100,001 rules completed 12 phases in
24.4 seconds, validating **9,943,427 replies with zero errors/timeouts**. Failed
persistence preserved live DNS, explicit promotions/recovery and restart passed,
and history stayed at 1,000 rows / 13 revisions / durable generation 16. Sampled
cache/inflight/refresh slots, threads and FDs remained within fixture bounds.
See [control-plane soak](control-plane-soak.md) for detailed semantics and limits.

All 112 Rust tests, strict workspace Clippy, formatting and fresh audit/deny
checks pass. Review found no production correctness defect; formatter spare
capacity in queued domains is the documented memory tradeoff. No new parser
fuzz campaign or browser flow was required: neither DNS parsing/dependencies nor
console code/response formats changed. Existing malformed-input tests and the
new raw-label/queue regressions run with the full suite.

Five installer tests and the rebuilt release's clean-container non-root
installation, UDP/TCP, warm DoT/HTTP2 DoH, conditional HTTPS lists, upgrade and
durable recovery checks pass. Native systemd sandbox activation remains a
deployment-host check. No host service, firewall or public resolver was changed.
