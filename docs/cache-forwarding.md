# Construct forwarding requests only on admitted misses

Automation note (2026-10-06): GitHub Actions and `.github/` were removed at
the maintainer's request. References to CI below describe historical verification;
run the documented commands locally and retain artifacts under `target/`.

Goal: remove measured request cloning/normalization from DNS-cache hits and
coalesced waiters, while preserving canonical upstream questions, DO/CD cache
partitions, per-client EDNS sizing and existing bounded cancellation-safe work.
Complete with allocator/timing evidence, protocol regressions and release checks.

The engine previously built a complete normalized forwarding message before the
resolver probed its response cache. The resolver then cloned that message again
when admitting a new upstream flight. Only the admitted leader needs an owned
forwarding message.

The resolver boundary now gives `Resolver::resolve` the accepted client message,
upstream profile and generation. The resolver constructs its existing `CacheKey`
from that message, probes the cache and checks bounded flight admission. Only a
new flight clones the message, uses the key's canonical question name, clears AD
and replaces client EDNS with payload 1232 plus the original DO flag. CD is
preserved. The engine still restores each caller's ID, question and transport
size on its private response. Cache contents, TTL aging, generation partitioning,
sharding, telemetry and task cancellation semantics remain unchanged.

Alternative: add an engine cache probe before constructing the forward message.
That duplicates resolver cache/metric logic and introduces an extra cache probe
on misses. A lazy closure API would also work but is unnecessary with one caller
and an existing concrete resolver boundary. No parser or transport redesign.

Risks: normalization must occur before upstream I/O, but only after admission;
DO/CD, question type/class, profile and generation must still select independent
keys. Coalesced callers with different casing, IDs or UDP sizes must receive their
own correctly encoded replies. Missing questions return a typed encoding error.
No persistence/API format migration is needed. The Rust resolver method signature
changes together with its workspace callers.

Verification: matched Criterion allocator/timing runs with blocked, cached,
temporary, rewrite and live telemetry fixtures; add maximum-length mixed-case and
DO/CD cache scenarios. Local mock regressions inspect the actual forwarded
message and gate a flight so differing client sizes/cases join deterministically.
Test DO/CD, type, profile and generation separation; run formatting, strict
Clippy and workspace tests, then matched real-daemon resilience and package
recovery with the production-only binary. Parsing/dependencies are unchanged.

## Allocator and timing evidence (2026-10-06)

AMD Ryzen 7 9800X3D, Linux 7.2.5-3-omarchy, rustc 1.98.1,
release thin LTO / one codegen unit; shared, unpinned host. A single-thread Tokio
executor isolates allocation probes from unrelated workers. Warmed fixtures
assert zero upstream lookups; even unexpected misses use loopback addresses.
Live empty queues drain outside each timed call with `BatchSize::PerIteration`.
Compare before/after within a scenario; iteration times are not network latency
percentiles or absolute throughput claims. No zero-allocation claim.

```sh
cargo bench --locked -p rustwalld-dns-core --bench engine -- wire --save-baseline cache-forward-before --sample-size 30 --warm-up-time 1 --measurement-time 2
cargo bench --locked -p rustwalld-dns-core --bench engine -- wire --baseline cache-forward-before --sample-size 30 --warm-up-time 1 --measurement-time 2
```

| Scenario | Allocations before / after | Allocated bytes before / after | Mean ns before / after |
| --- | ---: | ---: | ---: |
| Blocked decision-cache | 9 / 9 | 1,139 / 1,139 | 626 / 625 |
| DNS cache, short IN A | 12 / 11 | 1,248 / 1,160 | 986 / 927 |
| DNS cache, maximum-length mixed case, DO/CD | 36 / 33 | 7,254 / 6,666 | 2,252 / 2,169 |
| DNS cache, short name, DO/CD | 13 / 12 | 1,520 / 1,432 | 1,086 / 1,037 |
| Temporary allow, DNS cache | 11 / 10 | 1,237 / 1,149 | 1,008 / 944 |
| Blocked, unrelated exception | 9 / 9 | 1,139 / 1,139 | 631 / 633 |
| Blocked, expired exception | 9 / 9 | 1,139 / 1,139 | 634 / 638 |
| Local rewrite | 10 / 10 | 2,231 / 2,231 | 716 / 706 |
| Blocked, empty live queue | 9 / 9 | 1,139 / 1,139 | 659 / 653 |
| Blocked, full live queue | 9 / 9 | 1,139 / 1,139 | 621 / 621 |
| DNS cache, empty live queue | 12 / 11 | 1,248 / 1,160 | 1,021 / 962 |
| DNS cache, full live queue | 12 / 11 | 1,248 / 1,160 | 977 / 923 |

Cached cases improved by about 3.7–6.4% in this matched local run; other cases
stayed within 1.5%. Allocations remain in parsing, keys, cached responses,
telemetry and encoding. Results describe these warmed fixtures, not cold channels
or arbitrary workloads. Long-name labels contain 63/63/63/61 ASCII bytes and use
EDNS payload 4096 (clamped to 1232 for the client) with DO/CD enabled.

Artifacts: `target/cache-forward/criterion-{before,after}.log`,
`criterion-summary.json`, saved source files and preceding production binary.
No build, test or container job ran concurrently with timed measurements.

## Correctness review

The upstream observer gates one flight while differently cased/ID'd clients with
legacy UDP, EDNS or TCP join it. The observed upstream request is lowercase,
AD-cleared, CD-preserving and uses EDNS 1232; all callers retain their own wire
question and size behavior. A follow-up cache query succeeds after the mock
closes. Additional tests partition DO/CD, A/AAAA, profile and generation; an
empty resolver request admits no upstream work.

The first long-name fixture assumed that identical casing guaranteed legacy UDP
compression. Hickory writes the name before searching compression pointers, so
its intermediate maximum-length write can exceed 512 bytes. The regression now
asserts this existing truncation for both legacy callers and complete answers
for EDNS/TCP. This change does not replace the library encoder. Existing tests
also cover escaped/raw labels, coalesced initiator cancellation, TTL aging,
temporary expiry, bounded overload, malformed input and reloads.

Review found no production defect. Normalization remains within an admitted,
bounded flight and no mutex spans an await or network I/O. The resolver derives
the cache key internally, eliminating a caller-supplied message/key mismatch.
The public method consumes accepted queries; protocol admission remains in the
DNS engine. No database, filesystem, JSON, plugin, cache representation or
transport pool change was added.

## Production binary and failure checks

Build the resilience example separately before the production-only binary, to
avoid dev-dependency feature unification. Current binary SHA-256:
`7429d5b07d91b5406508eff68fcf60681a0a01a7c466ce28aaad42507336430a`.
The saved preceding release is
`02ba4d5605aa3ed4b920a5919d5e46ff2ce3840bb5c8b708440434937df05925`.

Both run the same local mock harness, four clients alternating blocked/cached
queries, five-second phases and a 200,001-rule candidate. Other project jobs were
idle. These network percentiles are diagnostic, not allocator attribution or a
strict performance gate on a shared host.

| Phase | Before p99 / p99.9 µs | After p99 / p99.9 µs |
| --- | ---: | ---: |
| Warm baseline | 16 / 27 | 16 / 29 |
| Stalled management HTTP | 16 / 28 | 16 / 26 |
| Shadow compilation | 16 / 27 | 15 / 21 |
| SQLite writer failure | 16 / 27 | 15 / 21 |
| Stalled scheduled HTTPS body | 16 / 25 | 15 / 22 |

Both binaries returned zero wrong replies/timeouts and performed two upstream
exchanges. The current binary validated 10,696,783 replies. Reports are
`target/cache-forward/resilience-{before,after}.json`.
Results demonstrate continued DNS service during the exercised failures, not a
universal bound on response time.

All 115 Rust tests, strict workspace Clippy, formatting, fresh audit/deny checks
and five installer tests pass. The initial fixture borrow error and Clippy
initializer warning were corrected; failure logs are retained with the fixture's
legacy-UDP assumption failure. No new parser fuzz campaign or browser run was
needed: parsing, dependencies and console code/formats did not change. Protocol,
encrypted transport, malformed-input and cancellation regressions ran in the
full suite. Native systemd sandbox activation remains a deployment-host check.

The production-only release and console were rebuilt. A clean network-isolated
container passed non-root installation, UDP/TCP, authenticated warm DoT/HTTP2 DoH,
reviewed/scheduled/conditional list retrieval, shadow/upgrade/backup recovery,
annotations and expired exceptions. The final documentation repack retains the
same tested runtime payload; manifest hashes and the measured binary SHA-256
are verified in `target/cache-forward/release-verification.json`.
`deployment-smoke.log` records the container gate. No host service, firewall or
public resolver was changed.
