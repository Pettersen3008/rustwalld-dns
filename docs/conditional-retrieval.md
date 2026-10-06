# Conditional downloaded-list retrieval

Automation note (2026-10-06): GitHub Actions and `.github/` were removed at
the maintainer's request. References to CI below describe historical verification;
run the documented commands locally and retain artifacts under `target/`.

Goal: reduce scheduled-check transfers and control-plane work without changing
DNS policy evaluation. Complete when validator/content isolation, HTTP 304,
changed-content shadow gates, failures, console evidence, restart recovery and
performance have been verified.

Observed: downloads are pinned/authenticated HTTP/1.1 with one admission slot,
15-second deadline, bounded headers/body and no redirect/persistent connection.
Scheduled unchanged bodies already avoid revision allocation but download/hash
all bytes and clone the configuration before fetching. Manual previews are full
GETs and must remain able to recover independently of automatic checks.

Design: a bounded runtime cache per scheduled source stores a content fingerprint,
validated generation, ETag (at most 512 ASCII bytes) and/or normalized HTTP date.
No persistent format or database migration. Source identity includes target,
URL, bootstrap IPs, private trust and interval. A cache from a staged body cannot
validate the old live body; after promotion it is eligible only for matching
stored bytes/hash. Generation changes with manually edited text are checked off
executor before validators are reused. Restart deliberately performs a full GET.

ETag takes precedence over Last-Modified. Reject unsolicited 304, malformed or
contradictory 304 validators; a 304 has no body, even if Content-Length describes
the selected representation. Weak ETags compare by opaque tag. Invalid/duplicate/
oversized optional 200 validators are ignored. A 200 replaces hints; a missing
validator cannot inherit an old one. Failed checks clear hints to permit full
recovery on the next check. A completion retired by runtime synchronization
cannot install validator state;
content fingerprints also protect the race before synchronization.
HTTP remains authenticated/pinned; validators never bypass candidate assertions.

304 preserves content, retrieval stamp and revision counter; only bounded
runtime check/transfer status changes. Changed 200 content clones configuration
in blocking work, compiles/asserts and persists shadow through the existing gate.
No timer promotion. Manual preview continues unconditional, including when the
publisher sends bad conditional responses. No new DNS lock, field or call path.

Alternative: durable validators in DownloadStamp. Deferred: source/trust/content
binding and metadata-only revisions add persistence/rollback complexity. Runtime
hints save steady-state transfers while preserving offline boot/backup semantics.

Verification: pure header/date/weak-tag tests and fuzzing; local HTTPS fixtures for
ETag/date/200/304/malformed/changed/stalled cases; generation edits and dismissed
shadows; restart with offline publisher and one full re-learning GET; browser
200/304 status; quiet pipeline baseline/comparison plus timed full/conditional
transfers with byte counts. Run formatting, strict Clippy, workspace/browser
checks, audits, release manifest verification and no-network deployment smoke.

Semantics follow RFC 9110 sections 8.8, 13.1.2, 13.1.3 and 15.4.5:
https://www.rfc-editor.org/rfc/rfc9110.html

The source is an explicitly configured policy mirror, not a general-purpose HTTP
cache. The operator's schedule sets deadlines; Cache-Control/max-age/Vary do not
change DNS policy or storage. A successful 304 is the authenticated publisher's
validation of the stored representation (weak ETags permit semantic equivalence),
not a fresh download/hash proof of byte-for-byte publisher equality. Stored
provenance always describes the bytes actually retrieved and reviewed.

## Verification evidence (2026-10-06)

The workspace suite passes 100 Rust tests; all 38 desktop/mobile browser flows
and five installer tests pass. Header tests cover strong/weak/empty tags,
duplicate/oversized/non-ASCII hints, canonical/obsolete dates and extreme years.
Local TLS fixtures verify validator precedence, 304 with representation length
larger than the body limit, malformed/contradictory replies, changed bodies,
full manual recovery, shadow dismissal/promotion, content edits, unrelated new
generations and a delayed reply racing publication. Fresh runtime tests require
an unconditional re-learning request. Strict Clippy, formatting and web build
pass. Root/fuzz cargo audits and npm audit report no known vulnerabilities;
cargo deny passes with existing duplicate-version warnings. Targeted
`download_config` fuzzing completed 342,815 inputs in 21 seconds without a crash;
its pure-header coverage opens no connections.

Measurements: AMD Ryzen 7 9800X3D, Linux 7.2.5-3-omarchy, rustc 1.98.1;
shared development host, unpinned scheduling/frequency. No concurrent builds,
fuzzing, browser suites or containers during timed sections. These are short
local observations, not an absolute throughput or strict network performance gate.

The transfer example uses 100,000 exact rules (`=b0.test` through `=b99999.test`),
1,288,890 bytes, SHA-256
`6f1e32c90fd0326575d79e99b24e5db078c396585af79349267064de6c49fc88`.
After discovery and four warm-up pairs, 40 full/conditional pairs alternate order.
Every request opens a fresh pinned/authenticated HTTP/1.1 connection. Full GET
median 2.419 ms, p95 2.720 ms; conditional median 1.328 ms, p95 1.450 ms.
Measured response body bytes: 51,555,600 versus zero. TLS and header bytes still
transfer. The example measures retrieval/hash costs, excluding candidate
compilation and DNS traffic; it validates 89 requests and zero remaining sockets.
Raw evidence: `target/conditional-transfer.json`.

The unchanged DNS engine benchmark uses 20 samples, one-second warmup and
two-second measurement per scenario, with saved `conditional-before` baseline.
Criterion mean point estimates (ns/query; includes full wire handling on DNS rows):

| Scenario | Before | After | Mean change |
| --- | ---: | ---: | ---: |
| `binding_select_ipv4` | 19.76 | 14.89 | -24.65% |
| `binding_select_ipv6` | 27.06 | 26.57 | -1.83% |
| `binding_select_mapped_ipv4` | 23.61 | 23.40 | -0.93% |
| `decision_cache_blocked_wire` | 631.28 | 615.47 | -2.50% |
| `decision_cache_blocked_with_exceptions_wire` | 655.61 | 634.10 | -3.28% |
| `dns_cache_hit_wire` | 987.58 | 973.86 | -1.39% |
| `expired_temporary_decision_cache_wire` | 653.55 | 635.20 | -2.81% |
| `temporary_allow_dns_cache_wire` | 1036.01 | 1000.34 | -3.44% |

No path regressed above the 10% investigation threshold. IPv4's baseline had a
wide confidence interval/outliers; the apparent improvement is not attributed to
this control-plane change. No DNS request code changed. Warm blocked queries
remain 10 allocations/1,151 allocated bytes; DNS cache hits (including temporary
allows) remain 13/1,259, measured by allocation-counter. The fixture includes
four subnet/device bindings with maximum metadata, finite caches and a saturated
telemetry queue; local paths assert zero upstream lookups. These counts do not
cover network/socket allocation or establish zero allocation. Raw logs:
`target/conditional-benchmark-{before,after}.log`.

Reproduce (build examples separately from the production binary):

```sh
cargo build --release --locked -p rustwalld-dns --example conditional_retrieval
TMPDIR="$PWD/target/tool-tmp" target/release/examples/conditional_retrieval
cargo bench --locked -p rustwalld-dns-core --bench engine -- --sample-size 20 --warm-up-time 1 --measurement-time 2 --save-baseline conditional-before
# Apply change, then compare in quiet conditions:
cargo bench --locked -p rustwalld-dns-core --bench engine -- --sample-size 20 --warm-up-time 1 --measurement-time 2 --baseline conditional-before
```

Browser verification uses disk-backed `TMPDIR="$PWD/../target/tool-tmp"` from
`web/`, avoiding the host's busy tmpfs/native Chromium failure documented in
scheduled-refreshes.md. The mobile/desktop conditional-unchanged screenshots
show `HTTP 304 · 0 body bytes · stored list retained` and retained retrieval stamp.


The production-only release binary (SHA-256
`ac8ea46d793be5c67b404f92c9a6d3e14c164c5c2894607ceea54a9215b8e1b8`)
also passed the existing real-process failure rehearsal: four UDP clients,
five-second phases, alternating blocked/warm cached names, 200,001-rule candidate,
stalled management clients, policy compilation and SQLite writer failure.
During an authenticated scheduled HTTPS body stall it returned 1,907,209 correct
responses with zero observed timeouts/wrong responses: p50 9 µs, p95 14 µs,
p99 24 µs, p99.9 64 µs. The baseline phase returned 2,093,628 correct responses
(p99 16 µs). The fixture verified one running refresh, finite admission (HTTP
429), durable publication failure isolation (503), cancellation and clean shutdown.
Raw report: `target/conditional-resilience.json`. This is a short loopback
rehearsal with a stalled full-body download, not a long-term soak or a conditional
retrieval latency measurement. The staged/published configurations differ across
phases; these numbers are not a strict comparative gate.

The deployment smoke verifies the same installed non-root binary through 200
learning, 304 unchanged checks, an actual process restart and full re-learning
before 304 reuse. Changed content remains an active-generation-5/pending-shadow-6
backup, survives upgrade and restore with the publisher offline, and requires
explicit promotion to generation 7. It runs in a no-network container; native
systemd sandbox activation remains a deployment-host check.
