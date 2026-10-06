# Scheduled list refreshes

Automation note (2026-10-06): GitHub Actions and `.github/` were removed at
the maintainer's request. References to CI below describe historical verification;
run the documented commands locally and retain artifacts under `target/`.

Opt-in periodic list checks yield a durable shadow candidate for review. Timers
never promote live policy. This slice includes schedule editing/status/check-now,
failure/conflict isolation, candidate persistence, restart/shutdown and validation
through real DNS queries, browser workflows and performance measurements.

Observed: HTTPS preview already bounds pinned destinations, trust, HTTP input,
body size, cancellation and deadlines. Configuration embeds source/list content.
The shared mutation gate serializes assertion-gated durable publication. Shadow
is already persisted, restored and backed up. A new queue would duplicate those
revision, retention and recovery contracts.

Design: optional refresh_interval_secs on FilterSource, 300 seconds through
30 days; omitted means manual-only. One app-owned worker checks one source at
a time, sharing download admission with manual previews. A one-slot check-now
request wakes the worker; concurrent/busy requests are refused. At most 64
schedule entries and one running check are retained. No new DB tables or schema.

Unchanged bytes update runtime status without allocating a revision. Changed
bytes are compiled off the executor, checked for nonempty rules, assertions,
fingerprint integrity and 16 MiB candidate size, durably committed as shadow,
then atomically published to shadow evaluation. Captured active/shadow revision
preconditions prevent overwrite of a concurrent edit or operator shadow. Existing
shadows pause every check, including after restart. Only explicit review/promotion
changes production. Shadow evaluation uses the existing DNS mechanism and has
its usual evaluation cost; scheduling adds no code or locks to DNS workers.

Runtime status records last result, failure, next monotonic deadline and running
source. Failed checks wait the configured interval; occupied admissions retry
after 30 seconds, never in a tight loop. Entries survive unrelated generations
when source identity/interval are unchanged, preventing reload retry storms.
Restart reconstructs deadlines from active retrieval stamps; runtime failure/
unchanged status is intentionally not a durable attempt ledger. Wall-clock changes
do not move an established in-process deadline. There is no catch-up burst.

Shutdown cancels in-progress network fetches and waits for compilation/commit
already in progress before stopping SQLite. Socket/task cancellation and slot
ownership must remain bounded. Locks protect only short runtime-state operations
and never span await or network I/O. Queued requests from retired generations
are discarded, as are queued checks paused by a new operator shadow. Failure
details are bounded and omit publisher URL/credentials.

Alternative: persistent independent drafts plus automatic scheduling/attempt
ledger. Deferred: it adds another queue, schema and promotion lifecycle. Reusing
the single durable shadow is adequate for a first reviewed-refresh slice, with
the explicit tradeoff that review pauses other scheduled sources.

Compatibility: old configurations remain manual-only. Existing schema-2 stores
need no migration. Older binaries cannot read sources with refresh_interval_secs;
use a compatible pre-feature backup when downgrading.

Review found and resolved JSON amplification before compilation, queued-check
retirement on shadow review, stale status/begin snapshots, and retired-job deadline
shortening after a new download stamp. Regression checks cover these cases.
DNS matching, cache keys, upstream selection and telemetry are unchanged.

Usage: Policies → Downloaded lists → Enable scheduled refresh. Set the interval
in seconds, validate the configuration, then review and promote it. A source
without a download stamp is due immediately after activation; a current stamp
waits one interval. Changing the publisher, target or interval creates a new
schedule. Editing the source in the console clears its retrieval stamp.
Check active schedule now runs the active configuration, not unsaved draft text.
GET /api/v1/filter-refreshes reports runtime state; POST /api/v1/filter-refreshes/check
accepts {source: index} with the current If-Match tag and returns 202 on admission.
Busy/review conflicts return 409; stale tags 412, absent tags 428 and a missing or
disabled schedule 422. Both endpoints require the management token.

The entire JSON-encoded configuration must fit 16 MiB when scheduling is enabled.
A counting serializer rejects amplification/oversized file configurations before
compilation without allocating another complete JSON buffer. Download body and
transport limits remain those documented in downloaded-lists.md. Timers use full
GETs; conditional retrieval, a durable attempt ledger, fleet jitter and automatic
live promotion are outside this slice.

Verification covers pure interval/legacy/JSON amplification checks; monotonic
deadlines and retired snapshots/jobs; one-slot admission and cancellation; real
HTTPS unchanged/changed/invalid/empty/redirect/stalled lists; assertion failures;
SQLite locks; concurrent active/shadow edits; and live DNS before promotion.
The deployment smoke restores an active scheduled configuration and pending
shadow with an offline publisher after upgrade and WAL backup recovery, then
explicitly promotes the restored candidate. No host service was installed.

The real-process resilience benchmark adds a successfully authenticated HTTPS
body stall with one pending scheduled download, warm blocked/cache DNS traffic,
four loopback clients and graceful cancellation. Its scheduled phase is capped
at five seconds, below the download's 15-second deadline. This complements the
local pipeline comparison; neither is a dedicated CI latency regression runner.

Quality checks: 94 Rust tests, strict all-target/all-feature Clippy, workspace
formatting, five installer unit tests, Rust root/fuzz lockfile audits, cargo-deny
and npm audit. Targeted download_config fuzzing processed 490,621 inputs in
21 seconds without a finding. No dependency versions changed.

Browser verification initially hit native compositor SIGTRAP/SIGSEGV and
screenshot failures with Playwright Chromium 153.0.8010.12; full bundled and
installed Chromium 152.0.7977.82 also failed with the default temporary directory.
Core/thread records identify native crashes; no kernel/cgroup OOM or PID-limit
events were recorded. A probe returned ERR_INSUFFICIENT_RESOURCES. On this shared
host /tmp is a busy tmpfs. Using a disk-backed workspace TMPDIR restored the
focused checks and all 38 desktop/mobile checks with the original bundled
browser. The precise
native cause remains unsymbolized; this is an observed test-environment workaround,
not a browser bug fix or a host configuration change. Failed-run/core evidence
is retained under target/refresh-browser-*. No extracted core copies remain.

Performance: AMD Ryzen 7 9800X3D, x86_64 Linux 7.2.5-3-omarchy, rustc 1.98.1,
shared unpinned desktop. No project builds, browser tests, containers or fuzzing
ran concurrently with timed measurements; unrelated desktop activity was not
controlled. Criterion uses 20 samples, one-second warm-up, two-second measurement,
the same four IPv4/IPv6 subnet/device bindings with maximum-sized annotations,
preseeded caches and one Tokio thread. No matching/cache/selection code changed.

| Path | Before estimate | First after estimate |
| --- | ---: | ---: |
| IPv4 selection | 14.739 ns | 14.761 ns |
| IPv6 selection | 26.598 ns | 27.479 ns |
| Mapped IPv4 selection | 23.352 ns | 30.601 ns |
| Blocked decision-cache pipeline | 625.04 ns | 621.14 ns |
| DNS response-cache pipeline | 986.16 ns | 975.58 ns |
| Temporary allow / DNS cache | 1,030.7 ns | 1,002.3 ns |
| Blocked / unmatched exception | 655.95 ns | 628.59 ns |
| Blocked / expired exception | 646.73 ns | 632.27 ns |

Blocked/cache pipeline changes are below 4.2%; this does not establish a speedup
or zero overhead. Warm allocator probes remain 10 allocations / 1,151 bytes for
blocked paths and 13 / 1,259 for DNS cache paths, including protocol parsing,
response cloning, serialization and a full telemetry queue. These local pipeline
estimates exclude sockets, concurrent refresh execution, CPU/query and RSS.

The first mapped-IPv4 sample crossed the investigation threshold (+31% slope
estimate, broad 27.561–33.099 ns confidence interval). An isolated repeat with
the identical executable, 30 samples and three-second measurement returned
23.470 ns (+0.51% relative to baseline), then 23.446 ns (+0.40%) on a
second repeat, without a code change. The large change did not repeat. All runs are
retained; shared-host variation is an inference, not a proven cause.

Real-process loopback run: four clients alternate warmed block/cache requests
for five seconds per phase, with two DNS and two control-plane Tokio threads,
a 16-event telemetry queue, 48 partial HTTP bodies, a 200,001-rule shadow
candidate and an external SQLite write lock. The single compilation request
overlaps 109 ms of its five-second sampling window. A separate scheduled phase holds
one authenticated publisher body stalled. The shipping binary SHA-256 is
`760a5ce954f09d45809351849d45fb187b1abd1906ff72737738f1a3e391c54e`.

| Phase | Responses | p50 | p95 | p99 | p99.9 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Baseline | 2,172,681 | 8 µs | 13 µs | 15 µs | 21 µs |
| Stalled API bodies | 2,168,747 | 8 µs | 13 µs | 15 µs | 20 µs |
| Shadow compilation | 2,131,516 | 9 µs | 13 µs | 16 µs | 22 µs |
| SQLite lock | 2,136,612 | 9 µs | 13 µs | 16 µs | 21 µs |
| Stalled scheduled body | 2,172,866 | 8 µs | 13 µs | 15 µs | 21 µs |

Every phase had zero wrong answers and zero DNS timeouts. There were two local
upstream lookups in total, one cache warm-up per active generation; the blocked
queries made none. API admission returned 429 under saturation; the locked
publication returned 503 without changing live policy. Telemetry drop/write
failure counters increased. The scheduled download remained one running check,
and graceful shutdown closed its socket. This synthetic closed-loop workload
cannot establish WAN latency, production throughput, CPU/query or RSS; no
zero-allocation claim is made. Native systemd sandbox activation remains untested.

Release verification uses a full locked production-only binary/npm build followed
by packaging the unchanged verified binary/assets with updated evidence documents.
All manifest hashes, production binary and compiled web assets are checked before
the final no-network container recovery smoke. The benchmarks use that same
production binary, not an example/dev-feature unified executable.


Follow-up: scheduled checks now support conditional retrieval. The original
measurements above cover the scheduler slice; current validator bounds, 304/body
byte diagnostics, recovery and measurements are in
[conditional retrieval](conditional-retrieval.md). Validators are not persisted;
stored list content remains available independently of the publisher.
