# Temporary exact-domain allows

Goal: temporarily allow one exact domain for clients using a chosen effective
policy, without waiting for management/SQLite to remove the exception at expiry.
Done means real UDP/TCP queries, warm caches, delayed upstream work, shadow,
restart/rollback, diagnostics and console editing all honor the same deadline.

An exception has a name, domain and absolute Unix-second `expires_at`. Domains
use the existing IDNA normalization. Bounds: 1,024 exceptions per policy, 4,096
per generation, unique names and normalized domains within a policy, and at most
seven days remaining at compilation. Expired entries remain valid historical
configuration but are never reactivated by compilation with a correct clock.

policy compiles an optional exact-name map into each immutable policy. Entries
retain their configuration index for provenance, absolute wall-clock expiry and
a conservative monotonic deadline. The normal path checks a single optional map
before the decision cache. No timer, plugin, mutable expiry table, DB or filesystem
is needed. An empty policy adds only a branch. A matching entry consults the
system clock; an expired monotonic deadline short-circuits that clock read. A fixed
one-way atomic expiry flag prevents an observed expiry from reviving after a
forward/backward clock jump. Rule content and deadlines remain immutable; there
is no global expiry lock or dynamically grown runtime structure.

Local rewrites keep precedence. Temporary decisions never enter the decision
cache. Normal upstream cache/single-flight keys stay generation/profile isolated;
only the private response copy sent to this client gets its record TTLs capped.
After an upstream wait, recheck the exception. If expired, apply the permanent
filter decision; synthesize a block if required. Snapshot retention does not
extend deadlines. Shadow uses the same exception evaluation without enforcement.

Alternative: schedule an automatic control-plane revision at expiry. Rejected as
the correctness mechanism: SQLite locks, executor stalls or failed promotion could
leave the exception active. Control-plane cleanup may be added independently.

Live wall-clock rollback cannot extend the monotonic deadline; a forward jump
expires an allowance early. Restarts/recompilation reconstruct remaining time
from absolute expiry and require a trustworthy system clock. No DNS appliance
can withdraw answers already used by applications or terminate their connections.
Sub-second remaining allowances emit TTL zero; clients must honor DNS TTLs.

Required assertions intentionally test permanent policy, excluding temporary
allows. Current-policy explanations and query telemetry identify actual temporary
decisions. Removing an exception uses normal validation/shadow/promotion and a
fresh generation. Rollback never resets its `expires_at`.

app retains fixed-size exception indices in the bounded telemetry queue. SQLite
schema 2 adds a nullable history column in a transaction, preserving schema-1
queries/revisions. Read-only maintenance accepts schema-1 snapshots; restored
stores migrate at daemon startup. New-schema stores are not downgrade compatible.
Existing configuration without exceptions remains readable and serializes as
before. Compilation/assertions/durable revision gates stay ahead of publication.

Verification: deterministic clock/normalization/limits tests; local UDP/TCP cache
and delayed/coalesced expiry checks; permanent-policy TTL isolation; expiry with
blocked management and full telemetry; strict assertion rejection; shadow and
fresh-generation removal/rollback; schema-1 upgrade/backup/restart tests; real
browser editing/explanations; targeted fuzzing and before/after Criterion with
allocator measurements. Build/test/fuzz/container jobs remain idle during timing.

## Operation

Use **Policies → Temporary exceptions** to select a policy, add a named exact
domain and choose 15 minutes, one hour, eight hours or 24 hours. The absolute
expiry is captured when added to the draft; validation/shadow time consumes that
allowance. Follow the existing validation, shadow and reviewed promotion workflow.
Removing an entry changes only the draft until promotion. Expired entries are
retained for inspection; cleanup does not control enforcement.

Policy configuration adds optional `temporary_exceptions`, an array of objects
with `name`, `domain` and numeric Unix-second `expires_at`. The API accepts the
same complete policy configuration; no separate unreviewed mutation route exists.
`GET /api/v1/temporary-exceptions` requires the management token and returns the
active generation plus each configured entry's policy, zero-based index, name,
normalized/configured domain, expiry and live active state. It reads the compiled
snapshot without SQLite. Current explanations include the active exception.
History/shadow events carry a nullable zero-based index scoped to policy and
generation; look up that revision for the original name/domain. Old events have
null provenance. Required reports explicitly state `basis: "permanent_policy"`.

## Verification evidence — 2026-10-05

79 Rust tests and 30 desktop/mobile browser checks passed, including real
UDP/TCP/cache queries, 16 coalesced requests retained across publication and
expiry, SQLite lock failure, process restart, expired rollback, Unicode labels,
revocation and preservation of schema-1 history/revisions. Formatting, strict
Clippy, Rust/npm advisory checks and the five packaging checks passed. Cargo deny
passed with existing duplicate-version warnings. The updated policy-check fuzz
target completed 48,538 executions in 21 seconds without a failure, covering
active/expired/out-of-range exception expiry and arbitrary domains alongside
assertion-report/strict-compilation agreement. Short fuzzing is not exhaustive.

The production bundle passed the clean non-root Debian container smoke with
local DoT/HTTP2 DoH fixtures, UDP/TCP temporary allows, permanent assertions,
schema-2 WAL backup, upgrade and expired-exception recovery. Its production-only
binary SHA-256 is
`fee022cdd3fdff19bf9953ce17cc9399a6e8a23bd069821affb99113b8dec58c`.
Native systemd sandbox activation remains a deployment-host check. No service
was installed on the development host. Review found and corrected empty-array
draft canonicalization and Unicode published-state labels; browser fixtures now
select their own generation/event instead of assuming unbounded history or
instant telemetry persistence. No outstanding defect was found in the reviewed
exception publication/expiry path; the documented clock and DNS TTL limits remain.

Quiet Criterion: AMD Ryzen 7 9800X3D (8 cores/16 threads), x86_64 Linux
7.2.5-3-omarchy, rustc 1.98.1, optimized Cargo bench profile. One-second warmup,
two-second measurement, 20 samples; same unpinned shared desktop before/after,
other project build/test/fuzz/container jobs idle. Each iteration performs DNS
wire parse, evaluation, serialization and a bounded telemetry attempt through a
single-thread Tokio runtime. It excludes socket delivery and SQLite. Responses
are preseeded; counters verify zero upstream requests. The one-slot telemetry
queue is full after warmup, so this measures the normal dropped-event path.

| Warm path | Before | After (Criterion estimate and interval) | Allocations / allocated bytes |
| --- | --- | --- | --- |
| Blocked decision-cache hit, no exceptions | 607.33 ns | 596.99 ns (595.72–598.72) | 10 / 1,151 |
| DNS-cache hit, no exceptions | 968.48 ns | 967.03 ns (964.00–970.86) | 13 / 1,259 |
| Active exact allow, DNS-cache hit | — | 1,003.4 ns (1,000.3–1,006.8) | 13 / 1,259 |
| Blocked decision-cache hit, unmatched exception | — | 616.54 ns (612.38–622.05) | 10 / 1,151 |
| Blocked hit after observed exception expiry | — | 615.84 ns (612.59–620.11) | 10 / 1,151 |

Allocation-counter probes measure total allocations/bytes for one warm iteration,
including parse/clone/telemetry/serialization. Ordinary-path counts match the
before probes. Observed expiry in the benchmark fixture is forced via a future
monotonic lookup, exercising the one-way flag without an hour-long wait. These
results do not establish p99, RSS, CPU/query, throughput, zero allocation or a
statistically stable regression gate. They show no concerning ordinary-path
change in this short run; no parser/cache optimization was introduced.

Repeat with:

```sh
cargo bench -p rustwalld-dns-core --bench engine --locked -- \
  --warm-up-time 1 --measurement-time 2 --sample-size 20 \
  --save-baseline temporary-after
```

Local raw evidence: `target/temporary-final-tests.log`,
`target/temporary-browser-final.log`, `target/temporary-fuzz.log`,
`target/temporary-benchmark-before.log`, `target/temporary-benchmark-after.log`
plus `target/temporary-deployment.log`, `target/temporary-release.log`
and `target/criterion/*/temporary-{before,after}/`. Screenshot evidence is in
`web/test-results/exceptions-*/temporary-allow.png`.
