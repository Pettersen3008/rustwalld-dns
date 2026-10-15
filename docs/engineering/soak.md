# Representative network soak protocol

Protocol for [DNS-009](../planning/backlog.md#dns-009-run-representative-network-soak--e4--l),
prepared by DNS-018. Self-reviewed against the current real-process examples,
resource/histogram helpers, API and recovery contracts, 2026-10-15.
This specifies future lab work; no long run or representative target is active.

## Existing evidence and missing capability

`crates/app/examples/control_soak.rs` covers conditional retrieval, candidate review,
promotion, SQLite lock/history failure, recovery and restart. It uses loopback UDP,
two closed-loop lanes, at most 16 cycles and a minimum 100–60000 ms per phase; control
work can extend a phase. `encrypted_resilience.rs` covers local DoT/HTTP2 fixtures,
invalid replies/reset/stalls/outages and promotion with three UDP-client lanes.
`auth_resilience.rs` checks blocked/local DNS while bounded password jobs run.
`resilience.rs` covers stalled management, compilation and failed persistence.
These spawn their own appliance; they do not drive an existing remote deployment.

The shared histogram has 21,001 bins: exact microseconds through 1 ms, 100-us upper
buckets thereafter, 2 s cap, explicit clipped count and uncapped observed maximum.
Timeouts are separate from reply quantiles; zero samples report zero, not success.
Resource samples count child-owned FDs/TCP socket inodes, threads and RSS; they are
not all namespace sockets, allocation counts or complete storage/network telemetry.
The observers retain first/last/peaks, not a time series. Existing fixture-specific
cache/inflight/FD limits must not become universal appliance limits.

Extending a loop around these examples would reset state and retain their shared
host/loopback/closed-loop bias. DNS-020 must add a bounded remote-driver mode and
windowed evidence before DNS-009 can run. Reuse the existing correctness/parser/
histogram helpers where compatible; preserve their short local regression modes.

## Lab and fixed run record

Use separate load clients and a dedicated native or container appliance on the
intended class of storage and network path. At least one client must traverse the
operator's representative routed/VLAN path, rather than share the appliance's
loopback namespace. The operator identifies which devices/OS/client stacks and
query rates represent intended use. Sprint 04's disposable KVM guest alone does
not establish that. Public DNS is never queried: all upstreams/publishers are
controlled lab UDP/TCP/TLS/HTTPS fixtures with private test names and trust roots.
Do not redirect ordinary client DNS or change router/DHCP/firewall settings implicitly.

Before setup is accepted, freeze a private `run.json` lab record with:

| Input | Required content |
| --- | --- |
| Authority and ownership | User instruction reference, named target/clients, allowed service/network/fault actions, execution window, stop owner and reversal |
| Identity | Source revision plus working diff/manifest, binary/image and dataset hashes, feature mode, OS/kernel/runtime/hardware, topology and clock check |
| Workload | Seed, per-lane names/types/classes/expected RRsets or refusal, client identities/admission, transport mix, offered nominal/burst rates and outstanding-work bound |
| Limits | Actual caches/inflight/queues/connections/history settings; numeric client deadlines, latency/RSS/FD/thread/disk/output budgets and recovery deadlines |
| Faults | Ordered named start/end windows, target resource, expected DNS/control behavior and verified backup/undo action |
| Evidence | Monotonic start/end, duration, baseline/warmup windows, sampling cadence, output limits and required final checks |

This is proposed controller input, not an existing application configuration/CLI
format. Missing target identity, numeric budgets, representativeness or authority
prevents setup being Ready. No values are inferred from an empty template or an
old benchmark. Dataset/filter sizes and IPv4/IPv6 coverage must match the selected
target; unsupported paths remain explicit gaps. Keep credentials out of this record.

## Workload and oracle

Start with the following proposed private corpus mix, then freeze any adjustments
from sanitized operator workload counts before the run. Percentages are a planning
seed, not a claim about real household traffic:

| Lane | Weight | Required oracle |
| --- | --- | --- |
| Permanent blocks | 30% | Correct configured block mode and no upstream exchange |
| Explicit allows | 15% | Allow precedence over overlapping blocks, correct fixture answer |
| Warm-name probes | 20% | Correct answer/aging; measure actual cache-hit counters |
| Fresh forwarded names | 15% | Unique bounded names and known response data from local upstream |
| Local records | 10% | A/AAAA and selected typed/wildcard/passthrough semantics |
| Negative answers | 5% | NXDOMAIN/NODATA and SOA aging; distinguish no-data from block |
| Large/truncated replies | 5% | UDP size bound, TCP fallback and validated full answer |

The baseline core profile uses 80% UDP/20% client TCP. Add a declared encrypted-ingress
profile when incoming DoT/DoH is in the target's claimed scope; omission is not proof
of that feature. Enumerate qtypes within each lane rather than combine impossible
name/type/RRset expectations. Include schedule and exception expiry across a real
boundary: private TTL zero is valid. Verify source/generation via authenticated
explanations/events at control boundaries; do not invent per-query provenance from
aggregate counters. Privacy-disabled history must not be required for that oracle.
During publication, declare the valid old/new transition outcomes until the bounded
in-flight deadline, then require settled active behavior. Client send time alone
cannot prove which generation the server pinned.

The client validates ID, QR/opcode/question, rcode, owner/type/data and relevant
TTL/EDNS semantics. Retire sockets after timeout to reject late responses. An
open-loop rate controller has bounded outstanding work and records missed send
slots explicitly; silently reducing offered load cannot satisfy the nominal gate.
Warm-name probes may miss after TTL/publication: only actual metrics establish hits.

## Duration, faults and recovery

Begin with a bounded qualification run (at most 15 minutes), including an intentional
wrong-answer sentinel that must make the controller fail and stop. Once setup is
accepted and the actual long window authorized, run 24 continuous hours. Up to 72
hours needs an explicit window/limit; never extend automatically. A process restart
is a planned fault, not permission to reset the elapsed record or erase evidence.
Warmup is separately recorded before the 24-hour acceptance interval. Fault windows
must not overlap unless that combination is explicitly selected beforehand.

| Phase | Expected observation and undo |
| --- | --- |
| Healthy baseline/steady/burst | Expected replies and actual offered load; no unexpected timeout, wrong answer, clipping or exceeded target budget |
| Validate/stage/promote/rollback | Staging leaves active DNS unchanged; reviewed publication gets fresh IDs, assertions/provenance agree; in-flight old work remains pinned |
| Publisher 304/change/stall | Unchanged content/generation on 304; changed content only stages; failed fetch preserves live policy; recover then explicitly review |
| One/all upstream failures | Retain block/local/cache correctness; cold all-failed misses SERVFAIL, no bad reply cached; no plaintext TLS downgrade; successful uncached recovery |
| Serve-stale opt-in companion | Expired replies only under declared outage/age/TTL limits, stale metrics reconcile; disabled default tested separately |
| SQLite lock/history failure | DNS keeps last durable generation, mutation rejected, history/drop counters explain loss; release lock and verify durable recovery |
| Dedicated-volume storage fault | Only after backing up and authorizing that isolated volume; keep the recorder outside it, never fill host/root storage or delete live WAL; verify failure isolation and retained state |
| Graceful restart/recovery | Deadline fixed in run record; verify backup, active/shadow/schema/policy continuity and cold-cache DNS; keep old main/sidecars and restore into absent destination |
| Shutdown | Stop owned traffic/service per agreed prior-state plan, drain bounded work, verify no live owned sockets/processes, preserve final data and backups |

Healthz proves liveness, not upstream readiness. A failed storage/fetch action must
not be turned into a green readiness assertion. Scheduled fault windows distinguish
expected SERVFAIL/refusal/outage loss from unexpected loss; report both denominators.
Do not subtract an observed failure by widening its planned window afterwards.

## Evidence and decision gates

DNS-020's recorder must use bounded histograms/counters, at most 32 lane/transport
histograms (seven corpus lanes across up to four transports fit), counters for at
most 16 clients, and one-minute
windows (at most 4320 for 72 hours), one-second resource sampling with online min/max/
first/last summaries, a 16-KiB window-record cap and a 128-MiB total artifact ceiling.
Rotate logs within 32 MiB. Keep only bounded sanitized wrong-answer exemplars; no
unbounded packet/per-query trace. Final aggregate bins may occupy at most 16 MiB.
Reaching a collection/output limit is incomplete evidence and stops the run safely.

Each window records run/phase/lane/transport and bounded per-client counters,
offered/sent/replied/timed-out/wrong/
skipped/cancelled counts, elapsed monotonic time, quantiles/max/clipping, configured
generation and sampled resources/metric deltas. Reconcile sent work with replies,
timeouts, errors and cancellations; preserve counter resets across process IDs and
generations. Final quantiles merge histogram counts, never average window quantiles.
Report sample counts and bucket precision. Any clipped tail prevents a latency pass;
a target deadline beyond the current 2-second layout needs an explicitly bounded
measurement change before setup acceptance.

Stop immediately on a wrong answer/provenance, unauthorized mutation/admission,
data-integrity failure, exceeded resource/output/latency budget, missed generator
load, unexpected nominal timeout, controller death or missing mandatory samples.
Stop fault injection, restore the agreed service state, preserve failure artifacts
and mark the window failed/incomplete. Retry only with a changed hypothesis and
new run ID; never overwrite the failed run. No universal numeric latency/RSS SLO is
invented here: the setup record must supply target-specific values before starting.

Acceptance requires the whole authorized interval, each selected required phase,
correctness/accounting, configured bounds, recovery and reviewed failures. Missing
budget/coverage evidence remains unverified. DNS-009 cannot be Done from a short
local report or a 24-hour process that did not exercise its agreed workload.

## Delivery split

- DNS-020: implement/test bounded remote runner and record validation; no activation.
- DNS-021: authorize/qualify representative lab, backup/reversal and freeze budgets.
- DNS-022: execute the authorized long window and preserve failure/recovery evidence.
- DNS-023: analyze accounting, tails/resources and faults; reconcile DNS-009/release gates.

See [verification](verification.md), [performance](performance.md) and
[install/recovery](../operations/install.md). The short examples remain reproducible
failure rehearsals; Sprint 05's 100-ms checks verified report metadata, not capacity
or representative soak performance.
