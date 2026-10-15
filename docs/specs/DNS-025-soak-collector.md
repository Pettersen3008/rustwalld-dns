# DNS-025 Bounded target-local resource collection

Status: Implemented and verified. Story: DNS-025, split from DNS-021 preparation.
Author: Codex, 2026-10-15. Personal context; repository planning. User requested
continuation with agents. No target/service activation or representative claim.
Separate read-only agent design review accepted the boundary with the storage/
stdout clarifications below; this is engineering review, not DNS-024 acceptance.

## Outcome and grounding

Deliver a reusable read-only Linux collector whose bounded stdout is accepted by
the existing remote driver's sample schema. DNS-020 used ignored Python fixture
code with real proc/status/metrics values but unbounded enumeration and generic
urllib redirects/proxies. Harden that small boundary rather than create SSH,
service/fault orchestration or a production telemetry endpoint.

Done: valid owned-process observations produce one complete envelope; incomplete,
stale/reused PID, ambiguous API ownership, oversized/special input or collection
deadline fails before stdout emission. Output failure may leave partial bytes;
the controller accepts only a complete parsed sample from a successful invocation.
A trusted controller owns invocation,
monotonic sequence and atomic installation/transport into the driver's sample file.
DNS-021 remains unready for actual representative qualification.

## Interface and ownership

`python3 scripts/soak-collect.py --run-id ID --target-id ID --pid PID
--start-ticks TICKS --api-url http://127.0.0.1:PORT --storage-directory /ABSOLUTE
--sequence N [--deadline-ms 750]` emits exactly one newline-terminated JSON envelope
of at most 16 KiB. No looping, target mutation, credential input or file publishing.
IDs match the driver's bounded ASCII syntax; integers fit u64, PID is positive.
Sequence is supplied by the controller and never inferred from stale output.
The fixed three counters are requests/cache_hits/history_failures from actual API
metrics. Six gauges retain the existing units/order. Unknown values never become 0.

PID/start ticks are checked before and after observation. Collector and target
must share the network namespace. Use owned socket inodes from bounded FD traversal
and the Linux proc TCP tables to require that the selected numeric loopback HTTP
address/port is a listening socket actually owned by this PID (wildcard binds may
match). Reject URL credentials, path/query/fragment, public/hostname endpoints,
redirects and environment proxies. Read-only status/metrics are not authentication
or per-query provenance; namespace/ownership and trusted execution remain explicit.
HTTP only for this leaf; HTTPS/password-mode sampling needs separate support before
that target can qualify. Never downgrade HTTPS.

Snapshot timestamp is observation start, preventing slow collection from making old
data fresh. Check required status/generation and exact selected counter types and
duplicates. Read generation again at the end; a concurrent change fails the sample
rather than attribute a mixed observation. Capture process resources from real proc
fields; FD count is owned descriptor count, not namespace sockets.

Storage is logical bytes of regular files under the named absolute directory,
including WAL/sidecars if present. Use descriptor-relative no-follow traversal,
checked u64 byte sums and stable opened-directory ownership. Bound depth to 8 and entries to 4096; reject
symlinks/special files and concurrent disappearance. This does not claim allocated
blocks, complete disk usage or a filesystem snapshot. Directory scope is frozen in
the external plan and evidence stays outside any fault volume.

Bound ordinary proc files to 64 KiB, TCP tables to 1 MiB, FD entries to 4096,
HTTP bodies to 64 KiB each and total process collection deadline to 100–2000 ms
(default 750 ms). Use a Linux process alarm/watchdog, fixed HTTP request timeout
within the remaining budget, and sanitized errors. The external controller must
also bound a remote invocation; local kernel/storage availability is not promised.
All collection finishes before stdout; a collection failure exits nonzero with no
sample. Collection watchdog ends before output. Controller must bound whole
invocation/output, capture successful complete JSON, parse it, then atomically
install; never forward a partial stdout stream into the live sample file.
No dependency changes.

Ownership: implementation agent owns only scripts/soak-collect.py and
scripts/tests/test_soak_collect.py in an isolated worktree. Coordinator owns records,
integration/actual daemon verification. Review agent remains read-only. Production
Rust, the remote driver schema, packaging and application config stay compatible.

## Verification and decisions

Focused tests cover accurate proc/metric parsing, ownership/namespace/start-tick
mismatch, missing/negative/boolean/duplicate/oversized values, redirect/proxy refusal,
storage/file/depth/FD limits, deadline and no partial stdout. Use owned local HTTP
and process fixtures only. Run actual CLI collection plus atomic handoff into a
short independently started appliance/remote_soak run, and deliberate failures.
Run all Python tests and required fmt/strict Clippy/workspace/docs checks. Audit/deny
and bounded seeded parser mutation checks supplement these parser/input changes.
No UI/performance/VM qualification is claimed.

Alternative: retain only a manual sampler checklist. It leaves the already observed
unbounded scratch code as the practical path. A generic SSH/fault framework adds
unresolved authority/transport assumptions; preserve ADR 0005's external boundary.

Accepted: separate agent code review resolved incomplete/ambiguous HTTP framing by
requiring one valid Content-Length, no Transfer-Encoding and complete bytes.
Eighteen focused tests, all 34 Python/473 workspace tests, required gates and six
actual owned-daemon/driver checks pass; 70000 seeded byte mutations complete without
unexpected parser failures. Audit/deny pass with retained warnings. No production
Rust/schema/dependency changes; [review](../reviews/sprint-07.md) and
[operator contract](../operations/soak-runner.md) describe limits. Raw evidence is
under target/review/sprint-07/. DNS-021 qualification remains open.
