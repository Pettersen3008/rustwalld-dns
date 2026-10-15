# DNS-020 Bounded remote soak driver

Status: Implemented and verified after Codex self-review, 2026-10-15.
Scope: Sprint 06, personal context, repository planning. Implements the driver
boundary of the [soak protocol](../engineering/soak.md); no lab activation.

## Outcome and grounding

An example CLI drives an already running, explicitly addressed private appliance
without starting/resetting it. Done means malformed/incomplete records cannot
start traffic, offered slots and completed/cancelled work reconcile, wrong replies
stop traffic, missing/over-budget evidence fails, bounded windows and merged bins
survive failure, and local UDP/TCP mocks demonstrate these paths.

Existing `control_soak`/`encrypted_resilience` own local child processes and closed
loop workers; `wire_compare` has fixed endpoints and scenario-specific answers.
Reuse Hickory and the shared 2-second histogram, leaving those modes intact.
The real status API exposes generation/cache/inflight but no host RSS/FD/disk
telemetry. No production endpoint, DNS path, persistent schema or dependency changes.
The standalone fuzz workspace directly declares the already locked Serde version
to exercise this exact example intake without exporting it from production libraries.

## Interfaces and ownership

`cargo run --locked -p rustwalld-dns --example remote_soak -- --run run.json
--output NEW_DIRECTORY` reads at most 256 KiB of strict versioned JSON. The
record freezes authority/identity/workload basis, client bind IPs, private numeric
UDP/TCP endpoints, ordered phase durations/rates/deadlines, resource/latency/output
budgets, sampler path and required external checks. Nonempty descriptions document
prerequisites; they do not manufacture user authority or verify representativeness.
The CLI never executes commands, service actions, faults or external final checks.

At most 32 lanes and 16 client identities. Each lane has a weight and up to four
hex-encoded reference DNS responses, parsed/validated by Hickory before networking.
Questions use IN and private `.test` names. Each phase selects valid response
indexes and sampled generations in advance, including explicitly bounded transition
outcomes; timeout allowances are frozen per phase. The oracle checks ID, question,
QR/opcode, flags, rcode, all RR owners/classes/data and per-record TTL ranges
(reference TTL is the ceiling; a lane supplies its floor), and EDNS equality.
UDP truncation optionally triggers TCP with header/partial-record checks followed
by a full oracle. Templates are fixtures, never learned from the target under test.

An operator-owned collector atomically replaces a local JSON sample file, possibly
transported from the appliance. Its schema includes run/target/process identity,
sequence, epoch milliseconds, generation, fixed resource gauges and up to 16
named counters. Samples must be fresh, monotonic and match the run; resource values
are compared to frozen numeric budgets. One-second polling summarizes first/last/
min/max online. Counter discontinuities preserve identity/reset information and
exclude unknown increments rather than invent deltas. Trusted collector transport,
clock alignment and actual remote collection are DNS-021 prerequisites. Local mocks
supply actual fixture samples; the driver does not claim independent provenance.

## Scheduling, recording and failures

One coordinator owns an open-loop monotonic slot schedule, at most 256 outstanding
queries and no work queue. Phases share one continuous schedule without draining
between them; results retain the originating phase's oracle/timeout allowance.
Window dispatch labels, completion-origin counts and inflight boundaries make mixed
completion windows explicit. Only the final offered interval has a bounded drain.
A late/unavailable send slot is counted as skipped and
fails the run. Each exchange owns a fresh socket (including after timeout), bounded
65,535-byte receive buffer and complete connect/write/read deadline, at most 2 s.
No retry hides loss. Cancellation aborts and joins owned tasks and reconciles
unfinished sent work as cancellations. No target process is owned or stopped.

At most 72 hours, 64 phases and 4,320 minute/partial-phase windows; qualification
records cap at 15 minutes. Resource polling cannot be starved by ready work.
The recorder streams per-lane window JSON capped at 16 KiB each, tracks per-client
counts, merges histogram counts, and writes final aggregate bins within 16 MiB.
Total artifacts cap at 128 MiB, reserving final evidence before window writes.
No query trace or growing logs. New directories prevent overwriting failed runs;
creation uses private file/directory modes. Output errors fail with partial files
preserved. A complete final report distinguishes driver acceptance from outstanding
external checks; it never closes DNS-009. Wrong-answer exemplars contain only a
bounded lane/phase/reason, never raw packets or unbounded peer errors.

An alternative was a controller that SSHes into hosts and injects faults itself.
That adds remote command/credential/service authority and a second deployment
system. Keep collection/fault ownership explicit at the lab-controller boundary.
This fixture format is new and versioned; existing example CLIs stay compatible.
See [ADR 0005](../decisions/0005-soak-controller-boundary.md) for this ownership choice.

## Verification

Local fixtures cover independent ports, UDP/TCP/truncation, full oracle mismatches,
TTL aging, timeout/late replies, open-loop overload, phase transitions, counter
resets, stale/missing samples, empty/clipped histograms, record/aggregate/artifact
caps and cancellation/socket cleanup. Run the actual CLI with valid and corrupted
fixtures and an independently started appliance; no public DNS or host services.
Run required fmt/strict Clippy/workspace tests/docs, example tests and diff review.
No latency/capacity claim follows from short local checks. Independent security,
representative network qualification and the authorized 24–72-hour run remain open.

Accepted: 473 workspace tests, required fmt/strict Clippy/docs, root/fuzz scans,
15 example regressions, six actual appliance CLI checks, real minute-boundary
recording and both legacy rehearsals pass. Seeded address-sanitizer smoke covers
the exact run/collector intake. Arithmetic regression reproduces/fixes the largest
accepted schedule's overflow. [Review](../reviews/sprint-06.md) records limits;
raw evidence stays under target/review/sprint-06/.
