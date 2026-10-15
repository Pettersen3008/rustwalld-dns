# Sprint 07 Review and remaining acceptance

2026-10-15. Personal context; repository planning, no Jira. User requested commit/
push and agent-assisted continuation. DNS-025 collector was reviewed, verified and
pushed as `4a980b6`. DNS-026 now qualifies synthetic Docker lab mechanics. DNS-021
representative acceptance and the sprint's full goal remain open.

## Delivered

A separate implementation agent owned collector/tests, then the private Hickory
fixture extension in isolated worktrees. A second read-only agent reviewed design,
code, controller and actual evidence. Coordinator integrated exact worker files,
owned planning/VMs and independently verified acceptance. This is engineering peer
review, not DNS-024 independent security acceptance.

The one-shot collector verifies actual PID/start/namespace/owned API and bounded
proc/storage/status/counters. The driver schema and production DNS path remain
unchanged. The controller owns bounded pinned transport, complete-success JSON
validation and atomic private publication, as [ADR 0005](../decisions/0005-soak-controller-boundary.md)
already specifies. `wire_compare` now exports ten fixed Hickory references and
accepts explicit private IPv4 server binding; count control stays loopback.

The user had approved a separate VM and continued after the concrete two-VM
proposal. Reusing that authority enabled the bounded lab without another permission
round. Two new Debian 13/KVM guests used restricted management NICs, a loopback QEMU
Ethernet link, no default routes/uplink and a dedicated appliance state disk.
Docker host networking existed only inside the appliance VM; actual DNS/API
listeners, UID 10001, zero capabilities, no-new-privileges, read-only root and restart
disabled were checked. Authenticated history records the independent client's
actual private source. The old native guest and unrelated router VMs were untouched.

## Acceptance evidence

- Pilot: 500 correct replies across all 20 weighted lanes. Frozen lab budgets have
  headroom and do not establish production capacity or latency SLOs.
- Qualification: 70 seconds at 20 QPS, then 20 seconds at 100 QPS; 3400 correct
  replies, exact UDP80/TCP20, no wrong/timeouts/skips, all lanes covered. Merged bins,
  dispatch/phase accounting and after-drain target request counters reconcile.
- Deliberately wrong oracle stops with one wrong reply; collector loss fails
  freshness; SIGINT fails with a cancellation disposition. SIGINT arrived with no
  outstanding exchanges, so this run does not demonstrate cancelling live sockets.
- Live CLI backup and verification, stopped restore into an absent database and
  500 correct queries after a cold-cache restart preserve generation 1. Restart-to-readiness is
  0.622 seconds, excluding backup/restore work. Original state and backup are kept.
- All six run source/plan hashes, actual deployed binary/collector/driver/fixture
  hashes and saved image config/layers were checked. Failed attempts remain intact.
  OCI index identity and guest Docker config identity are recorded distinctly.
- Owned services stop successfully, application restart stays disabled, both guests
  are off and owned PIDs/loopback listeners are absent. Independent finite QEMU
  watchdogs bound lifetime even if the coordinator disappears.
- Required fmt, strict all-target/all-feature Clippy, 473 workspace tests, 34 Python
  tests, 12 focused example tests, docs/whitespace and root/fuzz audit/deny pass.
  Existing duplicate/license-exception warnings remain explicit in ignored logs.

Raw inputs, successful/failed reports, samples, identities, merged bins, checks and
teardown are under ignored target/review/sprint-07/lab/. Earlier collector evidence
includes actual CLI ownership/framing failures and 70000 seeded parser mutations;
those are not coverage-guided fuzzing or independent security audit evidence.

## Rework and retrospective

Collector review found permissive HTTP short-body/ambiguous framing; exact single
Content-Length completion and direct deep-parser error regressions fixed it.
Lab review caught failed-boot cleanup, output caps applied after capture, invalid
lane options and pilot/recovery windows shorter than the 500-slot weight cycle.
All were corrected; first preflight failure sent no traffic and shut both guests
down. A missing guest runtime library was installed only in the disposable VM;
its failed start was retained. Strict all-target Clippy caught a test-only iterator
lint missed by the narrower worker command; required full checks passed after fix.

Two process improvements: validate the whole record before boot, and calculate
weighted-cycle coverage before choosing a pilot/recovery duration. Both were applied
here; measure success by fewer preflight failures and complete lane evidence on
future runs. Agent cost/elapsed contribution is unknown; no speed claim follows.

## Remaining acceptance

The [operator contract](../operations/soak-lab.md) records the actual synthetic
boundary and next window prerequisites. DNS-021 still needs intended routed/VLAN
path, hardware/storage and observed operator workload. Large downstream responses,
encrypted ingress, publication/exception/schedule boundaries and the full fault
protocol were not qualified by this slice. Conservative FD-change failure and
HTTP-only collector limits remain. DNS-022 needs an actual authorized 24-hour
window; DNS-024 needs an independent reviewer. No long run, scheduler, public
release or contact with an external reviewer occurred.
