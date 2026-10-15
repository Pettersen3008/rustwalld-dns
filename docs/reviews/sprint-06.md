# Sprint 06 Review and retrospective

2026-10-15. Personal context; repository planning, no Jira. Codex self-review;
no independent security review. DNS-020 is Done; no carryover. Starting snapshot committed/pushed as
`3c5a362` at the user's request; this sprint's new work remains uncommitted.

## Outcome and evidence

- New example-only remote driver uses private configured UDP/TCP endpoints,
  frozen Hickory answer templates and seeded fresh names. Continuous phases
  preserve original-phase oracles for late completions. It never owns/reset/stops
  the target; collector/fault/service ownership is an explicit external boundary.
- Strict records freeze identity, real appliance limits, authority references,
  rate/deadline/latency/resource/output budgets and external checks. Bounded
  outstanding work, skipped slots and cancellations reconcile. New private output
  directories, capped windows/merged bins, freshness and reset evidence fail safely.
- All 473 workspace tests pass, including 15 remote-example regressions covering
  oracle corruption, transitions, late replies/fallback, overload/cancellation,
  empty/missing/clipped evidence, resets and caps. Required fmt, strict Clippy,
  documentation and whitespace checks pass. Both freshly built legacy rehearsal
  CLIs pass; shared histogram behavior changed only by adding serialization.
- Six actual CLI checks against a separately started loopback appliance pass:
  correct UDP/TCP traffic, continuous rate transition, deliberate wrong-answer
  rejection, invalid input before output/traffic, SIGINT cleanup and validate-only.
  Actual host/process/status/metric samples are collected; no synthetic UI counters.
  The same appliance survives the driver checks, then its owner stops it cleanly.
- A separate 61-second real-clock run passes 610 replies and two minute/partial
  windows, with the expected 600/10 offered split and actual resource samples.
  Window accounting, output permissions and clean owned-process shutdown pass.
- Fresh two-seed address-sanitizer smoke completes 2,525,767 mutations without a
  finding; current run/collector parser sources match the tested target. Root/fuzz
  audit/deny pass with retained duplicate/license-exception warnings.

Raw logs, full command exits, fixture identities, bins and source manifests remain
under ignored target/review/sprint-06/. Short local checks prove driver behavior,
not capacity, authenticated remote collection or representative performance. No
production DNS/API/schema/UI behavior changed; no VM/browser/package rerun needed.
Previous disposable VM stays off. No public DNS, system service, fault action,
scheduler, release or delegated agent/reviewer was activated.

## Review, rework and limits

Self-review resolved missing seeded fresh-name continuation/actual appliance limits,
intermediate phase-drain pauses, explicit cross-window accounting and a real
maximum-duration arithmetic overflow. The last has a before-test panic and passing
72-hour/100000-QPS boundary regression using a wider intermediate; no long run was
needed. Required gates and CLI checks were rerun after the correction.

The cap fixture initially did not reach its declared limit; a real sixteen-counter
envelope now exercises that failure. Initial acceptance-controller mistakes (token
environment name, empty proc-status fields and Python variable scope) are preserved
as failed diagnostics, with corrected complete runs used for acceptance. No product
assertion was weakened. One rework reserve used; three relative story points,
not a measured delivery rate. Cost/time budget usage remains unknown.

New driver/helper modules remain below 500 lines; the cohesive local test fixture
is an explicit roughly 640-line test-only exception. No new library version or
production dependency: fuzz directly declares the existing locked Serde version.
[ADR 0005](../decisions/0005-soak-controller-boundary.md) captures ownership.
No unresolved code finding. Real sampler transport, representative topology/load,
full fault/recovery window, ARM/older binaries and independent security remain open.
The Sprint 05 security packet must include this new diff before actual review.

## Retrospective and next scope

Finite input/output bounds need arithmetic and real-clock boundary tests as well
as invalid-input fixtures. Two measurable follow-ups:

1. DNS-021: qualify actual collector identity/clock, routed/storage path and stop/
   reversal before traffic. Success requires a real manifest and wrong-answer stop.
2. DNS-022/023: review every phase boundary and collection limit using recorded
   offered/inflight/outcome counts; no silent gaps or averaged quantiles.

[Sprint 07](../planning/sprints/sprint-07.md) proposes DNS-021. It is not Ready:
named representative lab/workload, numeric budgets and setup authority are missing.
Do not infer them from the previous native VM or begin a long run from this closeout.
