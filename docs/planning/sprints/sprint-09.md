# Sprint 09 Qualify representative reliability prerequisites

Planning window: 2026-10-19–25; dates do not schedule execution.
Status: Active preparation. Goal: close runnable security-review fixture gaps and
prepare grounded representative qualification, preserving all M2 gates.
DNS-036 executes in the remaining 2026-10-15 two-hour window; dates above are a
planning horizon, not a scheduled run or velocity estimate.
Personal context; repository planning, no Jira. Capacity is unknown until actual
target/workload/access evidence exists; reserve roughly 20% for defects/rework.

## Selected engineering slice

DNS-036 (S,1 point): seed/replay the existing pure lease parser; one isolated worker,
coordinator integration/acceptance and separate read-only review. No runtime,
network, dependency or operational inventory changes. Other missing parser corpora
remain explicit later refinement; stop at the existing hard limit.

- [x] Inspect target, refine and separately review the bounded seed spec.
- [x] Implement tiny synthetic corpus and actual-parser replay/boundary regressions.
- [x] Review source, rebuild/replay seeded ASAN and run required local checks.
- [x] Reconcile acceptance, retrospective and next readiness checkpoint.

## Bounded-run review and retrospective

2026-10-15: DNS-036 accepted within the existing two-hour session. One isolated
worker delivered ten synthetic seeds and five actual-parser regressions; coordinator
verified exact integration and a separate read-only agent reviewed design/source/
evidence. Valid/invalid semantics, full fields and exact 1-MiB/4096-line boundaries
pass. Fresh rebuilt seeded ASAN completed 51,323,664 iterations in 901 seconds,
exit 0; no finding observed. This is supplementary local coverage, not parser
safety proof or DNS-024 independent review. No runtime/dependency/UI change.

Required fmt, strict Clippy, 497 default/510 all-feature Rust tests, 42 focused
example tests, 60 Python tests, docs and root/fuzz audit/deny pass; warnings remain
in logs. MSRV, benchmark compilation, strict rustdoc, consumers and archives pass.
Raw evidence and failed helper attempts stay under target/review/sprint-09/.
Performance and UI checks were not needed for this fixture-only slice; no new
architectural decision required an ADR. Agent cost/velocity remains unknown.

Separate review of the ignored local packet helper caught an overbroad public
template refusal and incomplete descendant cleanup; both were corrected before
snapshot execution. Process experiment: DNS-037/038 owners must prove at least one
valid corpus input reaches the real API before mutation, then assert exact bounds
in deterministic tests. Measure successful branch replay, not campaign iteration
count as coverage. Those stories remain drafts for the next bounded session;
representative qualification and sprint closeout are still pending.

## DNS-037 slice (2026-10-16)

- [x] Ground spec against file.rs/crypto.rs (labeled self-review).
- [x] Add fifteen public dummy seeds and six actual-API replay/boundary tests.
- [x] Fresh seeded ASAN 56,335,827 runs/601 s, exit 0; fmt, strict Clippy,
  503 workspace tests, docs and root/fuzz audit/deny pass.
- [x] Separate read-only review accepted (after implementation); added empty-name
  and uppercase-digest checks and doc fixes. DNS-037 Done.

## DNS-038 slice (2026-10-16)

- [x] Generate a documented, deliberately public P-256 pair; pack ten seeds.
- [x] Five actual-API tests: ALPN per mode bit, error categories, 1..8 chain,
  exact 256-KiB/16-KiB/empty bounds.
- [x] Seeded ASAN 27,397,431 runs/601 s, exit 0; fmt, strict Clippy, 508
  workspace tests, docs and root/fuzz audit/deny pass.
- [x] Separate read-only review accepted (after implementation); provenance,
  empty-certificate check and stale contract fixes applied. DNS-038 Done.

All three review-brief corpus gaps (lease, identity, server TLS) are now closed.
Process note: both reviews ran after implementation rather than before Ready; they
caught only doc/claim issues this time, but run fixture reviews before coding next.

## Next refinement

DNS-037 and DNS-038 were accepted on 2026-10-16 (see slices above). No runnable
in-repository story remains in this sprint: DNS-021 preparation needs actual target
hardware, routed path and observed workload, and DNS-024 needs an identified
independent reviewer. Both are external inputs, not agent-runnable work.

## Later candidate order

| Order | Story | Readiness |
| --- | --- | --- |
| 1 | DNS-021 | Draft spec; actual intended hardware/storage/routed path and observed workload remain prerequisites |
| 2 | DNS-022 | Requires qualified DNS-021 and separately authorized actual 24–72-hour interval/actions |
| 3 | DNS-023 | Requires complete long-run evidence; DNS-032 now supplies bounded mechanical checks only |
| Parallel external gate | DNS-024 | Needs an identified independent reviewer and agreed source/access/scope |

## Preparation tasks

- [ ] Establish actual target/path/workload evidence against the [qualification spec](../../specs/DNS-021-representative-lab.md).
- [ ] Freeze target-specific budgets, current binary/source and exact qualification/fault/reversal plan.
- [ ] Review readiness; mark DNS-021 Ready only when its actual prerequisites hold.
- [ ] Run <=15-minute qualification within existing applicable or newly scoped authority; retain failures/teardown.
- [ ] Review qualification and refine long-run readiness without automatically starting DNS-022.
- [ ] At closeout record delivered/carried criteria and one measurable retrospective improvement.

Sprint 08's [review](../../reviews/sprint-08.md) records secure collection, strict
wire/file/evidence handling, production truncation repair and actual VM coverage.
No new application feature, network discovery, physical router change, independent
reviewer contact, background scheduler or long-run activation follows from this plan.
