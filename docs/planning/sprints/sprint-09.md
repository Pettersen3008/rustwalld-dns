# Sprint 09 Qualify representative reliability prerequisites

Planning window: 2026-10-19–25; dates do not schedule execution.
Status: Proposed; no Ready execution story yet. Goal: turn the selected reference
profile into grounded representative qualification, preserving all M2 gates.
Personal context; repository planning, no Jira. Capacity is unknown until actual
target/workload/access evidence exists; reserve roughly 20% for defects/rework.

## Candidate order

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
