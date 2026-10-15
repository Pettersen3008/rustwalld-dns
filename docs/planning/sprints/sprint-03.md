# Sprint 03 Reach the policy task

Status: Closed; executed on 2026-10-15 at the user's request. Personal context, repository
planning, one agent. Goal: make the selected policy task easier to reach on a phone while
preserving draft ownership, review safeguards and semantic guidance.

## Selected scope

| Order | Story | Points | Readiness and purpose |
| --- | --- | --- | --- |
| 1 | DNS-014 | 3 | Grounded spec; measured phone task access and editor ownership |

Reserve one point for verification/rework. This is a focused proposal, not a
velocity forecast. [Backlog](../backlog.md) remains authoritative.

## Tasks

- [x] Reproduce the 390px-class empty-record task distance in both themes and
      inspect current editor/workbench/API ownership; retain viewport evidence.
- [x] Define a short spec with measurable task access, accessible guidance,
      desktop/mobile states and justified module boundaries. Review before Ready.
- [x] Implement a bounded slice preserving session/draft state, validation,
      shadow review, stale preconditions and existing public contracts.
- [x] Exercise real-daemon task/navigation/keyboard/error flows and visual
      acceptance; run required local gates and review the actual diff.
- [x] Reconcile story/contracts/metrics, record review and retrospective, then
      evaluate the next priority without silently starting it.

Accepted DNS-014, 3 relative points; no carryover. Rework is recorded in the
[review and retrospective](../../reviews/sprint-03.md), not counted as extra scope.
[Sprint 04](sprint-04.md) proposes DNS-008 and has not started. External host,
hardware, representative soak and independent security gates remain open.

## Exclusions and later candidates

No component-framework replacement, speculative DNS feature, API/persistence
change, hosted CI, publication or host activation. DNS-008 remains the next
reliability candidate; identify the authorized deployment target before actual
host acceptance. Independent security review, ARM and representative-network soak
retain their separate prerequisites. This plan creates no background work.
