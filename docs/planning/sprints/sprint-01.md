# Sprint 01 Trustworthy development baseline

Planning window: 2026-10-19 through 2026-10-25. Status: Closed; executed on 2026-10-15 at the maintainer’s request.
Goal: establish honest current-source acceptance and make one structural improvement
without changing DNS behavior. The reset is Sprint 00; its review records this change.

## Selected scope

| Order | Story | Points | Purpose |
| --- | --- | --- | --- |
| 1 | [DNS-004](../backlog.md#dns-004-establish-current-verification-and-performance-baseline--e1--m) | 3 | Repeatable current-source acceptance and baseline |
| 2 | [DNS-005](../backlog.md#dns-005-split-filter-public-api-and-implementation-ownership--e2--m) | 3 | Readable filter API with preserved behavior |
| 3 | [DNS-007](../backlog.md#dns-007-audit-policy-workflow-usability--e3--s) | 1 | Ground the next UI improvement in actual flows |

Plan: 7 points plus roughly 2 points reserved for regressions/rework. No measured
velocity exists yet. Backlog is the status authority. Dependencies must be Done
before a selected story starts; refine Backlog stories into Ready in that order.
If baseline defects consume capacity, defer the refactor explicitly.

## Tasks

DNS-004:
- [x] Inspect current dirty state/source identity and review the baseline spec.
- [x] Run local Rust/default/all-feature/MSRV/consumer and console acceptance.
- [x] Capture metrics, quiet matched fixtures and failure/uncertainty notes.
- [x] Review results, open actionable defect stories and update acceptance.

DNS-005:
- [x] Trace public exports, matcher/compiler ownership, tests and consumers.
- [x] Write/self-review short spec; preserve API and identify module boundaries.
- [x] Move code in behavior-preserving slices; verify scoped syntax/provenance.
- [x] Review diff, run gates/consumers and compare baseline before marking Done.

DNS-007:
- [x] Inspect policy/local DNS/migration desktop and phone flows with local data.
- [x] Check keyboard, both themes and failure/conflict/read-only states.
- [x] Record only reproducible issues and prioritize at most three follow-ups.

DNS-015 (verification rework reserve):
- [x] Diagnose the MSRV AddrInUse failure without changing production bind semantics.
- [x] Add eight-attempt, AddrInUse-only retries to the shared test fixture.
- [x] Repeat the failed case and full default/all-feature/MSRV acceptance.

## Closeout

- [x] Demo accepted outcomes and carry incomplete work with reasons.
- [x] Record before/after metrics, review identity, rework and user interventions.
- [x] Write one review/retrospective from the template; choose at most two actions.
- [x] Update backlog/roadmap and prepare Sprint 02 without starting it outside scope.

No publishing, host DNS/DHCP/firewall changes, service activation, live network soak
or new DNS features are authorized by this sprint plan alone. “Run Sprint 01” gives
execution scope for the tasks above, subject to AGENTS.md and existing authorization.

Accepted 8 points including the one-point DNS-015 fixture correction. No selected
story carried over. [Review and retrospective](../../reviews/sprint-01.md);
[Sprint 02 plan](sprint-02.md) is prepared and has not started.
