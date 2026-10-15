# Sprint 05 Prepare external validation

Status: Closed. Goal: make the remaining soak/security gates
executable without inventing a representative deployment or independent reviewer.
Personal context; repository planning, no Jira. [Backlog](../backlog.md) owns status.

## Scope

| Order | Story | Points | Readiness and purpose |
| --- | --- | --- | --- |
| 0 | DNS-019 | 1 | Confirmed stale histogram descriptions; use the rework reserve before measurement planning |
| 1 | DNS-018 | 1 | Refine the representative soak protocol and split DNS-009 before a long run |
| 2 | DNS-010 | 1 | Prepare the reviewable security scope/source packet and identify the independent-review dependency |

The one-point rework reserve covers DNS-019. Small selection reflects external prerequisites;
points are relative complexity, not a measured delivery rate or time promise.

## Tasks

- [x] Inspect the real-process resilience/soak harnesses and release contracts;
      separate measured fixtures from representative workload requirements.
- [x] Correct stale histogram metadata and verify emitted report descriptions
      against the shared helper's existing slow/clipped-reply regressions.
- [x] Define target/workload, fault/recovery matrix, measurements, duration/stop
      criteria and bounded setup/measurement/analysis stories for DNS-009.
- [x] Prepare security surfaces, current source identity/diff, invariants, known
      limitations and reproducible checks for an independent reviewer.
- [x] Self-review the prepared packets; retain target/reviewer gaps honestly,
      reconcile acceptance and plan the next authorized execution scope.

DNS-018, DNS-010 and rework DNS-019 are Done: three relative points, no carryover.
[Review](../../reviews/sprint-05.md) records current acceptance and limits.
[Sprint 06](sprint-06.md) proposes bounded remote-runner implementation; not started.

## Boundaries

Sprint 04's disposable VM remains powered off; it is not a representative router-client
network or an authorization for continuous operation. This sprint started no
24–72-hour process, scheduler, VM/service, router/DNS/DHCP/firewall change or
independent review. The user-requested starting snapshot was committed/pushed as
727cb87; subsequent Sprint 05 work remains uncommitted. No reviewer or agents were delegated.
Actual soak/hardware testing and independent review require their real prerequisites.
