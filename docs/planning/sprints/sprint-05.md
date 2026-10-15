# Sprint 05 Prepare external validation

Status: Proposed; not started. Goal: make the remaining soak/security gates
executable without inventing a representative deployment or independent reviewer.
Personal context; repository planning, no Jira. [Backlog](../backlog.md) owns status.

## Proposed scope

| Order | Story | Points | Readiness and purpose |
| --- | --- | --- | --- |
| 1 | DNS-018 | 1 | Refine the representative soak protocol and split DNS-009 before a long run |
| 2 | DNS-010 | 1 | Prepare the reviewable security scope/source packet and identify the independent-review dependency |

Reserve one point for rework. Small selection reflects external prerequisites;
points are relative complexity, not a measured delivery rate or time promise.

## Proposed tasks

- [ ] Inspect the real-process resilience/soak harnesses and release contracts;
      separate measured fixtures from representative workload requirements.
- [ ] Define target/workload, fault/recovery matrix, measurements, duration/stop
      criteria and bounded setup/measurement/analysis stories for DNS-009.
- [ ] Prepare security surfaces, current source identity/diff, invariants, known
      limitations and reproducible checks for an independent reviewer.
- [ ] Self-review the prepared packets; retain target/reviewer gaps honestly,
      reconcile acceptance and plan the next authorized execution scope.

## Boundaries

Sprint 04's disposable VM was powered off; it is not a representative router-client
network or an authorization for continuous operation. This proposal starts no
24–72-hour process, scheduler, VM/service, router/DNS/DHCP/firewall change or
independent review. No publication, commit/push or delegated agents are inferred.
Actual soak/hardware testing and independent review require their real prerequisites.
