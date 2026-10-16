# Sprint 10 Exercise the routed reference profile

Window: 2026-10-16 onward; dates do not schedule execution. Status: Active.
Goal: show that the existing appliance pipeline survives a routed client/upstream
path on disposable VMs, without claiming representative qualification.
Capacity: unknown agent cost; one M story plus ~20% rework reserve. Personal
context; repository planning, no Jira.

## Selected stories

DNS-039 ([spec](../../specs/DNS-039-routed-reference-mechanics.md)) is the
highest-priority story an agent can run. DNS-021/022/024 still need external
facts (target hardware/path/workload, independent reviewer), per the
[Sprint 09 review](../../reviews/sprint-09.md). DNS-013's alias-graph validation
was considered but deferred: today's no-chase design is documented, and rejecting
loops could break stored configurations, which is a persistent-contract decision.

## Tasks

- [ ] Ground and self-review the spec; mark Ready.
- [ ] Build the current release image and driver artifacts; boot three new guests.
- [ ] Path/admission proof, pilot, qualification, sentinel, cancellation and routed fault.
- [ ] Offline verification, teardown proof and separate read-only evidence review.
- [ ] Update lab contract, backlog, review/retrospective.

## Closeout

Pending.
