# Sprint 10 Exercise the routed reference profile

Window: 2026-10-16 onward; dates do not schedule execution. Status: Closed.
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

- [x] Ground the spec; separate design review BEFORE implementation (ten changes applied).
- [x] Build the current release image and driver artifacts; boot three new guests
  (one worker; interrupted once by an API spend limit and resumed with its context).
- [x] Path/admission proof, pilot, qualification, sentinel, cancellation and routed fault.
- [x] Offline verification, teardown proof and separate read-only evidence review.
- [x] DNS-040 (found in acceptance): reproduce, fix, regression and gates.
- [x] Update lab contract, security contract, backlog and changelog.

## Closeout

2026-10-16. Accepted DNS-039 and DNS-040. Carried: DNS-041 (encrypted pre-handshake
admission, which needs a public DoH contract decision) and the external DNS-021/024 gates.

Retrospective: reviewing the spec before implementation produced no stale-contract
findings, so last sprint's improvement held. The evidence review caught overclaims
in the worker's summary: TCP "dropped" and a skewed fault-timing estimate.
Improvement: the fault phase must reach an upstream-dependent lane. Size or reorder
the pre-fault phase from the weight cycle (owner: next lab story). Success: the
fault run records at least one upstream-dependent lane during the outage.
Next: DNS-041 is the highest-priority runnable story.
