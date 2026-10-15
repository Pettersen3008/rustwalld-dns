# Sprint 08 Close executable soak coverage gaps

Planning window: 2026-10-12–18. Execution bounded by the user’s two-hour
agent-assisted run, 2026-10-15 19:16:40–21:16:40 UTC.
Status: Closed; selected engineering outcomes accepted. Goal: verified secure collection, large-reply/live-cancellation
coverage and confirmed driver defect fixes toward M2. Personal context; repository
planning, no Jira. The [backlog](../backlog.md) owns acceptance/status.
Capacity: two implementation workers plus one read-only reviewer; root integrates,
owns shared contracts and runtime acceptance. Reserve time for discovered defects
and verification; points are complexity estimates, not completion promises.

## Selected stories

| Order | Story | Points | Reason |
| --- | --- | --- | --- |
| 0 | DNS-031 | 1 | Actual appliance truncated replies retain uncommitted wire bytes |
| 1 | DNS-029 | 1 | Reproduced CD request flag loss makes accepted records fail |
| 2 | DNS-030 | 1 | Reproduced trailing-wire false acceptance weakens the frozen oracle |
| 3 | DNS-027 | 3 | Production HTTPS API cannot use the existing HTTP-only collector |
| 4 | DNS-028 | 3 | Existing truncation/SIGINT evidence misses downstream fallback and live cancellation |
| 5 | DNS-032 | 3 | Extract mechanical saved-evidence analysis while representative gates remain external |
| Spike | DNS-033 | 1 | Ground the native file-admission boundary and dependency choice |
| 6 | DNS-034 | 1 | DNS-033 identified the native regular-file admission replacement gap |
| 7 | DNS-035 | 1 | Rejected phase-entry sampling leaves contradictory failure metadata |

Specs are reviewed before implementation. Record new bugs/spikes only when grounded
in observed behavior or a concrete unresolved risk. Stop new implementation early
enough to review/verify; carry incomplete criteria honestly at the hard limit.

## Tasks

- [x] Recover state, establish goal/time limit, inspect contracts and delegate exploration.
- [x] Review specs and reproduce the CD defect with a focused regression.
- [x] DNS-029: preserve uniform lane CD in fresh requests; verify both transports/fallback.
- [x] DNS-031: fix committed encoder prefix; reverify actual large-reply acceptance.
- [x] DNS-030: enforce complete Hickory wire decoding and the strict tool header profile.
- [x] DNS-027: implement verified HTTPS with explicit bounded trust, real TLS failures and no environment side effects.
- [x] DNS-028: extend Hickory fixture/oracle; prove actual downstream fallback and SIGINT with pending work.
- [x] Separately review diffs; integrate one worker at a time and run actual CLI acceptance.
- [x] DNS-035: retain correct phase/interval and old outcome origins after sample rejection.
- [x] DNS-034: harden run/sample leaf opening; verify bounded refusal and atomic handoff.
- [x] DNS-032: reconcile bounded native reports offline; preserve acceptance/provenance limits.
- [x] Run required checks; reconcile backlog/specs/contracts/changelog and retrospective.
- [x] Record next executable scope and checkpoint at or before the two-hour deadline.

## Carried external gates

Sprint 07 delivered DNS-025/026 and closes with DNS-021's representative goal unmet.
DNS-021 still requires intended routed/VLAN client path, hardware/storage and
observed workload. User delegated profile choice: Docker VM plus independent isolated routed test
client, initially synthetic 20/100 QPS UDP80/TCP20. Current actual lab is private L2;
representative rates/hardware/path remain unmeasured.
DNS-022's 24-hour interval cannot fit this run. No long-run/scheduler, physical
network changes, unavailable hardware evidence or independent-reviewer contact is
inferred. Existing bounded separate-VM authority persists for owned acceptance.

## Closeout

All selected stories and the grounded DNS-033 spike are Done; the
[review/retrospective](../../reviews/sprint-08.md) distinguishes tool/fixture
coverage from remaining M2 acceptance. [Sprint 09](sprint-09.md) carries the next
readiness plan; execution still depends on each story's actual prerequisites.
