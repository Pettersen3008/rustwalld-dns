# Sprint 07 Qualify the representative soak lab

Status: Collector and disposable Docker lab delivered; representative acceptance
remains open. Goal: qualify a named independent lab against the
[protocol](../../engineering/soak.md), using the bounded
[driver](../../operations/soak-runner.md). Personal context; repository planning,
no Jira. The [backlog](../backlog.md) owns story status/acceptance.

## Scope

| Order | Story | Points | Outcome/readiness |
| --- | --- | --- | --- |
| 1 | DNS-025 | 3 | Bounded target-local collector implemented and verified |
| 2 | DNS-026 | 3 | Authorized isolated Docker VM mechanics/recovery passed; guests off |
| 3 | DNS-021 | unselected | Needs representative routed/storage path, operator workload and target-specific budgets |

One point reserved for rework; no time/velocity promise. DNS-025 and DNS-026 split
concrete prerequisites from DNS-021. The user's separate-VM approval plus
continuation after the [two-VM proposal](../../operations/soak-lab.md) authorized
the bounded exercise. This authority was reused; no additional approval round was
needed. Representative acceptance remains separate.

## Delivered tasks

- [x] Ground/review and implement collector/tests in an isolated agent worktree.
- [x] Verify actual PID/API samples, atomic driver handoff and collection failures.
- [x] Ground/review the exact owned VM/client/storage/network/teardown boundary.
- [x] Extend the existing Hickory fixture with private binding and fixed oracles.
- [x] Freeze actual artifacts/config/clock/source/plan identities, distinct seeds,
      20/100 QPS UDP80/TCP20 workload and pilot-derived numeric budgets.
- [x] Run the 500-query pilot, 3400-query steady/burst qualification, expected wrong-
      answer/sample-loss/SIGINT failures, backup/restore and 500 correct queries after a cold-cache restart.
- [x] Reconcile after-drain counters and merged bins; separately review evidence.
- [x] Stop owned services, retain restart disabled, power off both guests and verify
      owned PID/listener absence. Preserve failed attempts under ignored target/.
- [x] Run required local checks, update contracts and prepare the long-window boundary.

[Review](../../reviews/sprint-07.md) records outcomes, rework and limitations.
The synthetic qualification is complete; the sprint's representative goal is not.
DNS-021 stays Backlog until intended path/hardware/storage and observed workload
are established. No later sprint or long run starts automatically.

## Remaining gates

- [ ] Identify the operator's representative routed/VLAN client path, hardware/
      storage and observed nominal/burst workload; freeze that target's budgets.
- [ ] Qualify remaining representative protocol/fault coverage under an exact plan.
- [ ] Freeze DNS-022's actual 24-hour start/end, stop owner and action/reversal
      authority; no automatic extension to 72 hours or persistent scheduler.

No workstation takeover, inferred router/DNS/DHCP/firewall changes, public release
or independent-reviewer contact. DNS-024 needs an identified independent reviewer.
The old native acceptance guest and unrelated router VMs were never activated or
changed by this slice.
