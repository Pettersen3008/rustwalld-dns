# Sprint 07 Qualify the representative soak lab

Status: Preparation delivered; actual lab qualification remains unready. Goal: qualify a named independent lab against the
[protocol](../../engineering/soak.md), using the bounded
[driver](../../operations/soak-runner.md). Personal context; repository planning,
no Jira. DNS-020 supplies the implementation prerequisite, not target authority.

## Scope

| Order | Story | Points | Readiness |
| --- | --- | --- | --- |
| 1 | DNS-025 | 3 | Ground/review and implement the bounded target-local collector prerequisite |
| 2 | DNS-021 | unselected | Needs named target/clients, representative routed/storage path, workload basis, numeric budgets and authority for actual setup/actions |

Reserve one point for qualification rework. No time/velocity promise. The
[backlog](../backlog.md) owns acceptance/status. DNS-025 is split from qualification
preparation; DNS-021 cannot execute from a recommended topology alone.
[Concrete disposable-lab proposal](../../operations/soak-lab.md) names the VM/
container/client/storage/teardown boundary and synthetic starting rates. It is
preparation, not an activation or representative acceptance record.

## Collector tasks

- [x] Inspect scratch sampling, driver schema and trust/collection limits with agents.
- [x] Review the short design, then implement collector/tests in an isolated worktree.
- [x] Integrate and verify real one-shot samples/atomic driver handoff and failures.
- [x] Review with a separate agent, run required checks and reconcile qualification gaps.

DNS-025 is Done; the sprint's qualification goal is not complete. Only preparation
was executable. [Review/handoff](../../reviews/sprint-07.md) records separate-agent
review, 34 Python/473 Rust tests, actual sample-to-driver checks and current limits.
DNS-021 stays Backlog pending the named plan's authority, workload and budgets;
no later sprint or long run starts automatically.

## Tasks after prerequisites

- [ ] Ground the named target/client/storage/network inventory and prepare the
      concrete collector transport, private fixtures, faults, backups and reversal.
- [ ] Freeze real source/binary/config/dataset/controller identity, workload seed/
      mix, numeric limits, oracles/generation transitions and stop owner/window.
- [ ] Validate the record and actual collector before traffic; prove resource and
      generation identity without invented counters or unauthenticated provenance.
- [ ] Execute at most 15 minutes within the specific setup authority, including
      a deliberate wrong-answer failure, cancellation and verified recovery.
- [ ] Review complete/failed evidence and record qualification disposition; prepare
      DNS-022's concrete authorized window proposal without starting it.

## Boundaries

Previous disposable-VM native acceptance does not establish representative client
paths or authorize a long run. No workstation takeover, inferred router/DNS/DHCP/
firewall changes, persistent scheduler, public release or independent reviewer
contact. DNS-022 needs separate actual 24–72-hour authority; DNS-024 needs an
identified independent reviewer. Missing prerequisites leave qualification open.
