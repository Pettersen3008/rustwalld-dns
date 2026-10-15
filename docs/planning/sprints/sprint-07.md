# Sprint 07 Qualify the representative soak lab

Status: Proposed; not Ready. Goal: qualify a named independent lab against the
[protocol](../../engineering/soak.md), using the bounded
[driver](../../operations/soak-runner.md). Personal context; repository planning,
no Jira. DNS-020 supplies the implementation prerequisite, not target authority.

## Proposed scope

| Order | Story | Points | Readiness |
| --- | --- | --- | --- |
| 1 | DNS-021 | 3 | Needs named target/clients, representative routed/storage path, workload basis, numeric budgets and authority for actual setup/actions |

Reserve one point for qualification rework. No time/velocity promise. The
[backlog](../backlog.md) owns acceptance/status; no other story is selected.

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
