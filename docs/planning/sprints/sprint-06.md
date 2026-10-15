# Sprint 06 Build bounded remote soak support

Status: Proposed; not started. Goal: turn the accepted soak protocol into a
bounded, locally verified remote-appliance driver before selecting/activating a
representative lab. Personal context; repository planning, no Jira.

## Proposed scope

| Order | Story | Points | Readiness and purpose |
| --- | --- | --- | --- |
| 1 | DNS-020 | 3 | Ground/review a short implementation spec, then deliver a bounded driver and recorder with local fault/cleanup acceptance |

Reserve one point for rework. Relative size is not a time/velocity promise.
[Backlog](../backlog.md) owns acceptance/status; [protocol](../../engineering/soak.md)
defines the requirements. DNS-018/019/010 are complete; DNS-020 needs its concrete
design before Ready.

## Proposed tasks

- [ ] Inspect reuse boundaries in existing examples/helpers and define a narrow
      remote driver/run-record interface, oracle, ownership and limits.
- [ ] Implement input validation, bounded rate/concurrency, late-reply handling,
      accounting and windowed histogram/resource output without resetting the target.
- [ ] Exercise private local mocks, independent endpoint configuration, wrong-answer
      sentinel, clipped/empty/incomplete evidence, counter resets and recorder limits.
- [ ] Verify cancellation/failure cleanup and legacy local modes; self-review and
      run required checks, update protocol/backlog and review/retrospective.

## Exclusions

No representative-target selection by inference, new host/systemd/VM activation,
router/DNS/firewall/DHCP changes, long run or persistent scheduling. Local bounded
fixtures verify the implementation; DNS-021 must qualify the real lab and DNS-022
needs the actual long-window authority. DNS-024 still needs an independent reviewer.
No public release, registry upload or delegated agent work is implied.
