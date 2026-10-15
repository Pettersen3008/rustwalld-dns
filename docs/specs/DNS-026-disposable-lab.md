# DNS-026 Execute disposable Docker lab qualification

Status: Implemented. Story: DNS-026 in the [backlog](../planning/backlog.md).
Author: Codex coordinator, 2026-10-15; separate agent design review: /root/review_sprint06, 2026-10-15.
Authority: user's earlier explicit separate-VM approval and continuation after the
concrete two-VM proposal, plus current instruction to continue with agents.

## Outcome and grounding

Demonstrate the bounded remote driver and collector against the repository Docker
appliance across two new isolated VMs, then verify teardown. This qualifies
synthetic lab mechanics; DNS-021's physical representative path/workload remains
open. Existing `wire_compare` supplies Hickory fixture/oracle logic but its server
binds only loopback. Extend that example with explicit private IPv4 binding and
bounded reference export; keep existing default commands unchanged.

## Design

Use [the lab boundary](../operations/soak-lab.md): fresh Debian overlays, a separate
8 GiB appliance data disk, loopback QEMU socket link, no physical uplink/default
route, restricted loopback SSH forwards and new pinned keys. Never reuse the old
native acceptance guest or touch other VMs. Provision artifacts offline from the
host. Docker runs inside the appliance guest, with application root read-only,
UID 10001, all capabilities dropped, restart disabled, bounded memory/PIDs/logs and
guest host networking: DNS binds only 172.30.77.10:5353 and API only
127.0.0.1:8080, without port mappings. The VM is the isolation boundary. Docker
bridge/iptables/IP-forwarding are disabled; this preserves exact client source
admission and avoids installing guest NAT tooling. API remains VM-loopback HTTP.

Root owns orchestration, evidence and planning; one isolated worker owns only
`wire_compare.rs` and its focused tests. Allow only private/loopback IPv4 listener
addresses and nonzero ports. Export fixed named existing fixture responses through
Hickory, including blocked/local expected references, never accepting arbitrary
wire input or claiming that fixture correctness establishes appliance behavior.
Keep control counts loopback. No production query path or persistent schema changes.

The ignored controller records VM UUID/PID/start ticks, artifacts and runtime
identities; transfers collector output through pinned SSH with whole-command
bounds, validates complete successful JSON and atomically publishes private files.
Freeze actual configuration, seed/corpus/oracles and pilot-derived numeric budgets
before the qualification. Run steady 20 QPS and burst 100 QPS, UDP80/TCP20, maximum
32 outstanding, all public upstream access absent. Traffic phases total <=900 s.

Exercise wrong-answer rejection, cancellation and sampler loss as distinct expected
failure records; never rewrite failures as passing traffic. Back up SQLite with
its CLI, stop the owned container, restore into an absent owned destination and
recheck DNS/state. No destructive storage-full injection in this slice. Recorder
and backup stay outside the dedicated state volume. Each command has a deadline;
owned QEMU has an overall finite watchdog. On all exits stop traffic/container,
disable restart, power off both guests and verify owned PIDs/listeners are absent.
A cleanup failure prevents Done.

Rejected: run Docker on the workstation or reuse existing VMs, because isolation
and explicit ownership are part of the accepted environment. No long soak,
scheduler, router/DHCP/firewall change or independent security review is included.

## Acceptance and verification

Preserve immutable run inputs, successful and failed reports, real collector
samples, external final counter reconciliation and cleanup under ignored target/.
No performance/capacity SLO follows from this short synthetic run. Check actual
nonroot/capabilities/mounts/restart/port scope, guest routing and PID/socket identity.
Verify restored active generation and cold-cache correct UDP/TCP DNS. Review changes
with a separate agent; run focused example tests and all repository-required fmt,
Clippy, workspace tests and documentation checks. Existing UI is unaffected.

## Decisions and outcome

The guest-host-network variant passed separate design review and preserves actual
client source admission. Read-only review accepted fixture code and controller
corrections before qualification, then verified real evidence/provenance afterward.
Pilot/recovery each cover all 500 weighted slots; steady/burst passed 3400 replies.
Wrong oracle, sample loss and SIGINT produce failed records; restore preserves
generation 1 and starts with empty cache. All services/owned guests end stopped.
SIGINT had no outstanding exchanges. The 0.622 s recovery observation measures
restart-to-readiness only. Large downstream replies, generation transitions and
representative/long-window acceptance remain unverified. See the updated
[operator contract](../operations/soak-lab.md) and [review](../reviews/sprint-07.md).
