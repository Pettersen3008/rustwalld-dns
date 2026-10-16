# Disposable lab qualification

DNS-026 exercised this synthetic environment on 2026-10-15 under the user's
separate-VM approval and continuation after the concrete proposal. Both owned
guests are now off. DNS-021 representative acceptance remains open. See the
[protocol](../engineering/soak.md), [driver](soak-runner.md) and
[container contract](container.md). [AGENTS.md](../../AGENTS.md) still governs
future activation; the earlier native acceptance VM was never reused.

## Exercised boundary

| Resource | Ownership and isolation |
| --- | --- |
| `dns-soak-appliance` | New disposable Debian 13 x86_64 VM, 2 vCPU/2 GiB RAM; locally verified repository Docker image, immutable config/token mount, non-root UID 10001, capability-free/read-only root, restart disabled |
| Appliance storage | Separate disposable 8 GiB guest data disk; named state directory and backups on separately scoped paths; evidence outside any fault volume |
| `dns-soak-client` | New disposable Debian 13 x86_64 VM, 2 vCPU/1 GiB RAM; bounded driver and controlled private UDP/TCP upstream fixtures |
| Lab path | Dedicated VM-to-VM private Ethernet, no physical-LAN uplink/default route; guest addresses 172.30.77.10/24 and .20/24, checked for conflicts before use |
| Host boundary | QEMU with a loopback-only socket network backend; no new host bridge, router/DHCP/firewall/DNS change or existing-VM reuse |
| Management | Private temporary SSH keys/pinned host keys, loopback-only host forwards; fixed timeout for every command and teardown owned resources only |
| DNS exposure | Guest host networking inside the appliance VM, no port mappings; DNS binds only 172.30.77.10:5353 and admits only 172.30.77.20/32; private fixtures, no public DNS |

Use actual artifact/kernel/runtime/image identities in the manifest; the exercise
does not assume a guest's existing installation or public image tag is current.
Do not use the general Compose file's automatic restart or physical-LAN mappings
unchanged for this disposable experiment. Keep keys, guest images, manifests and
all raw output under ignored target/review/sprint-07/lab/ or sprint-08/lab/.

The release image contains no Python collector. Keep that image unchanged:
collection runs from the appliance VM's Python environment, entering **only the
target container's network namespace** with the trusted lab controller. Use its
actual host-visible PID/start ticks and VM-visible bind-mounted state directory.
Guest host networking shares that namespace with the VM; ownership checks still
require the actual application PID/start ticks and exclusive listener. This lets
the collector verify the target-owned loopback API without adding Python
or tools to the application image. PID/network rebinding after restart is explicit.

Sprint 07 used token mode with numeric-loopback HTTP. Sprint 08 separately
verified the HTTPS collector against a password-mode appliance, with explicit CA/
SAN identity and wrong-name/PID/environment failure checks. The API remains confined
to guest loopback. Client encrypted DNS ingress remains a separate acceptance gate.
No secret belongs in command arguments or run.json.

## Bounded exercise and result

The **synthetic** offered load is 20 QPS steady, then 100 QPS burst, 80% UDP/
20% TCP, with maximum 32 outstanding attempts. Use the fixed private `.test`
corpus exported by `wire_compare references`: block,
allow, local, A/AAAA, CNAME, fresh, NXDOMAIN/NODATA and upstream UDP truncation
with TCP recovery. That original small reply covers upstream fallback; the separate
`large.bench.test` reference and `wire_compare probe-large` cover downstream replies. `wire_compare serve --listen 172.30.77.20:1053` keeps count control on
client loopback; listener parsing rejects public/wildcard/IPv6/zero ports. Freeze
numeric deadlines, latency, RSS/FD/thread/storage/cache/inflight/output budgets
after a bounded pilot, before qualification. Configuration defaults are not measured
capacity or representative workload evidence.

Prepare and separately review the exact versioned run record, source/image/
dataset/config/controller identity, seed/oracles and transition windows. Qualification
is at most 15 minutes, foreground only: verify sampler identity/freshness, baseline,
burst, deliberately wrong expected answer (must fail), cancellation and evidence
retention. Fault injection, backup/restore and service changes require explicitly
named allowed actions and undo in that same plan; they are never inferred from
permission to run a sampler or start ordinary local fixtures.

Capture complete successful collector stdout through the pinned transport, parse
and bound it, then atomically publish the driver file. Failed/partial/late captures
must not replace a valid snapshot. Driver sampling ages out when collection stops.
Sampler transport, whole-command deadline, monotonic sequence and process/socket
identity are qualification gates, not consequences of an HTTP health check.

On any failure, stop owned traffic/faults, restore the agreed owned service state,
preserve files and power off both owned guests; never touch existing lab/router VMs.
A successful disposable run also ends with containers stopped, restart disabled
and guests off. Verify shutdown/listeners and preserve the actual disposition.

A 500-query pilot covered the complete 500-slot weighted cycle. Frozen budgets
were 200 ms reply latency, 400 ms deadline, 64 MiB RSS, 128 FDs, 32 threads,
64 MiB managed state, 128 cache entries and 32 inflight entries. These are lab
limits with headroom, not production SLOs or capacity measurements. The 90-second
steady/burst run passed 3400/3400 replies with exact UDP80/TCP20, no skips/timeouts/
wrong replies, all 20 lanes covered and merged-bin accounting reconciled.

Wrong-oracle, stopped-collector and SIGINT runs failed as intended; the SIGINT
arrived with no outstanding exchanges. Live CLI backup/verification, stopped
restore into an absent database and 500 correct queries after a cold-cache restart
preserved generation 1. Restart-to-readiness was 0.622 s; this excludes backup/
restore work. After-drain request counters exactly match each run's sent attempts.
The application and owned services stopped, restart remained disabled, and guest PIDs/
loopback listeners are absent. Separate agent review checked code and evidence.

Sprint 08 rebuilt the release image after the large-reply probe found uncommitted
bytes after a truncated message. The repaired appliance returns a complete
498-byte UDP response with TC and 29 answers, and all 64 records in 1058-byte TCP.
A separate five-second 20-QPS run passed 100 logical probes (UDP80/TCP20), with
180 actual requests because all 80 UDP probes fell back to TCP. This run covers
two large-response lanes, not the earlier complete 20-lane corpus.

A bounded frame proxy observed a complete request and the actual appliance reply
before withholding it and interrupting the driver. Live SIGINT retained one
cancellation, no reply, reconciled accounting and peer EOF; target collection after
drain retained its PID. This intentionally failed driver run is cancellation
evidence. Source/plan/deployed-artifact and image identities were checked. Both
new guests and owned services stopped, restart remained disabled and listeners
were absent. Original failing packet/image and unsuccessful attempts are retained.

## Remaining acceptance

This topology can qualify lab mechanics and container recovery. It does not prove
the operator's physical routed/VLAN path, intended hardware/storage, client stacks
or observed workload. DNS-021's representative criterion remains open until those
are named and checked. DNS-022 still needs an actual authorized 24–72-hour window;
no persistent scheduler or automatic extension is proposed here.

For DNS-022, prepare a 24-hour foreground window only after DNS-021 names the
intended routed/VLAN client path, storage/hardware and observed nominal/burst
workload. Reuse the collector, fixed budgets as a starting measurement hypothesis,
private fixtures, explicit phase/fault schedule and outside-volume recorder/backup.
Freeze the actual start/end and stop owner with separate long-window authority;
recheck limits on the representative target before using these synthetic budgets.
The selected reference profile for later qualification is a Docker Linux VM and
an independent client on an isolated routed test network, starting with synthetic
20/100-QPS UDP80/TCP20. The exercised link above is private Ethernet, not that
routed path; actual household rates/device counts remain unmeasured. No 24-hour
run or persistent scheduler has started.

## Routed reference-profile mechanics (Sprint 10)

DNS-039 repeated the mechanics across one routed hop on three new disposable guests.
A filtered router guest connects them through QEMU unix-stream links; there is no NAT
and no host bridge. Path, admission, qualification, sentinel, cancellation and a
declared routed-link fault with recovery all passed. See the
[DNS-039 spec](../specs/DNS-039-routed-reference-mechanics.md) for results and
limitations. This is still synthetic: it is not the operator's physical path,
hardware or observed workload, so DNS-021 remains open.
