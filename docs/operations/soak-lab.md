# Disposable lab qualification proposal

Proposed DNS-021 environment, not activated or accepted as representative.
User asked for a recommendation; the proposed two-VM topology follows the existing
separate-VM preference. DNS-025 prepares collection first. See the
[protocol](../engineering/soak.md), [driver](soak-runner.md) and
[container contract](container.md). Actual activation needs the named plan's authority
under [AGENTS.md](../../AGENTS.md); the earlier native acceptance VM remains off.

## Concrete proposed boundary

| Resource | Proposed ownership and isolation |
| --- | --- |
| `dns-soak-appliance` | New disposable Debian 13 x86_64 VM, 2 vCPU/2 GiB RAM; locally verified repository Docker image, immutable config/token mount, non-root UID 10001, capability-free/read-only root, restart disabled |
| Appliance storage | Separate disposable 8 GiB guest data disk; named state directory and backups on separately scoped paths; evidence outside any fault volume |
| `dns-soak-client` | New disposable Debian 13 x86_64 VM, 2 vCPU/1 GiB RAM; bounded driver and controlled private UDP/TCP upstream/publisher fixtures |
| Lab path | Dedicated VM-to-VM private Ethernet, no physical-LAN uplink/default route; proposed guest addresses 172.30.77.10/24 and .20/24, checked for conflicts before use |
| Host boundary | Prefer available QEMU with a loopback-only socket network backend; no new host bridge, router/DHCP/firewall/DNS change or existing-VM reuse |
| Management | Private temporary SSH keys/pinned host keys, loopback-only host forwards; fixed timeout for every command and teardown owned resources only |
| DNS exposure | Container UDP/TCP 5353 published only on the appliance's lab interface; explicit client admission and private fixture upstreams, no public DNS |

Use current artifact/kernel/runtime/image identities in the manifest; the proposal
does not assume a guest's existing installation or public image tag is current.
Do not use the general Compose file's automatic restart or physical-LAN mappings
unchanged for this disposable experiment. Keep keys, guest images, manifests and
all raw output under ignored target/review/sprint-07/lab/ if this plan is authorized.

The release image contains no Python collector. Keep that image unchanged:
collection runs from the appliance VM's Python environment, entering **only the
target container's network namespace** with the trusted lab controller. Use its
actual host-visible PID/start ticks and VM-visible bind-mounted state directory.
This lets the collector verify the target-owned loopback API without adding Python
or tools to the application image. PID/network rebinding after restart is explicit.

Initial collector coverage is numeric loopback **HTTP**, so the synthetic fixture
uses token mode with HTTP confined to the container loopback and unpublished.
Production HTTPS/password/encrypted-ingress coverage remains separate and cannot
be claimed from that fixture. No secret belongs in command arguments or run.json.

## Bounded first exercise

Proposed **synthetic** offered load is 20 QPS steady, then 100 QPS burst, 80% UDP/
20% TCP, with maximum 32 outstanding attempts. Start with a small private `.test`
corpus containing known block/allow/local/forwarded/negative/large replies. Freeze
numeric deadlines, latency, RSS/FD/thread/storage/cache/inflight/output budgets
after a bounded pilot, before qualification. Configuration defaults are not measured
capacity or representative workload evidence.

Prepare and independently review the exact versioned run record, source/image/
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

## Remaining acceptance

This topology can qualify lab mechanics and container recovery. It does not prove
the operator's physical routed/VLAN path, intended hardware/storage, client stacks
or observed workload. DNS-021's representative criterion remains open until those
are named and checked. DNS-022 still needs an actual authorized 24–72-hour window;
no persistent scheduler or automatic extension is proposed here.
