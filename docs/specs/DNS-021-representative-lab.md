# DNS-021 Qualify the representative lab before the long window

Status: Draft; external prerequisites remain. Story: DNS-021 in the [backlog](../planning/backlog.md).
Author: Codex coordinator, 2026-10-15; readiness review pending actual target evidence.
Authority: user delegated the reference-profile recommendation; bounded prior VM
acceptance does not authorize physical network changes or a long run.

## Outcome and grounding

The two-VM private-Ethernet lab proves mechanics, recovery, verified collection,
large replies and cancellation. It does not exercise an operator routed path or
observed household workload. Qualify those missing properties before DNS-022,
using the existing [protocol](../engineering/soak.md) and
[lab boundary](../operations/soak-lab.md), without rewriting successful synthetic
runs as representative acceptance.

Selected reference profile: dedicated Linux Docker VM, independent client across
an isolated routed test network, initially synthetic 20 steady/100 burst QPS with
UDP80/TCP20. Use the same appliance limits as a starting measurement hypothesis,
not capacity/SLO promises. Do not connect this experiment to household DNS/DHCP.

## Readiness and concrete plan

Record the actual intended deployment CPU/RAM/storage/runtime and named client/
routed path. Verify ownership, private endpoints, return routing and that the
workstation/router/DNS configuration stays unchanged. Obtain observed workload
basis (device count/rates/query/transport mix) from existing operator evidence;
when absent, keep the synthetic assumption explicit and this criterion open.
No device discovery or external scanning is needed to prepare the plan.

Freeze exact source/artifact/config/dataset/controller identities, TLS CA/SAN,
private credential handling, pinned transport, clocks and numeric limits. Name
permitted activation/fault/backup actions, reversal and stop owner in the concrete
run plan. Prior scope persists; newly required authority must identify the actual
change rather than ask again about already approved bounded separate VMs.

Within <=15 minutes, verify actual client source/path, every selected lane,
normal/burst budgets, secure resource collection, a wrong-oracle sentinel and
positive live cancellation. Keep downstream fallback distinct from upstream
retry; logical probes and wire requests must reconcile under the declared mix.
Exercise representative backup/reversal and the remaining protocol transitions/
faults with outside-volume evidence; stop immediately on a declared failure.
Every attempt receives a fresh ID/directory; retain failed attempts and teardown.

After drain, use the offline consistency checker, then independently assess source,
authority, topology, duration, fault coverage and observed workload. Verify owned
service/container/VM disposition and absence of listeners. A passing checker cannot
supply those missing facts. Write qualification findings into the existing sprint
review; create bugs for observed defects and preserve unverified criteria.

## Acceptance and remaining decisions

DNS-021 stays Backlog until actual target/path/workload and applicable action
scope support its representative criterion. If only the selected synthetic routed
reference profile is available, record a separate bounded mechanics slice; keep
DNS-021 open. No workstation takeover or physical network action is inferred.
Only after qualification can DNS-022 freeze its separately authorized >=24-hour
foreground interval and fault/reversal schedule. No scheduler is proposed.
