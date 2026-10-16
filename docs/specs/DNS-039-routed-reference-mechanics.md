# DNS-039 Exercise routed reference-profile mechanics

Status: Implemented. Story: DNS-039 in the [backlog](../planning/backlog.md).
Author: Claude coordinator, 2026-10-16; self-reviewed against the DNS-021 spec,
soak-lab contract and Sprint 07/08 lab tooling; separate read-only design review
2026-10-16 BEFORE implementation: ready-with-changes, all ten changes applied below.
Authority: existing bounded owned disposable-VM authority plus the user's 2026-10-16
default authorization. No physical host, router, DHCP, DNS or bridge change.

## Outcome and grounding

The [DNS-021 spec](DNS-021-representative-lab.md) permits a separate bounded
mechanics slice on the selected synthetic routed reference profile, keeping DNS-021
open. The [disposable lab](../operations/soak-lab.md) exercised only one private
L2 segment. Question: do the existing image, driver, collector and offline verifier
behave correctly when the client and upstream fixture sit behind one routed hop,
and does a routed-link outage classify as a declared failure followed by recovery?

Non-goals: representative hardware/storage/workload, physical VLAN/router, long run,
encrypted ingress, downstream fallback, backup/restore (Sprint 07 covered it on L2;
not repeated), outage-loss denominators (the driver is fail-fast), new product code.
A pass does not close DNS-021 or DNS-022.

## Design

Three NEW disposable Debian 13 KVM guests from the pinned Sprint 04 base image,
evidence under target/review/sprint-10/routed-lab/ (mode 0700):

| Guest | Lab NICs | Role |
| --- | --- | --- |
| dns-route-router | 172.30.77.1/24 (MAC 52:54:00:78:01:02), 172.30.78.1/24 (:03) | stream server for both links; nftables forward policy drop, accept only 77<->78 with per-direction counters; then runtime ip_forward=1. No NAT |
| dns-route-appliance | 172.30.77.10/24, route 78/24 via .77.1 | current release image in guest Docker, host network, restart disabled; binds 172.30.77.10:5353; admits 172.30.78.20/32; upstream 172.30.78.20:1053 |
| dns-route-client | 172.30.78.20/24, route 77/24 via .78.1 | remote_soak driver, bind 172.30.78.20; wire_compare serve on 172.30.78.20:1053 |

Links: `-netdev stream,server=on,addr.type=unix,addr.path=<lab>/links/{a,b}.net`
on the router; appliance and client connect with server=off. The router boots
first and both sockets must exist before the others start. Never use loopback TCP
link ports, `/tmp/rw-vm-*`, or the sibling rustwalld VMs (record their PIDs and start
ticks before and after as evidence that they were not touched). Management NICs use
restricted user-mode networking with loopback-only SSH forwards. If `nft` is absent
in the guest image, upload a pinned package from the host or stop; never run an
unfiltered router. Record rp_filter/forwarding on all guests. Each guest runs under
an absolute QEMU watchdog <=2700 s, never extended. In-guest RuntimeMaxSec values
stay below the remaining watchdog time.

Fixed budgets (the pilot may only confirm them; any exceedance stops for review):
latency 200 ms, deadline 400 ms, resources [65536,128,32,67108864,128,32] (RSS KiB,
FDs, threads, managed bytes, cache, inflight), outstanding 32. Sprint 07 corpus,
weights and 20 lanes. Total planned traffic across all runs <=900 s.

Rejected alternative: a namespace router inside the client VM. It shares one kernel,
so it would not show the appliance receiving traffic from a routed peer.

## Acceptance and verification

1. Path: the appliance's `ip route get 172.30.78.20` shows `via 172.30.77.1`, and `ip neigh`
   shows the router MAC with no 78/24 entry. Client `ping -t1 172.30.77.10` gets TTL
   exceeded from .78.1, and `-t2` succeeds with TTL 63. Router nft counters forward
   at least the driver's sent count. vms.json command lines show each endpoint attached
   only to the router.
2. Admission: a query from the router (172.30.77.1) and from a temporary routed
   secondary client address 172.30.78.21 (UDP and TCP, one-shot python3) is DROPPED.
   There is no reply within the deadline, and requests_total is unchanged between
   collector samples. This also shows that no masquerade occurs.
3. Pilot of 500 queries covering all 20 lanes, then qualification: 70 s steady 20 QPS
   plus 20 s burst 100 QPS, UDP80/TCP20, zero wrong/error/skip, reconciled accounting,
   fresh samples.
4. Sentinel: a wrong oracle fails with failure `wrong_answer...`. SIGINT gives
   failure==`cancelled` with sent>0. Claim in-flight cancellation only if cancelled>0.
5. Routed fault: phases pre-fault 10 s and link-fault 20 s at 20 QPS, allow_timeouts
   false. Before the fault, arm an in-guest `systemd-run --on-active` restore. At least
   2 s into link-fault, run `ip link set <client-side> down` on the router only.
   Expected: driver_passed false, failure matching
   `^(unexpected_timeout|exchange_error): lane \d+, phase link-fault$`, zero bad
   outcomes in pre-fault, accounting reconciled. After restore, recheck address,
   route, forwarding and the ping proof, wait at least 3 s for upstream cooldown, then
   run a passing follow-up with a fresh ID. Record host-monotonic and guest times in
   fault.json. The fault cuts ingress and upstream together and cannot tell them apart.
6. Verifier table: pilot, qualification and follow-up exit 0; sentinel, cancel and
   fault exit 2 with their failure strings; evidence_consistent true for all.
7. Teardown: containers, transient units and timers gone; restart disabled; all three
   guests off; link sockets, SSH forwards and owned PIDs absent; sibling VMs unchanged.

No source change is expected. A tooling defect needing a source fix becomes its own
reproduced story with regressions. There is no uplink. Secrets are generated per run
and never placed in arguments or the run record.

## Decisions and outcome

Executed 2026-10-16 on 26f5f0b (image rustwalld-dns:routed-26f5f0b) by one worker
agent; separate read-only evidence review accepted it with wording fixes, recorded here.
All seven items pass. Pilot 500/500; qualification 3400/3400 (p50 342 us, p99 920 us,
max 4.6 ms); sentinel `wrong_answer`; cancel `cancelled` with sent 40 and cancelled 0,
so no in-flight cancellation is claimed. Fault `unexpected_timeout: lane 0, phase
link-fault`, about 4.0 s into the phase with a 9.3 s outage, then a 500/500 follow-up.
Verifier exit codes match the table, and teardown and untouched sibling VMs were verified.

Limitations and deviations:

- nftables is absent from the base image. A pinned host bundle was uploaded with
  hashes checked: Arch nftables 1:1.1.7-3, libnftnl 1.3.2-1, libmnl 1.0.5-2 and
  jansson 2.15.1-1.
- The fault reached only a locally answered lane, so no upstream traffic crossed
  the outage. Lane order is deterministic by weight.
- The router drop rule was never hit; all admission drops happened at the appliance.
- Cache peak 128 equals the configured capacity, so that budget is uninformative.
- Three earlier boot attempts failed on harness defects. The teardown of boot-02
  was not verified at that time; nothing remained afterwards.
- The admission request counter moved only for the admitted control query.
- Non-admitted TCP completed the handshake and then closed with no reply. That
  exposed slot exhaustion, which is fixed by DNS-040.

Evidence: target/review/sprint-10/routed-lab/ (review/ holds the re-run verifiers).
