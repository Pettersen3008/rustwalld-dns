# Sprint 04 Review and retrospective

2026-10-15. Goal: prepare native appliance acceptance, then execute the prepared
run after the user authorized a separate disposable VM. Personal context,
repository planning, no Jira. Review: Codex self-review; no independent review
claim. Base `3db92b7` was committed/pushed at the earlier user request. This sprint's
subsequent source changes remain uncommitted. Sprint closed; DNS-008 Done,
three relative points delivered, no carryover. One point reserved for rework used.

## Outcomes and evidence

- Fresh native x86_64 Debian 13.7/KVM guest: kernel 6.12.111, systemd 257.13,
  GLIBC 2.41; two vCPUs, 1536 MiB RAM, 8 GiB sparse disk. Official cloud-image
  checksum verified. Static networking without a default route and restricted
  QEMU user networking; only loopback SSH forwarded. Workstation services,
  DNS/firewall/DHCP and other running VMs were unchanged.
- Seven actual systemd starts passed the shared package fixture: non-root
  installed executable/console, ownership/access, UDP/TCP, authenticated local
  DoT/DoH mocks, source/provenance semantics, active 5/shadow 6 durability,
  schema migration, online WAL backup, upgrade, stopped-process release reversal,
  restore and promotion to 7. Upgrade/reversal uses the same binary in distinct
  bundles; older-binary schema/content compatibility remains unverified.
- Effective unit probe and MainPID observations passed: non-root UID/GID,
  empty effective/bounding capabilities, NoNewPrivileges, seccomp, read-only
  config/release/system mounts, writable state, PrivateTmp/ProtectHome/device
  isolation, denied secret reads/protected writes and unlisted socket family.
  Kernel-related unit settings were recorded; this is evidence for this guest,
  not every protection on every platform or an independent security audit.
- Non-VM and unprivileged invocations were refused. Repeating against the installed
  guest was refused without changing config, credentials or database. An injected
  exception immediately after successful startup left the unit inactive/disabled,
  verified before any controller stop action.
- Final clean native run passed; probe drop-in removed, unit inactive/disabled,
  application listeners absent. Reports collected, guest powered off and SSH
  forwarding closed. No continuous service or scheduler remains.
- Full current-source package build, default isolated Docker smoke and 16 Python
  orchestration tests pass. Required fmt, strict all-target/all-feature Clippy,
  workspace tests 458, documentation links and whitespace checks pass. Binary,
  console and bundled documentation hashes match the manifest.

Raw evidence: target/review/sprint-04/ and its native-vm/ directory. Native trial 05
and accepted-native-05/ contain the accepted run, properties/probe/journal;
trial 04 records intentional post-start failure and independently checked cleanup.
Identity, source/archive hashes, negative runs and shutdown results stay there.
No DNS performance, UI behavior, parser or dependency change; benchmarks/browser/
fuzz checks were not rerun. Representative 24–72-hour soak, ARM, other deployment
hosts, actual older-binary downgrade and independent security review remain open.

## Quality and rework

The 853-line existing smoke owns shared DNS/recovery assertions. New 113-line
native_service.py owns service-manager lifecycle/guard/cleanup; native_probe.py
is 61 lines. This cohesive test orchestration is the existing large-fixture
exception; no new large module, application API, schema, dependency or unit
protection change. Self-review found no unresolved source defects.

Retained failures: a final package run exposed three old assertions requiring
positive TTLs, contradicting the documented sub-second schedule boundary.
A controlled real-minute reproduction failed with exact expected RRset/TTL 0;
the corrected boundary run and deterministic core regression passed, retaining
all record and source TTL upper bounds. The first native run's installer import
created bytecode inside a writable bundle; manifest validation correctly refused
it before installation. Disabled bytecode writes in the harness; clean native
runs then passed. An initial standalone policy check used an absent installed
web path; workspace-path adaptation passed. None required production changes.

One failure-cleanup controller initially stopped the unit before observing state;
its result was diagnostic only. The corrected injected-failure test observed
inactive/disabled/MainPID 0 before external cleanup. Teardown uses listener checks
rather than immediate TCP rebind, which can fail after connection teardown.
User intervention: clarified deployment options, then authorized a separate VM.
Elapsed cost, independent-review effectiveness and production escapes are unknown.

## Retrospective and next scope

Reusing shared real DNS/recovery assertions with a small service adapter exposed
native harness assumptions without changing the product. Fresh prepared-disk
overlays preserved failed trials and made retries independent. Completed command
exit statuses prevented failed/incomplete evidence being accepted.

One process action, agent/DNS-018: define workload, failure/stop criteria and the
representative target before launching a long soak. Success: the next protocol
separates fixture results, native target evidence and representative-network
acceptance, and has bounded setup/measurement/analysis stories.

[Sprint 05](../planning/sprints/sprint-05.md) proposes DNS-018 soak protocol and
DNS-010 security-review preparation. It has not started. Native acceptance here
closes the authorized sprint; it starts no further VM, long run, reviewer task,
background automation or release.
