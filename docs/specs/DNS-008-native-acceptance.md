# DNS-008 Native acceptance preparation

Status: Implemented and verified. Story: [DNS-008](../planning/backlog.md#dns-008-prepare-native-deployment-host-acceptance--e4--m).
Author/reviewer: Codex, self-review, 2026-10-15. Authority: user's request to
commit/push existing work and continue Sprint 04; subsequent user instruction
authorizes the prepared acceptance run in a separate disposable VM.

## Outcome and grounding

Prepare a current-source native package, isolated recovery evidence and a concrete
host acceptance/reversal procedure. Do not infer that the development workstation
is the deployment target. Workstation service activation, router/DNS/firewall changes,
24–72-hour soak, ARM evidence and an independent security review are excluded.

`scripts/release.py` builds the locked executable and console before bundling.
`scripts/install.py` verifies members, installs immutable releases, preserves
configuration/secrets/state and atomically replaces `current`; it never starts a
service. `--root` skips account/service-manager operations. The existing
`packaging/smoke.py` runs the actual installed process as its service account in
a network-isolated Debian container. It validates the unit and exercises WAL
backup, schema migration, active/shadow recovery and simulated bundle upgrade.
It does not boot systemd or prove native sandbox activation. Its upgrade uses the
same executable with changed documentation, so it cannot prove binary downgrade.

## Design

Extend that existing fixture, rather than add a second privileged harness:

- Assert installed ownership/modes and actual service-user access: read config,
  write state, execute release; deny config/unit/release writes and secret reads.
- Stop the child, atomically switch `current` to the retained original release,
  check config and restart it. Verify durable active/shadow IDs, unchanged private
  files, blocked/local/forwarded UDP/TCP behavior, then switch forward and retain
  the existing restore/promote assertions. Label this same-binary reversal.
- Add a bounded operator acceptance section to the existing install guide with
  target prerequisites, exact service boundary, port/capability/storage/sandbox
  assertions, backup/recovery and reversal. Require a compatible pre-upgrade
  backup for an actual older binary; symlink reversal alone is insufficient.

No app/library/API/schema/default-listener changes. No query-path or performance
change. Reuse existing fixture timeouts; any new child process must have a timeout
and cleanup in `finally`. Logs/builds/manifest/source identity stay in ignored
`target/review/sprint-04/`; tracked planning contains only concise results.

Discovered rework: existing typed/RRset/wildcard smoke assertions require positive
TTLs, contradicting the [schedule contract](../architecture/policy.md#boundaries-and-provenance)
and deterministic core tests: the sub-second minute remainder emits zero. A real
last-second container reproduction returned the exact expected RRset with TTL 0
and failed only that assumption. Accept zero while retaining type/class/owner,
record payload/count and source TTL upper bounds. Verify the old assertion fails
and the corrected fixture passes at a real minute boundary; keep this bounded
reproduction wrapper in ignored evidence. Do not change production TTL behavior.

Rejected: activate a temporary unit on the workstation to demonstrate sandboxing.
That would cross the explicit host-service boundary and choose a target without
authority. Unit verification and process checks remain separately labeled.

## Acceptance and verification

Authorized continuation: provision a new x86_64 Debian KVM guest with systemd PID1,
an independent writable disk and loopback-only SSH. Use available portable QEMU
read-only; do not touch other VMs or install host services. Download the official
cloud image over HTTPS and verify its published SHA-512. Static guest networking
has no default route/DNS and QEMU restricts outbound traffic. Temporary keys,
seed image, guest disk, identity and serial logs belong under ignored target/.
Bound the guest to two vCPUs, 1536 MiB RAM and an 8 GiB sparse disk. Stop the app,
leave its unit disabled, then power off this guest after collecting evidence.

Reuse the existing package smoke's DNS, publication and recovery assertions with
an explicit native-systemd mode. That mode must refuse non-VMs and pre-existing
managed installations before writing. A separate small service adapter owns unit
start/stop and a temporary ExecStartPost probe; the probe runs under the actual
unit sandbox and records UID, capability/seccomp state, mount permissions,
PrivateTmp/ProtectHome isolation, state writes and address-family rejection.
Keep Docker's default direct-process mode unchanged. Offline Python HTTP/2 fixture
dependencies may be copied into the guest; no public DNS is queried. This proves
the tested Debian guest's sandbox/recovery path, not every kernel/distribution,
real older-binary compatibility or a representative-network soak.

Run a full `python3 scripts/release.py --output target/review/sprint-04/releases`,
then `python3 -m unittest discover -s scripts/tests -v` and
`scripts/deployment-smoke.sh ACTUAL_ARCHIVE`. Verify hashes against the freshly
built executable/console. Run fmt, strict workspace Clippy, workspace tests,
documentation links and whitespace checks. No DNS benchmarks or UI browser rerun:
the executable/console behavior is unchanged by this slice. Review the actual
diff and permission/reversal failure paths before acceptance.

Native evidence records the named guest, OS/architecture/GLIBC, systemd/kernel,
loopback ports, storage paths, initial absence of managed state and user authority.
The effective sandbox and full recovery checks close only the tested guest's
native criterion; representative soak and ARM hardware remain separate gates.

## Decisions and outcome

Self-reviewed against installer, release builder, unit and smoke code. Routine
fixture/runbook choices are delegated; no public or persistent contract changes.
The fixture permission/reversal checks and bounded operator proposal are implemented.
Full package build, 16 Python tests, isolated deployment smoke, fmt, strict Clippy,
458 workspace tests and documentation checks pass. Executable/console hashes match
the bundle manifest. The guide's policy example passes `--check-config` with only
the workspace console path adapted; the installed `/opt` path is absent locally.
Raw evidence: `target/review/sprint-04/`; [review](../reviews/sprint-04.md) and
[operator procedure](../operations/install.md#native-host-acceptance-proposal).
The authorized Debian 13 x86_64/KVM target passed seven real systemd starts and
the full existing DNS/publication/migration/upgrade/reversal/backup/restore flow.
Effective sandbox probes and refusal/failure-cleanup cases passed. The unit ended
inactive/disabled with its probe removed; the guest powered off. Raw native
identity, code/archive hashes, results and negative runs are under
target/review/sprint-04/native-vm/. One native-harness correction prevents Python
bytecode imports from modifying the verified bundle. No application or unit
protection was changed. Source/build gates passed after that correction.
