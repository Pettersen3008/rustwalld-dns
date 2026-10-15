# Sprint 04 Prepare native appliance acceptance

Status: Closed. Goal: make native deployment-host acceptance
concrete and reviewable without activating host/network services from planning.
Personal context; repository planning remains canonical.

## Scope

| Order | Story | Points | Readiness and purpose |
| --- | --- | --- | --- |
| 1 | DNS-008 | 3 | Self-reviewed spec; current package/recovery fixtures and a bounded host acceptance/reversal proposal; target pending |

One point reserved for rework was used to correct the documented zero-TTL minute
boundary in existing package assertions. Prior sprint points are relative size, not a weekly
velocity or time estimate. [Backlog](../backlog.md) owns status and acceptance.

## Tasks

- [x] Inspect current packaging, install/recovery guides and service boundaries;
      ground a short spec and distinguish fixture checks from native acceptance.
- [x] Build current-source console/package inputs and exercise isolated existing
      package/recovery fixtures, retaining failures and environment limits.
- [x] Prepare concrete prerequisites, sandbox/port/permission/storage assertions,
      backup/upgrade/recovery steps and a tested reversal proposal.
- [x] Identify the intended target and the exact authority needed for native
      activation; present the prepared proposal before requesting new authority.
      Keep actual host tests pending until an authorized target exists.
- [x] Run the prepared native systemd/sandbox/recovery acceptance in a new
      disposable Debian KVM guest; collect evidence and leave it stopped.
- [x] Review and reconcile story/evidence/contracts; prepare the next scope from
      actual results, with external prerequisites left explicit.

Preparation is verified; [review](../../reviews/sprint-04.md) records evidence and
limits. The user's continuation authorizes the prepared run in a separate VM.
DNS-008 is Done: the Debian 13/KVM run, negative cases and effective sandbox
checks passed. Service stopped/disabled and guest powered off. Delivered three
relative points; no carryover. [Sprint 05](sprint-05.md) is proposed, not started.

## Exclusions and later work

Activation is authorized only inside the new disposable acceptance VM.
Do not change workstation DNS, firewall, DHCP or systemd services. Representative
soak, ARM validation and an actual independent security review remain distinct
gates with their own prerequisites; do not use package fixtures as substitutes.
No hosted CI, external release publication or background scheduling. The user's
2026-10-15 request authorized committing/pushing the accumulated work before this
sprint; that snapshot is `3db92b7` on `main` and `origin/main`.
