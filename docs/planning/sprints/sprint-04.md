# Sprint 04 Prepare native appliance acceptance

Status: Proposed; not started. Goal: make native deployment-host acceptance
concrete and reviewable without activating host/network services from planning.
Personal context; repository planning remains canonical.

## Proposed scope

| Order | Story | Points | Readiness and purpose |
| --- | --- | --- | --- |
| 1 | DNS-008 | 3 | Refine before Ready; current package/recovery fixtures and a bounded host acceptance/reversal proposal |

Reserve one point for rework. Prior sprint points are relative size, not a weekly
velocity or time estimate. [Backlog](../backlog.md) owns status and acceptance.

## Proposed tasks

- [ ] Inspect current packaging, install/recovery guides and service boundaries;
      ground a short spec and distinguish fixture checks from native acceptance.
- [ ] Build current-source console/package inputs and exercise isolated existing
      package/recovery fixtures, retaining failures and environment limits.
- [ ] Prepare concrete prerequisites, sandbox/port/permission/storage assertions,
      backup/upgrade/recovery steps and a tested reversal proposal.
- [ ] Identify the intended target and the exact authority needed for native
      activation; present the prepared proposal before requesting new authority.
      Keep actual host tests pending until an authorized target exists.
- [ ] Review and reconcile story/evidence/contracts; prepare the next scope from
      actual results, with external prerequisites left explicit.

## Exclusions and later work

This plan authorizes no activation and selects no deployment machine by inference.
Do not change workstation DNS, firewall, DHCP or systemd services. Representative
soak, ARM validation and an actual independent security review remain distinct
gates with their own prerequisites; do not use package fixtures as substitutes.
No hosted CI, release, commit, push, publication or background scheduling.
