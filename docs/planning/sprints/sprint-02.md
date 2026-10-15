# Sprint 02 Readable engine and reliable policy review

Status: Closed; executed early on 2026-10-15 at the user's request. Original
planning window: 2026-10-26 through 2026-11-01. Personal context, repository planning,
one agent; dates are planning windows, not an automatic schedule.
Goal: preserve measured DNS behavior while improving
engine ownership and the reliability of keyboard-driven policy review.

## Selected scope

| Order | Story | Points | Readiness and purpose |
| --- | --- | --- | --- |
| 1 | DNS-016 | 1 | Ready spec; fix the reproduced asynchronous review focus loss |
| 2 | DNS-006 | 3 | Refine and specify before Ready; split engine responsibilities |
| 3 | DNS-017 | 1 | Ready small copy correction; accurate V2–V6 cancellation guidance |

[Backlog](../backlog.md) owns priority/status/acceptance. Plan 5 points plus 1 point
for rework. Sprint 01 delivered 8 relative points, but one run does not establish
weekly agent velocity. Existing hardware/release gates remain separate.

## Tasks

DNS-016:
- [x] Reproduce the async-review focus loss against current source.
- [x] Confirm trigger capture/disabled-state ordering and review the short spec.
- [x] Restore valid trigger focus; keep fallback and modal containment intact.
- [x] Verify Escape/Cancel/Close, successful actions, errors and existing query focus.

DNS-006:
- [x] Trace engine admission, local/policy decisions, pending forwarding and finalization.
- [x] Define private module boundaries and review a short behavior-preserving spec.
- [x] Confirm current source/fixture identities; rebuild a baseline if anything changed.
- [x] Refactor in bounded slices, preserving API/generation/client/cache/provenance.
- [x] Run protocol/scope/expiry/schedule/cancellation, consumers and required gates;
      compare saved matching/engine/loopback fixtures and retain unfavorable runs.

DNS-017:
- [x] Replace obsolete current-import version wording in migration and validation notices.
- [x] Preserve cancellation warnings and frozen interpreter behavior.
- [x] Verify the actual imported version and affected browser flows in both themes.

## Closeout and exclusions

- [x] Record acceptance, metrics/performance and UX evidence, review identity and rework.
- [x] Update backlog/roadmap and one review/retrospective; select at most two actions.
- [x] Carry incomplete work explicitly and prepare the next sprint without auto-start.

Accepted all three stories, 5 relative points; no selected story carried over.
[Review and retrospective](../../reviews/sprint-02.md). [Sprint 03](sprint-03.md)
is proposed for DNS-014 and has not started. External release gates remain open.

DNS-014's phone task-distance concern is ranked for later refinement; it is not
bundled into this sprint's small focus/copy fixes. No new DNS features, hosted CI,
release/publication, host DNS/DHCP/firewall changes or service activation.
