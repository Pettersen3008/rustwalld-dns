# DNS-014 Reach the selected policy task

Status: Implemented and accepted in Sprint 03. Grounded and self-reviewed by sprint
agent before implementation on 2026-10-15.
Authority: user's request to continue Ponytail, executing Sprint 03 in personal
context with repository planning. Story: [DNS-014](../planning/backlog.md).

## Outcome and grounding

Current real-daemon 390px empty-record fixture puts Add DNS record around Y1852,
below two publication cards, policy selectors and extended reference prose. The
old audit's Y1921 was historical, not the acceptance baseline. Both themes have
the same geometry and no document overflow. Operators should reach their selected
task within one phone viewport without losing validation or review safeguards.

Workbench owns async validation, immutable draft edits, shadow versions, preconditions
and review origins. Its 821 lines mix those handlers with publication/status and
assertion presentation and section navigation. editors.tsx (845) contains four
independent exported editors. Local DNS is 308 lines; API schemas/types (723) and
semantic CSS (1936) are cohesive existing exceptions, not a reason for mechanical
splits. Relevant contracts: [design](../engineering/design.md),
[console ownership](../../web/README.md), [local DNS](../architecture/local-dns.md).

## Design

- Keep publication controls before the editor, with unchanged handlers and unique
  button labels. Replace the two tall cards with one compact publication panel;
  validate/stage and active shadow review/stop stay visible. Keep honest generation,
  counts/sample scope, busy/read-only/conflict/error feedback. Put explanatory
  validation/shadow prose in a native disclosure, preserving all semantic guidance.
- Move Add DNS record into the selected policy panel's header. Keep the policy
  selector, blocked-reply setting, record paging and conditional routes. A native
  disclosure holds extended record/wildcard guidance; the filtering-override warning
  remains visible. Keep the HTTPS/SVCB disclosure independently reachable.
- Adding a record selects its page and focuses its new domain input after React
  renders it, using a local ref/effect, with no timers or global selector. Existing
  10000-record and 25-row bounds and immutable edits remain unchanged.
- Private feature modules own publication/assertion presentation and accessible
  section tabs. Workbench retains all async/draft/session/publication state and
  dialog handlers. Split the four independent editors into files with a thin
  compatibility re-export; retain their function bodies and hook ownership.

Alternative: move all publication controls below the editor. Rejected because
operators would have to cross long editors to validate and their feedback could
become detached from its initiating action. Compact existing controls and expose
reference guidance on demand without a new navigation or component framework.

No DNS work, telemetry, dependency, polling, API/schema, serialized configuration,
draft ownership or persistent change. No ADR is needed for these private UI
ownership/layout choices. Retain cohesive API/CSS exceptions explicitly.

## Acceptance and verification

- On the same empty-record fixture at 390×844, both themes: Add DNS record ends
  within the first 844 document pixels and its Y position is at least 50% lower
  than the fresh baseline. Desktop 1280×800 also keeps the action within view.
  No document/dialog overflow. Retain before/after viewport and document evidence.
- Keyboard Add focuses the new record domain, including row 26 after a full page;
  policy changes, paging, type/family edits, removal and draft persistence remain
  correct. Guidance can be opened by keyboard; its semantics are retained.
- Real-daemon validate→stage→review→promote/stop, async focus return, failed/invalid
  input, stale ETag, draft navigation, read-only and revoked/disconnected states
  retain their behavior. No hidden publication action or fabricated status.
- Run all HTTP and HTTPS console flows, Bun format/lint/build/audit and visual
  inspection in both sizes/themes. Add a behavior/task-distance regression that
  fails on the original layout. Compare unchanged editor/handler bodies.
- Run required cargo fmt/strict workspace Clippy/default workspace tests and
  python3 scripts/check-docs.py. Record source metrics and preserve unrelated work.
  DNS performance benchmarks/fuzzing are unnecessary: no Rust, parser, dependency
  or query path changes; do not claim a DNS performance improvement.

## Decisions and outcome

The compact publication panel keeps actions before the editor; the Local DNS
header uses an explicit selected-policy cue and a scoped grid so Add stays beside
the title on phones. Four unchanged editor bodies, assertion rendering and all
async/draft handlers moved or remained intact per source comparison. Workbench is
504 lines; its cohesive async/dialog ownership is retained rather than split to
satisfy an arbitrary cap. Local focus synchronizes a bounded addition request with
its rendered input, without a state-reset render or timer.

The new geometry regression failed on the original layout. All six focused flows,
38 affected regressions and 180 HTTP/2 HTTPS cases pass. Phone Add moves from
Y1852.06 to Y772.02 (58.32%), ending at Y816.02 within 844px; desktop ends within
800px. All four theme/layout states were visually inspected. Existing guidance
tests now open the disclosure; the focus test verifies the new next-tab summary,
retaining original DNS/provenance and focus-return assertions.

Required Rust/Bun/docs gates and source preservation checks pass. Evidence stays
in target/review/sprint-03/; the [sprint review](../reviews/sprint-03.md) owns final
measurements, findings and rework. No DNS/API/schema/dependency or draft/session
ownership contract change.
