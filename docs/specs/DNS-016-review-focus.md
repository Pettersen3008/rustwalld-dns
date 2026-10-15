# DNS-016 Focus return after asynchronous policy review

Status: Implemented and accepted in Sprint 02.
Author/reviewer: sprint agent, self-reviewed against current code on 2026-10-15.
Authority: user's 2026-10-15 request to continue implementation and planning.
Story: [DNS-016](../planning/backlog.md).

## Problem and grounding

Review promotion fetches the candidate while its button is busy/disabled.
The generic Modal captures document.activeElement in an effect after opening.
Native reproduction twice showed BODY after Escape and a 300ms settle; the next
Tab focused Skip to content. The query-details focus regression already passes,
so a general claim that every dialog is broken would be incorrect.

Affected code: web/src/features/policies/workbench.tsx asynchronous review handler
and review buttons; web/src/components/common.tsx Modal origin/fallback logic;
existing console/design browser tests. The likely defect is origin capture after
the triggering control loses focus, to confirm before changing the implementation.

## Proposed boundary

Capture the initiating HTMLElement before setting busy or awaiting the API. Pass
that explicit origin to the controlled Modal, using a narrow optional parameter
or equivalent local ownership. Existing synchronous callers retain their behavior.
On close, restore only a connected, enabled, non-inert target; fall back to main
content if successful promotion/stop removed it. Do not focus BODY or a removed
button. Avoid global DOM selectors, timers as a fix, or a replacement dialog system.

Alternative: move the generic capture effect earlier. That cannot reliably recover
a trigger already blurred during asynchronous work, so it does not address the
observed sequence. Keep Radix containment and escape behavior.

## Acceptance and verification

Test real-daemon validate → stage → review → Escape/Cancel/Close after an actual
candidate fetch. After settling, focus returns to the initiating button and Tab
continues from it. Test successful publication/stop when the trigger disappears,
loading/error paths, both themes and desktop/phone layouts. Preserve query-details
focus and keyboard section navigation; no credentials or policy/DNS semantics change.

Run Bun format/lint/build, affected console/design/auth flows and inspect screenshots.
Run required workspace checks for the final meaningful change. No hot-path work,
new runtime dependency, configuration, schema or benchmark improvement is proposed.

## Outcome

The new real-daemon regression failed before the fix at focus return after Escape.
Workbench now captures each initiating button before setting busy/awaiting fetch;
Modal accepts an optional explicit origin and falls back when focus cannot land.
Synchronous callers retain capture behavior. Review covers dismissal, containment,
request/publication errors and successful removal. Evidence and final acceptance
are recorded in the Sprint 02 review; raw artifacts are in target/review/sprint-02/.
