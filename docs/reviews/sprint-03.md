# Sprint 03 Review and retrospective

Closed 2026-10-15. Personal context, repository planning,
one agent under the user's request to continue Ponytail. Review: agent self-review;
no independent/human approval, commit, merge, publication or deployment is claimed.
DNS-014 accepted: 3 relative points, no carryover. Points are not a weekly velocity
or delivery-time claim.

## Outcome and evidence

DNS-014 is accepted. The
publication panel keeps validate/stage and active review/stop actions visible,
with honest generation and retained-sample scope. Native disclosures retain
validation, wildcard, passthrough and service-record guidance. Local DNS shows its
selected policy beside Add; adding selects the new page and focuses the domain.

Fresh baseline: Add starts at Y1852.06 on 390×844 and Y1040.25 on 1280×800, both
themes, empty-record fixture. The new regression fails before implementation at
bottom Y1896.06 against the 844px gate. Six focused desktop/mobile task flows pass
after correction, covering keyboard Add, guidance, draft navigation, publication,
row 26 and independent policy edits/removal. Final phone Add starts at Y772.02,
ends at Y816.02 within 844px (58.32% less document distance); desktop starts at
Y626.52 and ends at Y668.17 within 800px (39.77% less distance). Both themes match;
these are spatial measurements on the stated fixture, not runtime latency claims.
Viewport/document images and geometry JSON are in target/review/sprint-03/.

Required fmt, strict workspace/all-target/all-feature Clippy, default workspace
tests (458) and documentation links pass. Bun format/lint/build/audit pass (186
packages, no reported vulnerability). Final all-HTTP suite: 180 passed; HTTPS:
both passed. The 38 affected-flow rerun passed first. Completed zero-exit results
are recorded in checks.json and browser-checks.json; earlier failures are retained.
Eight normalized source comparisons preserve all four editor bodies, assertion
rendering, section state/navigation markup and async/draft/publication handlers.
No new dependency, Rust, API, schema, lockfile, query-path or DNS behavior change.
No DNS performance improvement or independent security acceptance is claimed;
benchmarks/parser fuzzing were not needed for this UI-only slice.

## Quality, review and rework

editors.tsx becomes four stable re-exports to policy/network/upstream/assertion
editors (111–278 lines). Workbench drops 821→504 lines; publication presentation,
assertion results and section navigation have separate ownership. Its cohesive
async/dialog boundary remains intact. API/schema stays 723 lines; semantic CSS
1936→1952 with five scoped rules. These are explicit cohesive exceptions, not
permission to add unrelated complexity. Frontend inventory: 33→41 files,
9922→10036 physical lines. Rust stays 199 files/57875 lines; LOC is descriptive.

Self-review found a scope cue missing when Add precedes the policy selector;
the header now names the selected policy, with safe wrapping. No unresolved
semantic findings. Source comparison finds no unexpected changed/new files or
missing originals; Rust, manifests, lockfiles and API/schema are unchanged.
Full browser acceptance and final four-state visual inspection are complete.

Retained rework: the first implementation reset state in an effect, rejected by
lint; replaced it with a bounded focus request. Restored one required type import
after extraction. New test locators were corrected for the existing unsaved-draft
link label and native select labeling. The first phone header wrapped Add below
the viewport (bottom Y921); corrected the header/grid without weakening acceptance.
The baseline audit had a viewport/button-height JSON field collision; corrected
and reran actual measurements, keeping the original report. T3 preview lost its
automation host; used the documented local Playwright workflow. Early suites were
interrupted to incorporate confirmed corrections, and retained as incomplete.
There were four source corrections after the first implementation: focus-effect
cleanup, the type import, phone header layout and the selected-policy cue. Test
interaction and measurement-harness corrections are recorded separately above.

No user intervention after scope start. Independent-review effectiveness, escaped
production defects and time/cost usage remain unknown. Native activation, ARM,
representative-network soak and independent security review remain external gates.

The first complete HTTP run reported 170 passed/10 failed: existing guidance
checks assumed always-open prose and focus checks assumed the old next-tab target.
They now open the intended disclosure and verify its text, or continue Tab to
the new summary. All DNS/provenance assertions and focus-return/containment checks
remain intact. An early progress update incorrectly inferred desktop success from
the log tail; corrected explicitly. Final acceptance uses command exit results,
not the most recent passing lines. Failed/incomplete logs remain available.

## Retrospective and next scope

Helpful: measure the current fixture, set a concrete task-distance gate, compare
unchanged state handlers and test actual keyboard/paging/publication behavior.
Viewport captures expose wrapping and scope cues that source counts cannot prove.

Two process actions:
1. Agent, DNS-014 (implemented): retain viewport and document screenshots plus
   geometry JSON for each theme/layout. Success: all four states meet the declared
   viewport gate and can be compared to the fresh baseline.
2. Agent, DNS-014 (implemented; reuse in DNS-008): record running/completed command
   status and exit codes in browser-checks.json before making gate claims. Success:
   all acceptance claims refer to completed zero-exit checks and retained failures;
   a passing log tail cannot stand in for the full result.

[Sprint 04](../planning/sprints/sprint-04.md) proposes DNS-008 (3 points plus one
rework reserve). It has not started; no deployment target or activation authority
is inferred. Current-sprint acceptance and closeout are complete; the release's
external prerequisites remain open. Revalidate changed source before relying on
these historical results.
