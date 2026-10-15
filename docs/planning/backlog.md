# Ranked delivery backlog

Status here is authoritative. IDs are permanent. Size S=1/M=3/L=5 relative points;
L stories must split before Ready. “Ready” means the agent has grounded/reviewed the
spec when required; no blanket human spec gate. Scope follows the active request.
[Workflow](../engineering/workflow.md) defines transitions and Done.

## Epics

| Epic | Outcome | Milestone |
| --- | --- | --- |
| E1 Development foundation | Lean planning, repeatable acceptance, honest baseline | M0/M1 |
| E2 Maintainable core | Cohesive modules with stable observable contracts | M1 |
| E3 Operator experience | Clear, accessible policy and daily-use workflows | M1/M3 |
| E4 Appliance reliability | Recoverable installation, bounded failures, supported hardware | M2/M4 |
| E5 Compatibility growth | Proven source semantics and safe incremental DNS extensions | M3 |

## Reset delivered in this change

### DNS-001 Establish agent-owned delivery — E1 — S

Status: Done. Priority: 0. Dependencies: none. Sprint: 00.
Acceptance: shared AGENTS/CLAUDE entry; story/spec/task/decision/sprint/retrospective
workflow; scoped agent autonomy; local verification and maintainer merge boundaries;
current roadmap/backlog/sprint and next executable spec. Review in
[Sprint 00](../reviews/sprint-00.md). Final check outcomes belong there.

### DNS-002 Consolidate documentation and verify packaging — E1 — M

Status: Done. Priority: 0. Dependencies: DNS-001. Sprint: 00.
Acceptance: original dirty Markdown recoverable; every old docs path mapped;
current DNS/source/recovery limits retained; obsolete ledgers/measurement essays
removed; local links and bundle contents checked; source behavior preserved.
Evidence: target/docs-reset-2026-10-15/; [cleanup map](../archive.md).

### DNS-003 Add local documentation and metrics tooling — E1 — S

Status: Done. Priority: 0. Dependencies: none. Sprint: 00.
Acceptance: reusable offline link check fails for missing local files/anchors;
metrics describe source inventory without claiming semantic safety; generated
output stays under target/; focused script tests pass. Verification is recorded
in the Sprint 00 review; no new hosted workflow.

## Sprint 01 candidates in execution order

### DNS-004 Establish current verification and performance baseline — E1 — M

Status: Done. Priority: 1. Dependencies: DNS-001, DNS-002, DNS-003. Sprint: 01.
Spec: [baseline](../specs/DNS-004-baseline.md), grounded/self-reviewed 2026-10-15.
As a maintainer I need current-source evidence before extending the alpha.

Acceptance:
- Required default and all-feature Rust checks, public consumers/MSRV, console
  checks/real-daemon flows and existing script tests have dated current-tree results.
- Record source metrics and matched local block/cache/miss fixtures with hardware,
  source/binary identity, toolchain/features and correctness; retain every repeat.
- Record failures/noise and unverified hardware/soak/security gates explicitly.
  No feature, service activation or performance improvement is claimed.
- Update Sprint 01 review with actionable defects and baseline evidence; required
  unavailable checks leave this story incomplete instead of “passed historically”.

### DNS-005 Split filter public API and implementation ownership — E2 — M

Status: Done. Priority: 2. Dependencies: DNS-004. Sprint: 01.
Grounding: crates/filtering/src/lib.rs has 1058 lines in the reset inventory,
including inline tests starting at line 720. Split by ownership; do not treat
that total as 1058 lines of production logic.
Spec: [filter ownership](../specs/DNS-005-filter-ownership.md), grounded and
self-reviewed before implementation.
As a library maintainer I need a readable stable public surface.

Acceptance: grounded spec identifies ownership boundaries; split implementation
into cohesive private modules; preserve public imports/signatures, frozen V0–V6
syntax/IDs/provenance and serial/parallel equivalence; no new dependencies or hot
path machinery. No new production file exceeds 1000 lines, aim below 500. Relevant
filter/scope tests, consumer checks, workspace gates and matched matcher results
show preserved semantics and no confirmed unexplained regression.
Accepted: root 1058→30 lines, four private implementation modules and unchanged
matching tests moved to the public integration boundary. Function/serde/index
preservation checks, default/all-feature/MSRV/consumer/archive gates, seeded ASAN
and 42 current-daemon browser flows pass. Twenty matched Criterion means have no
candidate slowdown above 4.7%; extra loopback repeats resolve the initial relative
tail concern without a universal latency claim. See the Sprint 01 review/evidence.

### DNS-006 Split engine orchestration by responsibility — E2 — M

Status: Done. Priority: 3. Dependencies: DNS-004. Sprint: 02.
Grounding: crates/dns-core/src/engine.rs has 1043 lines.
Spec: [engine ownership](../specs/DNS-006-engine-ownership.md), grounded and
self-reviewed before implementation on 2026-10-15.
Acceptance: spec maps admission, local/policy, forwarding and finalization before
moves; retain original snapshot/client identity, response inspection, exception/
schedule rechecks, cache keys and telemetry; no API/behavior change. Protocol,
cache, CNAME, client/tag, schedule and cancellation regressions pass with workspace
and consumer gates; matched engine/loopback baseline has no unexplained regression.
Accepted: facade 1043→260 lines and five private modules (113–294), preserved
stage/type bodies and original schedule tests. Default/all-feature/MSRV, consumer,
compiled archive, rustdoc/benchmark-build and security/fuzz gates pass; 68 current
daemon browser cases pass. Engine means have no slowdown above 4.9%; an identical
matcher-binary outlier did not recur in four focused repeats. All loopback bounds
and counts pass, with no sustained unexplained regression. Self-review and full
evidence/limits: [Sprint 02 review](../reviews/sprint-02.md).

### DNS-007 Audit policy workflow usability — E3 — S

Status: Done. Priority: 4. Dependencies: DNS-004. Sprint: 01.
As an operator I need a clear safe route from editing to a verified promotion.
Acceptance: inspect real-daemon policy, local DNS and migration flows on desktop
and phone in both themes; keyboard/loading/error/stale-ETag/read-only states follow
[design](../engineering/design.md); classify reproducible issues with screenshots
under target/ and at most three ranked follow-up stories. Do not redesign from
assumed failures. A short sprint-review finding summary is sufficient.
Accepted: native desktop 1280px/phone 390px, light/dark, keyboard wrapping/panel
focus, loading/empty and real stale-ETag preservation inspected. Full baseline
148 HTTP + two HTTPS flows cover permissions/revoke and error paths. Ten native
screenshots and DOM observations are in target/review/sprint-01/ui-audit/.
Ranked follow-ups: DNS-016 (confirmed focus defect), DNS-014 (phone task-distance
concern), DNS-017 (confirmed version-copy defect). No UI source was changed.

## Reliability and later work

### DNS-008 Prepare native deployment-host acceptance — E4 — M

Status: Backlog. Priority: 6. Dependencies: DNS-004. Sprint: 04 proposed.
Acceptance: current package/recovery fixtures pass; prepare explicit host prerequisites,
sandbox/port/permission/backup/recovery assertions and reversal plan; identify the
authorized target. Mark host tests pending until actually run with permission.
No workstation DNS/firewall/DHCP or service activation as a side effect.

### DNS-009 Run representative network soak — E4 — L

Status: Backlog. Priority: 7. Dependencies: DNS-008 and authorized target access.
Refine into setup/measurement/analysis stories. Acceptance: 24–72-hour representative
query mix, promotion/restart/storage/upstream failures, latency/resource/telemetry
observations and recovery; retain faults and explicit workload limits. A loopback
fixture cannot satisfy representative-network acceptance.

### DNS-010 Scope independent security review — E4 — S

Status: Backlog. Priority: 8. Dependencies: DNS-004.
Acceptance: threat surfaces, reviewable source identity, parser/admission/publication/
auth scope, known limits and reproducible local checks prepared. Actual independent
review needs an identified independent reviewer; self-review does not meet that gate.

### DNS-011 Validate target ARM hardware — E4 — M

Status: Backlog. Priority: 9. Dependencies: DNS-008 and target hardware.
Acceptance: target/toolchain identity, DNS/protocol/resource/recovery and matched
local performance recorded on actual hardware; support claims limited to that
validated target. Cross-compilation alone is insufficient.

### DNS-012 Refine source compatibility priorities — E5 — S

Status: Backlog. Priority: 10. Dependencies: DNS-004, DNS-007.
Acceptance: rank real operator cases among unsupported service parameters, source
priority/exception effects and live refresh; each candidate includes source semantics,
compatibility/cache bounds and a vertical slice. Preserve blockers until proven.
No broad parity claim or automatic selection of an unrequested feature.

### DNS-013 Validate service-alias graphs — E5 — M

Status: Backlog. Priority: 11. Dependencies: DNS-012.
Grounding: current service-binding contract explicitly leaves complete alias graph
validation open. Acceptance must be specified before Ready: offline graph limits,
loops/conflicts, exact/suffix/root targets, typed mode semantics and error provenance;
no unbounded query chasing or Additional synthesis. Keep this separate from adding
service parameters and from full AdGuard compatibility.

### DNS-014 Reduce policy editor complexity — E3 — M

Status: Done. Priority: 4. Dependencies: DNS-007. Sprint: 03.
Spec: [policy task access](../specs/DNS-014-policy-task.md), grounded and self-reviewed
before implementation on 2026-10-15.
Grounding: editors.tsx/workbench.tsx exceed 800 lines, API types 700; globals.css is
1936 lines. The Sprint 01 audit additionally measured Add DNS record at document
Y≈1921px in a 390×844 empty-record fixture: status cards and reference prose precede
the task. This is a usability concern, not an overflow or DNS correctness defect.
Keep semantic guidance accessible while reducing scroll to the selected task.
Acceptance: use observed UX/code ownership to split only justified
boundaries; preserve draft/session lifecycle, validation/shadow/preconditions and
all real-daemon flows. Keep cohesive token/CSS exceptions explicit; do not move
lines solely to satisfy a numeric cap or introduce a component framework.
Accepted: matched empty-record phone action Y1852.06→772.02 (58.32% less document
distance), bottom Y816.02 inside 844px, both themes. Desktop Y1040.25→626.52.
Four editor bodies, assertion results, tabs and async/draft handlers are preserved;
workbench 821→504 lines. Keyboard Add selects/focuses a new row across paging and
policies. Guidance, policy scope and publication safeguards remain accessible.
Required Rust/Bun gates, 38 affected flows and all 180 HTTP/2 HTTPS cases pass;
four final theme/layout viewport states inspected. Self-review, raw failures and
measurement limits: [Sprint 03 review](../reviews/sprint-03.md).

## Sprint 01 verification defect

### DNS-015 Bound retries for ephemeral DNS fixture startup — E1 — S

Status: Done. Priority: 1. Dependencies: none. Sprint: 01 rework reserve.
Grounding: the first Rust 1.95 workspace test run failed in
revisions::shadow_promote_rollback_and_durable_generation at the shared Harness
Server::bind call with AddrInUse. Server correctly binds TCP first, then UDP at
the selected port; the UDP port can already be occupied. This is a fixture startup
assumption, not evidence of broken policy publication or an MSRV incompatibility.

Acceptance: retry only AddrInUse when allocating the fixture's ephemeral dual
transport listener, at most eight attempts; all other failures remain immediate.
Preserve production bind/error semantics, test assertions and concurrent tests.
Retain the failed run and pass full default/all-feature/MSRV tests plus focused
repeats of the failed case. No standalone spec: narrow test-only error handling;
source diagnosis and acceptance are recorded here and in the sprint review.
Evidence: full default/all-feature/MSRV reruns and six focused repeats passed;
logs and command results are in target/review/sprint-01/baseline/fixture-fix-checks.json.

## Ranked UI audit follow-ups

### DNS-016 Restore focus after asynchronous policy review — E3 — S

Status: Done. Priority: 2. Dependencies: DNS-007. Sprint: 02.
Spec: [focus return](../specs/DNS-016-review-focus.md), grounded/self-reviewed.
As a keyboard operator I need closing review to return me to its initiating action.

Confirmed reproduction: validate/stage a candidate, open Review promotion, press
Escape, wait 300ms. document.activeElement is BODY; the next Tab reaches Skip to
content rather than the review action. Reproduced twice in the native browser.
The review handler disables its button while fetching the candidate; Modal records
focus after opening. That timing is the likely cause, to verify during implementation.

Acceptance: capture the trigger before asynchronous work; Escape, Cancel and Close
return focus to the connected enabled trigger. If publication removes it, use a
sensible main-content fallback. Preserve modal containment, error/loading states,
query-dialog return and desktop/mobile themes; add a real-daemon keyboard regression.
No credential, policy-publication or DNS behavior change.
Accepted: the new regression fails before the fix; 20 new desktop/mobile/light/dark
cases pass after it, including delayed fetch, Escape/Cancel/Close, containment,
successful removal, failed fetch and stale publication. Existing console/design
24 flows and both HTTPS permission flows pass. Visual inspection and required
workspace checks pass; self-review, no independent review claimed. Raw evidence:
target/review/sprint-02/; closeout in the Sprint 02 review.

### DNS-017 Correct cancellation-version guidance — E3 — S

Status: Done. Priority: 5. Dependencies: DNS-007. Sprint: 02.
Confirmed: a fresh supported AdGuard import produces adguard_v6, but migration says
“Review the V2 lists” and validation says “Inspect the V2 list text”. Native evidence
contains both messages and the actual V6 selector value.

Acceptance: both notices refer accurately to the reviewed list, without hard-coding
an outdated current-import version; keep the warning that removing cancellation
can expose a block. Verify native and legacy V2–V6 behavior and the affected real
browser import/validation flows. Tiny copy correction: no standalone spec needed;
no compiler, parser, serialized version, cache or policy-precedence change.
Accepted: version-neutral notices retain the cancellation warning. Twelve real
daemon browser flows cover Native/legacy rejection, V2–V6 validation, fresh V6
import and V2 promotion/provenance. Both themes/layouts were visually inspected.
Seven frozen-cancellation Rust regressions and final console format/lint/build/
audit plus both HTTPS flows pass. Self-review; [Sprint 02 review](../reviews/sprint-02.md).

## Deferred ideas

DoQ/DNSCrypt, automatic HA, external identity and firewall bypass prevention are
outside the selected roadmap. Refine only with a concrete product request. New
stories use the next free ID and link the outcome to an epic; never pad the backlog
with speculative tasks. Bugs found during acceptance outrank elective features.
