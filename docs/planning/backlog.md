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

Status: Done. Priority: 6. Dependencies: DNS-004. Sprint: 04.
Acceptance: current package/recovery fixtures pass; prepare explicit host prerequisites,
sandbox/port/permission/backup/recovery assertions and reversal plan; identify the
authorized target. Mark host tests pending until actually run with permission.
No workstation DNS/firewall/DHCP or service activation as a side effect.
Spec: [native acceptance](../specs/DNS-008-native-acceptance.md), self-reviewed
against current packaging and recovery code. The user authorized the prepared
run in a separate disposable VM. Debian 13 x86_64/KVM, systemd 257 and GLIBC 2.41
passed the full native service/DNS/upgrade/reversal/WAL recovery fixture and
effective sandbox probes. Seven unit starts; final inactive/disabled state,
removed probe drop-in and powered-off guest verified. Repeat-installed/non-VM/
unprivileged refusals and injected-failure cleanup passed. Default container smoke,
16 Python tests and required checks (458 Rust tests) pass. Evidence:
target/review/sprint-04/native-vm/; [review](../reviews/sprint-04.md).
Real older-binary compatibility, other hosts/ARM and representative soak remain
unverified. Same-binary reversal does not establish downgrade compatibility.

### DNS-009 Run representative network soak — E4 — L

Status: Backlog. Priority: 7. Dependencies: DNS-008 and authorized target access.
Refine into setup/measurement/analysis stories. Acceptance: 24–72-hour representative
query mix, promotion/restart/storage/upstream failures, latency/resource/telemetry
observations and recovery; retain faults and explicit workload limits. A loopback
fixture cannot satisfy representative-network acceptance.
Define the protocol first in DNS-018; activation and the long run need a separately
authorized representative target and execution window.
Delivery split: DNS-020 runner, DNS-021 lab qualification, DNS-022 long window,
DNS-023 analysis. All four and the original acceptance must hold before DNS-009 Done.

### DNS-010 Scope independent security review — E4 — S

Status: Done. Priority: 8. Dependencies: DNS-004. Sprint: 05.
Acceptance: threat surfaces, reviewable source identity, parser/admission/publication/
auth scope, known limits and reproducible local checks prepared. Actual independent
review needs an identified independent reviewer; self-review does not meet that gate.
Accepted: [grounded review brief](../engineering/security-review.md) maps trust
surfaces/invariants/tests, known limits and fuzz gaps. Local source packet includes
base plus diff/status, complete source hashes/modes and current check records;
extracted source verifies and passes fmt/docs. Root/fuzz audit and deny pass with
retained deny warnings. No reviewer contact, upload or independent review occurred.
Evidence: target/review/sprint-05/security-packet/; DNS-024 tracks actual review.

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

### DNS-018 Define representative soak protocol — E4 — S

Status: Done. Priority: 7 (DNS-009 prerequisite). Dependencies: DNS-008. Sprint: 05.
Outcome: turn DNS-009's large soak into executable setup, measurement and analysis
slices before starting a long run. Acceptance: grounded query/client mix, correctness
and resource/latency observations, promotion/restart/storage/upstream failure matrix,
backup/recovery, duration/stop criteria and evidence schema; identify missing target
and execution authority explicitly. Create bounded follow-up stories from that
protocol. Excludes activation, router changes and starting/scheduling a soak.
Protocol: [representative soak](../engineering/soak.md), self-reviewed against
current examples, histogram/resources and durable API/recovery contracts.
Accepted: workload/oracle, target/run-record prerequisites, numeric-budget gate,
fault/undo matrix, duration/stop/evidence bounds and DNS-020–023 delivery split are
defined. Missing representative lab/window authority remains explicit; no long
run started. Existing short CLI rehearsal and histogram checks ground the limits;
they do not establish representative performance. Self-reviewed; docs checks pass.

### DNS-019 Correct rehearsal histogram metadata — E4 — S

Status: Done. Priority: 6 (acceptance defect). Dependencies: DNS-008. Sprint: 05 rework.
Confirmed: shared histogram bins cap at 2,000,000 us with 21,001 bins, while
control_soak describes 1 s/11,001 bins and encrypted_resilience describes 1 s.
Acceptance: both emitted descriptions match the existing 2 s/21,001-bin helper;
preserve sampling, quantiles, clipping, workloads and correctness assertions.
Verify actual report output and existing >1 s/clipping regressions. Tiny fixture
metadata correction needs no standalone design; no runtime/performance change.
Accepted: fresh before/after CLI reports prove the correction; all nine example
regressions pass, including eight shared histogram tests. Source comparison confirms
only two strings changed, with byte-identical daemon and histogram helper. Required
workspace gates pass. Evidence: target/review/sprint-05/; self-reviewed.

### DNS-020 Implement bounded remote soak runner — E4 — M

Status: Done. Priority: 7. Dependencies: DNS-018. Sprint: 06.
Outcome: exercise an independently hosted appliance without respawning/resetting
it per cycle. Acceptance: validate the protocol's run record, bounded offered-rate
driver/oracle, explicit load skips/cancellations, fixed resource/histogram windows,
counter resets and output limits; reject wrong answers, missing budgets, clipping
and unsafe/unbounded inputs. Preserve existing short local modes. Verify with
local mocks, injected wrong answers, recorder limits and cleanup. No external
activation or long run; ground a short spec before implementation.
Accepted: [spec](../specs/DNS-020-remote-soak.md) and
[driver contract](../operations/soak-runner.md), self-reviewed. Strict inputs,
continuous offered phases, original-phase oracle, resource/reset accounting and
bounded output verified with local mocks and a separately running appliance.
All 473 workspace tests, required gates, six CLI success/failure checks, 61-second
minute-boundary run, both legacy rehearsals and seeded sanitizer smoke pass;
root/fuzz audit/deny pass with retained warnings. Evidence: target/review/sprint-06/.
No representative/remote-collector/long-window acceptance is claimed.

### DNS-021 Qualify representative soak lab — E4 — M

Status: Backlog. Priority: 7. Dependencies: DNS-020, DNS-025, DNS-026 and named representative lab.
Sprint: carried from 07; candidate 09, not Ready without target/workload/budget/authority prerequisites.
Draft: [representative lab](../specs/DNS-021-representative-lab.md), selected reference
profile and concrete readiness/qualification steps; no representative claim.
The [two-VM exercise](../operations/soak-lab.md) passed synthetic mechanics under
DNS-026 and is stopped; it does not establish the operator's representative
routed/storage workload.
Acceptance: independent clients and representative routed/storage path, private
fixtures, observed workload basis, numeric load/latency/resource/recovery budgets,
verified backup and reversal, and at most 15-minute qualification including a
wrong-answer sentinel. Freeze the run record and exact long-window authority.
No workstation/router takeover or automatic long-run start. Missing target,
representativeness or authority keeps this story unready.

### DNS-022 Execute representative soak window — E4 — M

Status: Backlog. Priority: 7. Dependencies: DNS-021 and authorized 24–72-hour window.
Acceptance: complete the protocol's continuous workload and planned fault/recovery
matrix with bounded complete evidence, stop on declared failure, and restore the
agreed service state. Retain failed/incomplete attempts with new IDs for retries.
Scheduling/background execution needs explicit authority; native VM acceptance
alone does not authorize this run. Measurement results feed DNS-023.

### DNS-023 Analyze soak and reconcile reliability gate — E4 — S

Status: Backlog. Priority: 7. Dependencies: DNS-022.
Acceptance: verify source/topology/load/duration, reconcile request and metric
counts, merge histogram bins, review latency/resource tails, failures and recovery,
and triage every defect/gap without dropping adverse windows. Close DNS-009 only
when its full interval, representative workload and phase criteria hold; an
incomplete/failed run remains open with a specific next action.

### DNS-024 Perform independent security review — E4 — L

Status: Backlog. Priority: 8. Dependencies: DNS-010 and identified independent reviewer.
Refine/split with the reviewer before Ready: agree exact source, surfaces, method,
access and execution limits. Acceptance: independent reviewer identity/date,
coverage/exclusions, private reproducible findings and severity/confidence;
maintainer triage, regression-backed resolutions and explicit unresolved gaps.
New relevant code needs review of its new diff. A self-review or passing scans
cannot satisfy this gate. No delegation/contact/upload authority is inferred.

### DNS-025 Implement bounded target-local soak collector — E4 — M

Status: Done. Priority: 7. Dependencies: DNS-020. Sprint: 07.
Split from DNS-021's concrete collector prerequisite; does not close qualification.
Outcome: replace ignored scratch sampling with a reusable one-shot Linux collector.
Acceptance: real PID/start/namespace/API ownership, proc/storage/status/metric values,
strict numeric/identity parsing, bounded files/enumeration/HTTP/deadline/output,
no redirects/proxies, no sample on collection failure and no target mutation. Trusted
controller owns sequence/atomic handoff/remote transport; HTTPS remains unsupported.
Verify local fault fixtures plus actual daemon-to-driver handoff and required gates.
Spec: [bounded collector](../specs/DNS-025-soak-collector.md); separate agent design review accepted.
No VM/service activation, real lab selection, long run or independent security claim.
Accepted: separate agent design/code review; 18 collector regressions, all 34 Python
tests, 473 workspace tests and required gates pass. Actual owned-daemon CLI checks
prove valid samples/30 UDP-TCP replies, PID/listener refusal, wrong-answer failure
and stale collection failure with complete accounting/cleanup. A bounded 70000-case
seeded Python parser mutation run completed without unexpected exceptions; no
sanitizer/coverage-guided claim. Root/fuzz audit/deny pass with retained warnings.
Evidence: target/review/sprint-07/; representative qualification/DNS-021 remains open.

### DNS-026 Execute disposable Docker lab qualification — E4 — M

Status: Done. Priority: 7. Dependencies: DNS-020, DNS-025. Sprint: 07.
Split synthetic lab mechanics from DNS-021's representative acceptance. User's
separate-VM approval and continuation after the concrete proposal authorize two
new isolated guests and the bounded exercise; no workstation takeover/long soak.
Acceptance: freeze real artifact/topology/clock/config/oracle/budget identities;
run Docker appliance plus independent client with private Hickory fixtures;
demonstrate steady/burst, deliberate wrong answer, sampler loss, cancellation,
SQLite backup/restore and verified owned-container/VM teardown. Preserve failures.
Review code and evidence separately and pass required local checks.
Spec: [disposable lab](../specs/DNS-026-disposable-lab.md).
Evidence: ignored target/review/sprint-07/lab/. Separate agent design/code/evidence
review accepted. Pilot 500, steady/burst 3400 and 500 correct queries after a cold-cache restart; exact after-drain request accounting. Wrong-answer, sample-loss and SIGINT
fail as intended; SIGINT had no outstanding exchanges. All owned guests/services
stopped, restart disabled and listeners absent. Required local checks pass.
Physical representative paths/workloads and DNS-021 remain open.



### DNS-027 Collect verified HTTPS appliance observations — E4 — M

Status: Done. Priority: 7. Dependencies: DNS-025. Sprint: 08.
Outcome: collect actual production-style TLS API observations without weakening
PID/namespace/socket identity or introducing environment writes/trust fallback.
Acceptance: explicit bounded CA/server identity, numeric-loopback-only connect,
verified TLS>=1.2, strict framing/deadline/output limits, real success/failure TLS
fixtures and actual appliance handoff; unchanged HTTP/schema/production DNS path.
Spec: [HTTPS collector](../specs/DNS-027-https-collector.md); separate agent design review accepted.
Tasks: current sprint. No representative/long-run/security-audit claim.
Accepted: 25 focused TLS/collector regressions and actual password-mode TLS appliance
collection; wrong identity/PID/environment failures, bounded parser mutations and
separate source/runtime review. Required/security/compatibility gates pass.
Shared review/evidence: [Sprint 08](../reviews/sprint-08.md), ignored target/review/sprint-08/.

### DNS-028 Qualify large replies and live CLI cancellation — E4 — M

Status: Done. Priority: 7. Dependencies: DNS-020, DNS-026. Sprint: 08.
Outcome: distinguish actual downstream fallback and interrupted live exchanges
from the earlier upstream-only truncation and idle SIGINT evidence.
Acceptance: fixed bounded Hickory large RRset/reference, exact oracle, actual
appliance UDP<=512+TC/fullTCP/driverfallback, OS SIGINT after observed outstanding
request, positive cancellation accounting, peer EOF/target survival and cleanup.
Spec: [protocol coverage](../specs/DNS-028-soak-protocol-coverage.md); separate agent design review accepted.
No production query path/schema/dependency or large-scale performance change.
Accepted: actual rebuilt VM image returns complete 498-byte UDP TC/29RR and
1058-byte TCP/64RR. 100 logical probes reconcile with 180 wire requests; live OS
SIGINT retains one cancellation, peer EOF and target survival. Both guests off.
Shared review/evidence: [Sprint 08](../reviews/sprint-08.md), ignored target/review/sprint-08/.

### DNS-029 Preserve CD in accepted soak request envelopes — E4 — S

Status: Done. Priority: 6 (confirmed acceptance defect). Dependencies: DNS-020. Sprint: 08.
Reproduced: CD=true response reference validates, but transmitted query CD=false;
a correct echoing responder is reported wrong. No appliance defect is inferred.
Acceptance: preserve reference CD for UDP/TCP/fallback; reject mixed-CD transition
references before traffic; wrong CD still fails; uniform existing records unchanged.
Spec: [CD envelope fix](../specs/DNS-029-soak-cd-envelope.md); separate agent design review accepted.
Reproducer: ignored target/review/m2-adversarial/; tasks in current sprint.
Accepted: before/after local UDP/TCP/fallback regressions preserve correct CD and
reject wrong/mixed CD; separate review and all required/security gates pass.
Shared review/evidence: [Sprint 08](../reviews/sprint-08.md), ignored target/review/sprint-08/.

### DNS-030 Reject incomplete and unmatched raw soak DNS wire — E4 — S

Status: Done. Priority: 6 (confirmed oracle defect). Dependencies: DNS-020. Sprint: 08.
Reproduced: exact valid reply plus trailing bytes is reported correct; fixture hex
also accepts the suffix. Hickory decodes only a prefix. Reserved header Z is also
normalized away; enforce zero only in the strict tool profile, not production DNS.
Acceptance: shared Hickory complete-consumption boundary for references and UDP/TCP
replies and advertised UDP byte bounds; suffix/truncation/Z regressions, unchanged valid/compressed DNS, preserved
failure evidence and required checks. No parser replacement or production change.
Spec: [complete oracle wire](../specs/DNS-030-complete-soak-wire.md); separate agent design review accepted.
Reproducers: ignored target/review/m2-adversarial/. Tasks in Sprint 08.
Accepted: all original false-acceptance reproducers now fail; valid compressed
wire and full TCP remain accepted. Seeded ASAN smoke and required gates pass.
Shared review/evidence: [Sprint 08](../reviews/sprint-08.md), ignored target/review/sprint-08/.

### DNS-031 Remove uncommitted bytes from truncated DNS replies — E4 — S

Status: Done. Priority: 5 (confirmed production correctness defect).
Dependencies: none. Sprint: 08. Discovered by DNS-028 actual appliance acceptance.
Hickory truncation rolls back its cursor but retains partial Vec bytes; engine
returns that suffix. Captured511-byte UDP/29RR TC reply fails complete decoding.
Acceptance: return only committed encoder bytes; raw UDP/EDNS/TCP regression,
actual repaired container fallback across VMs, preserved failing packet/image,
required checks/security and matched hot-path measurement. No custom parser/API change.
Spec: [truncated wire boundary](../specs/DNS-031-truncated-wire-boundary.md); separate agent design review accepted.
Evidence: ignored target/review/sprint-08/lab/large-wire*; tasks in Sprint 08.
Accepted: 18 raw A/AAAA transport cases and repaired actual VM fallback pass;
matched warm measurements retain both favorable/unfavorable observations with
unchanged fixture allocations. Seeded ASAN and full compatibility gates pass.
Shared review/evidence: [Sprint 08](../reviews/sprint-08.md), ignored target/review/sprint-08/.

### DNS-032 Reconcile saved driver evidence offline — E4 — M

Status: Done. Priority: 7. Dependencies: DNS-020. Sprint: 08.
Split mechanical analysis from DNS-023, whose actual long-run acceptance remains
blocked on DNS-022. Outcome: safely validate consistency of the four bounded native
report files without opening recorded paths or exercising any network/service.
Acceptance: native count/bin/quantile/window/client/resource reconciliation,
explicit passing versus consistent failed runs, incomplete/tampered/special-file
refusal; actual Sprint 07/08 fixtures and targeted malformed-input checks.
Spec: [offline evidence verifier](../specs/DNS-032-offline-soak-verifier.md), separate agent design review accepted.
No provenance, authority, representative-path, fault-matrix or long-run claim.
Accepted: 19 focused tests; 15 real/native CLI classifications retain passing versus
failed states and unchanged input files. Eight confirmed malformed-consistency
variants reject; 4864 bounded structured mutations have only supported outcomes.
Separate source/evidence review and final gates pass; see [Sprint 08 review](../reviews/sprint-08.md).

### DNS-033 Review native driver input replacement races — E4 — S

Status: Done. Priority: 7. Dependencies: DNS-020. Type: spike.
Observed during DNS-032 exploration: soak_record::bounded_file checks path metadata
before File::open, then follows the path again. A replacement between those calls
may bypass the initial symlink/special-file refusal or block opening a FIFO; the
post-open regular-file check happens after opening. No exploit or operational
failure was demonstrated. Investigate descriptor-based no-follow/nonblocking
opening and identity checks without weakening caps or adding a production parser.
Acceptance: decide supported platform/dependency tradeoffs, bounded owned-file
regressions and an implementable spec or evidence that existing constraints suffice.
Do not treat the Python verifier's safer reader as fixing this separate native path.

Spike accepted: source/caller and dependency review recommends safe locked rustix
NOFOLLOW/NONBLOCK opening with descriptor validation. Parent-directory trust and
external filesystem watchdog remain explicit. Implementation is DNS-034, separately
specified/reviewed; the spike itself performed no exploit test or source changes.

### DNS-034 Harden native driver regular-file admission — E4 — S

Status: Done. Priority: 6. Dependencies: DNS-033. Sprint: 08 rework reserve.
Outcome: remove the metadata/open leaf replacement gap for run/sample reads while
preserving atomic regular-file handoff and existing caps/identity checks.
Acceptance: safe no-follow/nonblocking open, descriptor type check, cap boundaries,
owned FIFO/symlink/atomic replacement regressions and actual CLI refusal/handoff;
explicit trusted-parent/local-filesystem/watchdog boundary. No production API change.
Spec: [native file admission](../specs/DNS-034-native-soak-file-open.md), separate agent design review accepted.
Accepted: safe descriptor admission and four regressions; 19 actual CLI checks
plus six collector/atomic-handoff checks pass. Owned child/controller stop cleanly.
Only existing rustix dependency edges changed; required/compatibility/security gates pass.
Separate source/evidence review and final gates pass; see [Sprint 08 review](../reviews/sprint-08.md).

### DNS-035 Preserve phase metadata on entry-sample failure — E4 — S

Status: Done. Priority: 6. Dependencies: DNS-020. Sprint: 08 rework reserve.
Confirmed native deterministic failure: with prior work pending, rejecting the
next phase's sample creates a window with the new label but old planned interval.
Scalar accounting still reconciles; complete failure evidence is contradictory.
Acceptance: establish entering phase metadata before fallible sampling; retain
failure, old completion origins/last observation, zero new dispatch and cancellation
accounting. Both native variants must classify consistent failed offline, not pass.
Spec: [failed phase evidence](../specs/DNS-035-failed-phase-evidence.md), separate design review accepted.
Reproducer: ignored target/review/sprint-08/phase-sample-repro-02/.
Accepted: both actual offer_phase regressions fail before and pass after; saved
current-source native cancellation/late-completion outputs classify consistent
failed (exit 2), preserve old observations/origins and dispatch no new requests.
Separate source/evidence review and final gates pass; see [Sprint 08 review](../reviews/sprint-08.md).

### DNS-036 Seed bounded lease-parser review coverage — E4 — S

Status: Done. Priority: 7. Dependencies: DNS-010. Sprint: 09.
Grounding: the review brief names missing lease_inventory seeds; target is pure
UTF-8 parsing with fixed now=100, not network discovery or operational inventory.
Acceptance: small synthetic valid/invalid corpus, actual-parser replay/field/boundary
assertions and rebuilt bounded seeded ASAN; required local checks and separate
review. No runtime behavior, dependencies or independent security approval changes.
Spec: [lease-parser corpus](../specs/DNS-036-lease-parser-seeds.md), separate design review accepted.
Accepted: ten synthetic seeds, five full-field/rejection/exact-boundary regressions,
separate source/evidence review and all required/compatibility checks pass. Fresh
seeded ASAN completed 51,323,664 iterations/901 seconds, exit 0; no safety or
independent-review claim. Evidence: target/review/sprint-09/.

### DNS-037 Seed pure identity-document review coverage — E4 — M

Status: Backlog. Priority: 7. Dependencies: DNS-010. Candidate: Sprint 09 follow-up.
Outcome: public synthetic corpus reaches valid/invalid validate_document branches
without password hashing, file load/save, provisioning or actual credentials.
Acceptance: reviewed dummy PHC/TOTP/token fixture policy, semantic and boundary
replay, rebuilt bounded seeded ASAN and required checks; no auth behavior changes.
Draft: [identity-parser corpus](../specs/DNS-037-identity-parser-seeds.md).

### DNS-038 Seed pure TLS-configuration review coverage — E4 — M

Status: Backlog. Priority: 7. Dependencies: DNS-010. Candidate: Sprint 09 follow-up.
Outcome: explicitly public matching fixture pair reaches both packed server_tls
modes and meaningful parser/configuration errors, without handshakes or live keys.
Acceptance: reviewed public-pair construction, exact discriminator/separator replay,
PEM/chain/boundary tests and rebuilt bounded seeded ASAN; no TLS/trust changes.
Draft: [TLS-parser corpus](../specs/DNS-038-tls-parser-seeds.md).

## Deferred ideas

DoQ/DNSCrypt, automatic HA, external identity and firewall bypass prevention are
outside the selected roadmap. Refine only with a concrete product request. New
stories use the next free ID and link the outcome to an epic; never pad the backlog
with speculative tasks. Bugs found during acceptance outrank elective features.
