# Sprint 01 Review and retrospective

Closed 2026-10-15 under the maintainer’s “Run Sprint 01” request. Original planning
window: Oct 19–25. Goal met: current-source acceptance and one behavior-preserving
ownership improvement. Review: agent self-review; no independent/human approval,
merge, release or deployment is claimed.

## Accepted outcomes

DNS-004: fresh local baseline, source/environment identities and saved executables.
DNS-005: filtering crate root reduced from 1058 to 30 lines, with four private
modules and existing contract tests moved to public-API integration tests.
DNS-007: real-daemon desktop/phone/light/dark audit, with three ranked follow-ups.
DNS-015: bounded test-fixture startup retry, using one point of the rework reserve.
All selected stories completed: 8 relative points including rework, not a velocity
or time-to-deliver guarantee. Sprint 02 is planned and has not started.

Evidence: ignored `target/review/sprint-01/`. source-before.tar.gz/source-before.json
preserve the original dirty tree; environment.json records hardware/toolchains.
The source-integrity report confirms only the filtering implementation/imports and
one test fixture changed outside Markdown. UI sources, manifests and lockfiles
are unchanged; the saved candidate matches the final shipping executable.

## Verification

- fmt and strict workspace/all-target/all-feature locked Clippy: passed.
- Default workspace tests: 458 passed before/after; all-feature tests: 471 passed.
- Rust 1.95 compile and full tests: passed, 458 tests after the fixture correction.
- Public consumers, verified library archives, benchmark builds and warnings-as-errors
  rustdoc: passed. All 14 broad candidate checks passed.
- Console format/lint/build/audit: passed. Baseline real-daemon suites: 148 HTTP
  desktop/mobile flows and two HTTPS/auth/read-only/revoke flows. Current refactor
  daemon: 42 affected filter/scope/provenance/publication browser flows passed.
- Python suite: 16 passed, including manifest coverage/deterministic repacking.
  Final doc-link/whitespace checks and package repeat results are in checks/.
- Root/fuzz cargo audit/deny: passed with existing informational warnings retained.
  ASAN filter corpus replay: 7677 inputs, 133s; fresh-seed mutation run: 6027 inputs,
  31s; offline engine preparation: 792360 inputs, 31s. These supplement regressions
  and do not establish security certification or exhaustive coverage.

The initial MSRV test failed with AddrInUse at dual-transport fixture startup.
Production Server::bind correctly reports bind errors; the test assumed ephemeral
startup always succeeds. DNS-015 retries only that error, at most eight attempts.
The failed run remains; full reruns and six focused repeats passed. No test
assertions or production listener/error behavior were weakened.

## Performance and structure

Ryzen 7 9800X3D, Linux x86_64, pinned Rust 1.99 release builds. Separate benchmark
package builds retain matching features; saved baseline/candidate binaries ran
serially as baseline → candidate → candidate → baseline. Shared desktop activity
was uncontrolled. Matcher datasets: 100k/1M rules; loopback uses its own small
warm policy and 100k-rule reload fixture, not a 1M-rule wire-latency claim.

Twenty selected Criterion cases cover exact/suffix/miss/working-set/mixed/scoped
matching and blocked/cache/long-name engine work. Averaged candidate slowdowns are
all below 4.7%. One baseline-only 100k miss lookup changed from about 11ns to 28ns;
retain it as variability, not a claimed speedup. CPU/query probes do not link the
allocation counter. Allocation probes retain 8 allocations/1127 bytes for warmed
blocked replies and 10/1149 for warmed cache replies in their documented fixture.
No zero-allocation, maximum-capacity or universal performance claim.

Initial loopback warm-block p99 was 9/10us baseline versus 12/11us candidate,
triggering investigation. Eight additional alternating launches found blocked p99
medians 8.5us baseline/9us candidate, cache 9.5us/both, and reload 11us/9us. Individual
tails varied in both builds; no sustained 20% regression was reproduced. All cold
exchange counts and 128-waiter single-flight checks passed. Keep every launch in
comparison.json, loopback-repeats.json and the raw logs; do not choose only fast runs.

At 1M rules both versions retain Rule size 56 and estimated payload 121388897 bytes.
RSS was about 208–209MiB and peak about 307–311MiB across runs, including compiler
transients/allocator retention. Estimates are not exact allocator/RSS accounting.
Rust inventory: 189→194 files, 57782→57824 physical lines (+42 for explicit imports/
module headers and the fixture correction). UI remains 33 files/9909 lines.
The four new production modules are 75–242 lines; no new dependency/suppression.

## UX findings and remaining gates

Ten native screenshots/DOM observations are in ui-audit/. Inspected keyboard section
wrapping/panel focus, empty/loading states, light/dark layouts, and a genuine competing
editor write producing 412 while preserving the V6 draft and publishing no shadow.
Existing HTTPS tests and screenshots verify read-only controls and durable revoke.
No document overflow was observed at 1280px/390px; this is targeted inspection,
not complete accessibility certification.

Ranked follow-ups: DNS-016, confirmed focus loss after asynchronous promotion review
(Escape leaves BODY; next Tab jumps to Skip to content); DNS-014, phone usability
concern (Add DNS record near document Y1921px in a 390×844 empty-record fixture);
DNS-017, confirmed V2 guidance despite actual V6 import/validation. No UI source
changed during the audit. Existing defects are recorded rather than hidden by a
passing test count.

Native host/systemd activation, ARM, 24–72-hour representative-network soak and
independent security review remain open. 5M/10M datasets and comparative-appliance
capacity were not measured. Repacking is not native-host deployment acceptance.

## Retrospective and next planning

Helpful: freeze the dirty source and binaries first; use real consumers; separate
model/parsing/index/evaluation ownership; compare moved bodies; include visual and
keyboard checks. Rework: one missing Source import after the move, corrected before
passing validation; initial test-fixture failure; a working-directory correction
in orchestration. No maintainer clarification/intervention was needed after start.
Independent-review effectiveness and escaped production-defect rates remain unknown.

Two process actions:
1. Agent, DNS-005 (implemented): bounded fuzz smoke uses fresh checked-in seeds and
   an outer process timeout. Old corpus initialization consumed the mutation window;
   preserve that replay and report actual elapsed time/input count. The fresh run
   completed mutations in 31s; a timeout must never be recorded as a pass.
2. Agent, DNS-016 (Sprint 02): add a real-daemon focus-return regression for async
   review, alongside existing query-dialog coverage. Success: Escape/Cancel/Close
   return to the correct enabled trigger, with a tested fallback when it disappears.

[Sprint 02](../planning/sprints/sprint-02.md) prioritizes focus return, engine ownership
and truthful version guidance at 5 points plus rework reserve. DNS-014 remains a
separate UI/structure slice. Refresh baselines if source/fixtures change; do not
reuse this review as acceptance of a future diff.
