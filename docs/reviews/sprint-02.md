# Sprint 02 Review and retrospective

Closed 2026-10-15, executed early under the user's request to
continue implementation, planning and tasks. Personal context; repository backlog,
no Jira; one agent. Review identity: agent self-review. No independent/human
approval, merge, publication or deployment is claimed.
All three selected stories accepted: 5 relative points, no carryover. These points
are not time promises or a measured weekly velocity.

## Outcomes and evidence

DNS-016 accepted: capture the initiating button before asynchronous candidate
loading; guarded return with main-content fallback. A new real-daemon regression
failed on the original source. All 20 new desktop/mobile/light/dark cases pass,
including delayed loading, Escape/Cancel/Close, containment, failed candidate
fetch, stale publication and successful promotion/stop removal. Existing 24
console/design cases and both HTTPS permission flows pass. Desktop/phone screenshots
were visually inspected in both themes; existing query-detail focus is retained.

DNS-006 accepted: correctness, compatibility, compiled archive/benchmark-build
and matched performance checks pass.
The engine facade is 260 lines, down from 1043; five private child modules are
113–294 lines. Shared types remain in the parent; public signatures are unchanged.
Normalized stage-body/shared-type comparisons and unchanged schedule-test bodies confirm the
move; imports and helper visibility are the only intended code differences.

Current Rust gates: fmt, strict workspace/all-target/all-feature Clippy, default
workspace tests (458), all-feature tests (471), Rust 1.95 check/tests (458), three
independent consumers, all five compiled library archives and warnings-as-errors
rustdoc pass. Current daemon: 68 console/focus/client/tag/type/schedule/service/
SafeSearch browser cases pass. Python suite: 16 passed. Documentation links pass.
Root/fuzz audit and deny pass with existing warnings; seeded ASAN engine_prepare
completed 859200 inputs in 31s without a crash. This supplements regressions and
does not establish exhaustive parser coverage or independent security acceptance.

DNS-017 accepted: both notices refer to reviewed/imported lists without an assumed
version; the warning about removing cancellation is retained. Twelve real-daemon
browser cases cover Native/legacy rejection, V2–V6 validation, fresh V6 imports,
V2 publication/provenance and bounded report paging. Eight viewport screenshots
were inspected in both themes/layouts. Seven frozen-cancellation Rust regressions
pass. Final console format/lint/build/audit and both current-daemon HTTPS flows
pass; no interpreter/configuration/cache contract changed.

Raw evidence and the original dirty-source snapshot: target/review/sprint-02/.
Named checks/commands and retained failures are in focus-checks.json,
engine-checks.json, engine-security.json and the corresponding logs.

## Quality and AI effectiveness

No new dependency, persistent/public API, DNS semantics or hot-path machinery.
Rust source inventory: 194→199 files, 57824→57875 physical lines (+51 for module
imports and explicit test imports). Five new production modules stay below 300
lines. Frontend source stays at 33 files, 9909→9922 lines (+13 for focus ownership,
fallback checks and copy formatting). Existing dirty source and unrelated work
remain intact; the final source-integrity check found no unexpected changed/new
files and no missing original files.

Ryzen 7 9800X3D, Linux x86_64, Rust 1.99 default-feature binaries; separate package
builds and CPU-pinned baseline → candidate → candidate → baseline launches, with
own verification jobs idle. Shared desktop activity was uncontrolled. Twenty-one
Criterion cases cover 100k/1M matching and block/cache/long-name/local engine work.
Engine mean slowdowns are below 4.9%; twenty of the twenty-one total case means
have no slowdown above 5.7%. The 1M matcher miss has one 22.86ns run versus roughly
11ns in the other three, despite byte-identical matcher executables. Four focused
alternating repeats measured 10.53–10.85ns (candidate-labeled average −0.62%).
The anomaly is consistent with process/workload variability; no reproducible source
regression was found. comparison.json and matching-repeats.json retain every run.

Loopback block p99: baseline 9/8us, candidate 8/8us; cache: 9/9us versus 10/9us;
reload: 8/8us versus 9/8us. Cold exchanges remain 50 and 128 duplicate misses use
one upstream exchange; all fixture assertions pass. Peak whole-load child RSS
is about 35–36MiB, including the workload and policy compilation; this is not exact
engine memory accounting. Allocation probes retain 8 allocations/1127 bytes for
warmed blocks, 10/1149 for warmed cache and 10/1415 for local rewrites. No sustained
unexplained latency/resource regression, capacity, universal latency or
zero-allocation claim.

Rework: the first focus regression correctly failed before implementation; the
first post-fix suite exposed a mistaken next-tab test locator, corrected without
changing production behavior. The engine split exposed a schedule-test Ordering
import previously inherited from its parent; made explicit before passing checks.
The source-comparison harness initially treated rustfmt's trailing signature comma
as a body change; narrowed that comparison and retained the initial failure.
One source/test rework round each for DNS-016 and DNS-006; none for DNS-017.
No maintainer intervention after execution start. Independent-review effectiveness,
escaped production defects and time/cost usage are unknown.

Native host/systemd activation, ARM hardware, representative 24–72-hour network
soak and independent security review remain outside this sprint's acceptance.

## Retrospective and planning

Useful: save the dirty source and executables before moves, compare complete stage
bodies, use actual daemon/browser failures, and retain anomalies rather than
averaging them away. Full-page captures make fixed overlays harder to inspect;
viewport captures clearly show the changed cancellation notices. No source
contract or scope deviation was needed.

Two process actions:

1. Agent, DNS-016 (implemented): hold a real candidate fetch across the disabled
   interval in focus regressions. The original code fails; all twenty post-fix
   cases pass, including each dismissal method and successful removal.
2. Agent, DNS-014 (next proposal): capture one viewport per theme/layout for changed
   interactions, retaining full-page captures and DOM distance only for document
   task reach. Success: the next review has all four viewport states plus an
   explicit before/after task-distance measurement.

[Sprint 03](../planning/sprints/sprint-03.md) proposes DNS-014's observed phone
task distance and justified editor ownership (3 points plus 1 for rework). It has
not started; readiness still requires current-source refinement and a reviewed
spec. M1's local development exit criteria are met; appliance/release gates remain
open. Revalidate changed source before relying on these historical results.
