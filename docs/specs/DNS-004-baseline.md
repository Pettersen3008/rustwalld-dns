# DNS-004 Current-source acceptance baseline

Status: Implemented and locally accepted. Story: DNS-004. Author/reviewer: reset agent,
self-reviewed against repository commands and source on 2026-10-15; no independent
or human approval is claimed. Evidence collection completed before the DNS-005 refactor.

## Outcome and scope

Establish a reproducible current-tree baseline before structural or product work.
Existing historical results cannot establish acceptance for a dirty source tree.
Collect local checks, code inventory and matched correctness/performance fixtures.
No source optimization, dependency update, new feature or host activation.

## Grounding and boundaries

Six workspace crates are declared in Cargo.toml. Existing reusable tools are
scripts/measure.py, cpu-probe.py, verify-consumers.py, verify-crates.py and the
crate Criterion/loopback examples. web/package.json defines Bun/Oxc/build and
real-daemon Playwright checks. scripts/release.py and script tests cover bundles.
Use these harnesses; do not create per-story benchmark scripts or public-DNS tests.

## Approach and alternatives

Capture git revision/dirty state and source digest, pinned toolchain, CPU/OS,
features and fixture inputs. Run the [local verification matrix](../engineering/verification.md)
with command/exit status/log paths. Capture scripts/metrics.py output. Build
shipping binary and examples separately; save executables and identities under
ignored target/review/sprint-01/baseline/ before subsequent story edits.

Use serial Criterion matching/engine plus real loopback load, then quiet repeats
for block/cache/miss. Record response correctness, upstream counts and telemetry
mode. Include 100k rules initially and at least 1M when hardware permits; explicitly
record unmeasured larger sets. Repeat in both orders once a candidate exists.
The baseline story measures current state; it does not itself prove an improvement.

Rejected: treating old readiness counts as current, comparing differing feature
builds, or creating a hosted CI workflow. They weaken the source/evidence contract.

## Budgets and compatibility

No DNS runtime behavior, allocations, cache identity or persistent format changes.
Measurements use local mocks and bounded existing fixtures. Run jobs serially to
avoid benchmark interference. Report RSS/payload/allocation evidence distinctly.
Investigate noise and regressions per the performance policy; no chosen favorable
run or absolute speed claim. Temporary artifacts stay under target/.

## Acceptance and failure behavior

All story acceptance in the backlog must have fresh current-source evidence.
A failing check becomes a concrete defect with source/command and reproduction;
retain its log, do not alter workload to hide it. Missing tools/hardware remain
explicit gaps. Required unrun checks prevent Done. Native host, ARM, long-soak and
independent-security gates remain open even when every local check passes.

## Tasks and outcome

Tasks live in Sprint 01. Required local Rust/default/all-feature/MSRV, consumer,
archive, console, 148 HTTP and two HTTPS browser flows, script and link checks pass.
The initial MSRV AddrInUse failure is retained; DNS-015 fixed only fixture startup,
then full reruns and six focused repeats passed. Audit/deny also pass in root/fuzz.
Saved default shipping binary, separate matching/engine/load/CPU/footprint binaries,
hardware/features/source identities and 100k/1M rule measurements are under
`target/review/sprint-01/baseline/`; command logs are under checks/. The first
performance run is baseline-a1, with 30 samples and 0.5s/1.5s Criterion windows.
5M/10M datasets, host/ARM/representative-soak/independent-security gates are unmeasured.
See [Sprint 01 review](../reviews/sprint-01.md) for final acceptance and comparisons.
