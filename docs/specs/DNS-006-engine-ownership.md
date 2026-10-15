# DNS-006 Engine ownership without behavior changes

Status: Implemented and accepted in Sprint 02. Grounded and self-reviewed
by sprint agent before implementation on 2026-10-15.
Story: [DNS-006](../planning/backlog.md). Authority: user's request to continue
implementation and planning, scoped to Sprint 02. No public/persistent changes.

## Outcome and grounding

crates/dns-core/src/engine.rs is 1043 lines. It owns the serving API, admission,
local decisions, pending forwarding, response inspection, shadow comparison and
wire encoding. Server, examples and external consumers use the re-exported API;
engine_schedule_tests.rs exercises deterministic clock cutovers through private
prepare_at/complete_at/finish_at methods. Protocol/scope/CNAME/cache tests exercise
the public boundary. Preserve those tests rather than replacing them with tests
of module layout. Contracts: [architecture](../architecture.md),
[upstreams](../architecture/upstreams.md), [policy](../architecture/policy.md).

## Design

Keep engine.rs as the parent facade with unchanged Engine/EngineConfig, Transport,
Prepared and opaque PendingQuery definitions; retain constructors, observation,
snapshot access and answer orchestration. Add private child modules:

- admission: prepare/prepare_at, including snapshot pinning, normalization,
  client selection, temporary exception and schedule capture, and Outcome/Pending
  construction. Keep permission check, parse and telemetry ordering unchanged.
- decision: step and decide; local records/SafeSearch/block versus raw-cache or
  forward selection, forwarding aliases, type/client/tag/generation cache keys.
- forwarding: forward/reject/complete/complete_at; preserve resolver source mapping,
  pinned snapshot/client re-selection, exception refresh and alias assembly.
- outcome: finish_at and shadow_decision; preserve expiry/schedule rechecks,
  response CNAME/value inspection, shadow evaluation before synthesis, private TTL
  clamping, final flags, encoding, counters and bounded nonblocking telemetry.
- wire: accepted_question, canonical_ascii, finalize and encode, with the existing
  exhaustive Hickory ASCII/escape test next to its helper.

Use separate inherent impl Engine blocks. Helpers needed by siblings get only
pub(super) visibility. Keep shared private Pending/Step/Outcome types and fields in
the parent so descendants can use them without widening visibility. Narrow imports
per module. Schedule tests retain their sibling path and explicit protocol imports.
Aim below 500 lines per production module; no new dependency, trait, allocation,
lock, await, parser or query-path operation. Move complete bodies unchanged except
visibility/imports; verify token-equivalent bodies against the source snapshot.

Alternative: public stage traits or separate engine objects would force new
interfaces and state transfer, complicating lifetime/pinned-generation ownership
without a caller need. A private split preserves the ownership model. No ADR is
needed for this local implementation arrangement.

## Acceptance and verification

Existing refusal/EDNS/DO/CD, UDP/TCP truncation, local/rewrite/alias/SafeSearch,
raw/decision cache and response-inspection behavior must remain unchanged. Pending
queries retain the admission generation, client name/tags and resolver content;
expiry/schedule changes recheck before responding. Cancellation/coalescing and
load shedding retain existing bounds. Controller publication and persistence do
not change. All errors/failure sources and telemetry/provenance retain ordering.

Run cargo fmt --all --check; cargo clippy --workspace --all-targets --all-features
--locked -- -D warnings; cargo test --workspace --locked; all-feature workspace
tests; Rust 1.95 check/tests; python3 scripts/verify-consumers.py;
python3 scripts/verify-crates.py --allow-dirty; cargo bench --workspace --no-run
--locked; warnings-as-errors rustdoc;
python3 scripts/check-docs.py. Run relevant real-daemon console/scope flows with
the rebuilt daemon. Supplement parser/admission preservation with seeded ASAN
engine_prepare fuzzing, cargo audit/deny and unchanged dependency identities.

Performance hypothesis: moving unchanged functions should preserve observable
latency/allocation/resource behavior, but optimizer boundaries may change results.
Save fresh default-feature matching, engine and load executables before moves;
record source/fixture/toolchain/hardware identities in target/review/sprint-02/.
Build packages separately, then compare baseline → candidate → candidate → baseline
with CPU affinity and no concurrent verification jobs. Use 100k/1M matching fixtures,
blocked/cache/long-name/local engine fixtures and the existing loopback/load
correctness/reload/coalescing workload. Retain every result and investigate repeated
changes above 10%; a confirmed unexplained >20% regression blocks acceptance.
No absolute speed, capacity, hardware deployment or zero-allocation claim.

## Decisions and outcome

Facade 260 lines, five private modules 113–294 lines. Stage/type body comparison
and existing deterministic schedule tests are preserved; self-review found no
semantic changes. One test import became explicit. Default/all-feature/MSRV,
consumer/archive/rustdoc gates, 68 current-daemon browser flows and seeded ASAN
admission fuzzing pass, along with the final workspace benchmark-build gate.

Twenty-one matched Criterion cases and loopback checks found no sustained
unexplained regression. An isolated identical-binary matcher miss anomaly is
retained with four focused repeats. See the [Sprint 02 review](../reviews/sprint-02.md)
and target/review/sprint-02/ for complete scoped evidence and resource limits.
No design deviation, API/persistent change or new dependency was needed.
