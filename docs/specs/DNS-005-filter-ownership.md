# DNS-005 Filter ownership and stable public surface

Status: Implemented and locally accepted; DNS-004 completed first. Author/reviewer: sprint agent,
self-reviewed against code/callers/tests on 2026-10-15. Authority: Run Sprint 01.
Story: [DNS-005](../planning/backlog.md). No public API or format change proposed.

## Outcome and grounding

crates/filtering/src/lib.rs has 1058 lines: public rule/configuration/provenance
records, control-plane parsing, name indexes, immutable evaluation and 339 lines
of contract tests. Existing private modules already own cancellation, scopes,
regex, parallel work and ordered ingestion. Keep those responsibilities intact.
Downstream policy/core, external consumers, fuzz targets and benches import the
crate-root public names. compile/exclusions/values currently access root-private
snapshot fields and helpers; module moves must preserve their internal access.

## Design and ownership

- lib.rs: crate docs, private module declarations and explicit public reexports.
- model.rs: Action, Matcher, ListInput, RuleSyntax, Source, Rule, ListStats,
  Cancellation, Decision and CompileError; serialized names/defaults and field order
  remain unchanged. Decision's constructor stays crate-internal.
- parsing.rs: normalize and existing native/AdGuard rule parsing. Only normalize
  remains public through the root; parsing is still control-plane work.
- index.rs: immutable name Index/Ids and escape-aware parent/suffix helpers.
  Keep hasher, sentinel values, inline annotations and walk logic unchanged.
- snapshot.rs: FilterSnapshot fields, ordered evaluation, cache-context identity,
  lookup/accessor methods and derived payload/count sealing. Sibling access uses
  pub(super), equivalent to the previous root-private visibility to child modules;
  it does not expose mutable state outside the crate.
- tests/matching.rs: existing normalization, precedence/provenance, exhaustive/
  randomized reference and escaped-label tests using the public root API. Preserve
  test bodies and assertions; existing scope/parallel/regex tests remain in place.

Update only sibling imports/internal helper paths. Public types/functions/methods,
serde behavior, rule IDs/provenance, V0–V6 interpretation, compile admission and
serial/parallel ordering remain stable. No runtime wrapper or new data structure.

Alternative: moving inline tests alone reduces the file length but leaves public
model, parsing and query evaluation coupled. Separate ownership makes the public
surface readable and gives future changes a clear destination. A new crate or
public module hierarchy would introduce compatibility/dependency cost without
helping this slice; reject it.

## Failure modes and verification

Risk: module privacy changes accidentally expose fields or break siblings; changing
paths can lose tests or rustdoc links; codegen may alter inlining. Compare moved
function bodies/token structure to the saved baseline, review all visibility and
root exports, compare test inventory and use existing independent consumers.
Production uses no unsafe/unwrap/expect and adds no lint suppression/dependency.

Run focused filter default/all-feature tests, full fmt/strict Clippy/default and
all-feature workspace tests, MSRV, public consumers, archive verification and
rustdoc. Retain existing parser/scope/cancellation regression coverage. Use saved
baseline/candidate matcher and engine executables in both orders, 100k/1M fixtures,
plus loopback block/cache/miss/cancellation/reload runs. Investigate repeated
regressions per [performance policy](../engineering/performance.md); no absolute
latency or zero-allocation claim. All artifacts stay under target/review/sprint-01/.

## Outcome

Implemented as designed: crate root 30 lines; model 204, parsing 196, index 75,
snapshot 242; existing matching tests 339 lines at the integration boundary.
Snapshot/parser/index/model/test preservation and manifest/lock checks pass. One
missing Source import was corrected after the first compile; no semantic rewrite
was needed. All broad candidate gates, seeded ASAN and 42 affected browser flows
pass. Matched measurements and the explicit loopback-tail investigation are in
[the Sprint 01 review](../reviews/sprint-01.md) and target/review/sprint-01/.
No new runtime behavior, configuration/schema, cache/protocol feature or UI source
change was introduced. No dependency or lint suppression was added.
