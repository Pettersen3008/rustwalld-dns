# DNS-032 Reconcile saved driver evidence offline

Status: Implemented. Story: DNS-032 in the [backlog](../planning/backlog.md).
Author: Codex coordinator, 2026-10-15; separate design review accepted by /root/review_sprint06, 2026-10-15.
Authority: user's two-hour M2 engineering goal, repository-only analysis.

## Outcome and grounding

DNS-023 currently depends on manual reconciliation of the recorder's summary,
aggregate bins and window rows. Extract that mechanical prerequisite without
claiming long-run or representative acceptance. Ground field semantics in
soak_recorder.rs, histogram.rs and soak_samples.rs and the actual Sprint 07/08
reports. No recorder/schema, production, network, service or UI changes.

## Design

Add Python stdlib `scripts/verify-soak.py --directory /absolute/DRIVER_OUTPUT`.
Use descriptor-relative no-follow directory/file access and duplicate-key/integer
validation from the existing collector, with a cohesive shared helper only if
necessary. Read only run.json (256 KiB), summary.json (64 KiB), aggregate.json
(16 MiB) and streamed windows.ndjson (16 KiB per row, <=4320 groups/32 lanes).
Selected files total <=128 MiB and the stricter frozen applicable output budgets.
Bound nesting/cardinality and reject special files, symlink ancestors, missing/
partial records, booleans as integers, overflow and nonterminated window lines.
Never open another recorded path or execute an embedded command.

Validate supported format/required shapes, recorded run/target/client/lane/
transport/phase identities, uniqueness, consecutive windows, time ordering,
per-lane inflight continuity and exact count reconciliation. Sum window scalars
into aggregate lanes and clients/summary with checked u64 arithmetic. Recompute
histogram counts and quantiles using the native fixed mapping and compare reports.
Validate intended/offered/unoffered/completed/pass/failure consistency and resource
summary shapes/identity/budgets. Per-window resources are duplicated per lane:
require equal copies and count once, not once per lane. Freeze exact supported
native fields; unknown newer evidence fails rather than silently passing.

Output bounded JSON separating evidence_consistent, driver_passed, completed and
external_checks_unverified. Exit 0 for consistent passing driver, 2 for consistent
failed driver and 1 for invalid/incomplete evidence. Incomplete flush coverage is
incomplete evidence, never a recorder bug or acceptance. No credential input,
network access, writes, dependencies or authority inferred from run.json.

Aggregate has no run/source binding; consistency cannot authenticate provenance.
Windows lack bins, so exact per-window distribution cannot be reconstructed.
Completion-origin counts sum replies + timeouts + errors, exclude cancellations
and may name earlier dispatch phases. The 21001-bin allocation has ten unused tail
bins: 2 seconds maps to index 20990, so indices 20991–21000 remain zero. Bins cannot
reconstruct exact max_us or window distributions; compare only derivable values.
For native zero-query failed runs, windows=0 is valid even if initial sampling
left nonempty global resources; no window resources exist to sum. Exit 2 requires
complete scalar/window coverage for the recorded work, otherwise exit 1.
Cancellation has no completion-origin entry. Completion-origin counts do not partition outcome kinds: exact mixed-phase
 timeout-policy compliance cannot be reconstructed. Reject a passing claim with
 timeouts if no contributing origin permits them; retain the remaining ambiguity.
 Never assign timeouts solely to the current window's dispatch label.
A stopped run may have offered==intended while completed=false; counts alone never
prove completion. Window resource deltas may cross sample boundaries, so their
first/last observations alone cannot reconstruct deltas. Sample deltas cannot be equated to
logical probes or drained wire counts. Do not claim full Prepared::parse/Hickory
run validation, fault-matrix coverage, authority, duration or M2 acceptance.
Rejected Rust example: adds deserialization/filesystem interfaces for a leaf;
Python reuses hardened access and can differentially test its small bin mapping.

## Acceptance and verification

Actual saved Sprint 07 qualification: pass/3400 replies; Sprint 08 large-tls:
pass/100; live-sigint: consistent failed/one cancellation. Check bounded generated
native multiwindow output to compare totals and quantiles. Regress tampered IDs,
counts/bins/quantiles/windows/inflight/client totals; truncated/missing files,
duplicate keys/rows, oversized lines, symlinks/FIFOs and overflow/boolean values.
Keep raw reports under ignored target/. Focused Python tests, full discovery,
required repository gates, separate code/evidence review and bounded deterministic
malformed-input mutations. No query-path performance or UI impact.

## Decisions and outcome

Implemented and accepted; resource/pass rules must follow current recorder, not
plausible invented semantics. Keep limitations visible in the operator contract.

## Outcome

Accepted after separate source/evidence review and required local, compatibility
and security checks. [Sprint 08 review](../reviews/sprint-08.md) records results,
review corrections and limits; current behavior is in the
[driver contract](../operations/soak-runner.md). Raw successful/failed fixtures and
identities stay under ignored target/review/sprint-08/.
