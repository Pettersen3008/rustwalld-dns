# Sprint 00 Workflow and documentation reset

Date: 2026-10-15. Goal: install a lean agent-owned delivery process and recoverably
consolidate documentation. Review identity: agent self-review; no independent or
human acceptance is claimed. DNS-001–003 are the reset stories. Sprint 01 remains
planned for Oct 19–25; none of its implementation stories have started.

## Outcomes

Shared AGENTS/CLAUDE instructions now cover scoped autonomy, engineering invariants,
local checks and honest acceptance. The process includes ranked stories, tasks,
specs, sprint planning, decisions, acceptance and review/retrospective. Performance,
code ownership and UI acceptance are explicit requirements. Routine choices are
delegated; merge/release/host authority remains unchanged.

Flat docs were consolidated into current architecture and operator contracts,
product scope, engineering guidance and lean planning records. The cleanup map
covers every prior docs path. Uncommitted/untracked originals are preserved in
`target/docs-reset-2026-10-15/before-docs.tar.gz`; this is a local ignored snapshot,
not a committed or remote archive. Licenses/security/support policy remain.

Release packaging now recursively includes current Markdown docs and shared
agent instructions. Its regression checks verify maintained paths, complete doc
coverage, manifest hashes and byte-identical repacking of the same built inputs.
New reusable tools check local Markdown links and emit descriptive source metrics.

## Acceptance evidence

Evidence directory: `target/docs-reset-2026-10-15/`; raw logs in checks/.

- `cargo fmt --all --check`: passed.
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`: passed.
- `cargo test --workspace --locked`: passed, 458 tests across 58 result groups.
- `python3 scripts/check-docs.py`: passed, 52 Markdown files, zero broken local links.
- `python3 -m unittest discover -s scripts/tests -v`: passed, 16 tests including
  link/metrics fixtures and deterministic package repacking.
- Source-integrity comparison: all existing Rust, web/src, fuzz and other runtime
  sources match the initial dirty tree. Existing non-Markdown changes from this
  task are limited to release.py, its deployment test and the Compose doc comment.
- Snapshot/path-map check: all 74 original docs have archived bytes and a current
  mapped destination. `git diff --check`: passed.

Packaging tests repack the existing release executable and console assets; they
prove current doc contents/manifests and deterministic repacking, not a fresh
production binary/console build. No runtime source or UI behavior changed here.
A fresh release build, browser visual work, benchmark reruns, security fuzzing and
native/container activation are outside this docs/tooling slice. DNS-004 requires
fresh current-source application/consumer/UI/performance evidence before expansion.
Native host, ARM, representative soak and independent security gates remain open.

## Review findings and corrections

Confirmed: hard-coded retired doc names would break bundle assembly. Fixed by
shipping the maintained tree and checking every doc in the archive.
Confirmed: consolidation initially retained earlier-version claims about current
imports, DS compatibility, schedules and service parameters. Corrected current
entry points and removed obsolete delivery reports while retaining versioned
semantics, limits and source interpretation references.
Confirmed: moved current-sprint and operator/source references can break navigation.
Checked local files/headings with a reusable offline command.
Concern resolved: a file's total line count includes inline tests; the filtering
story now explicitly distinguishes those from production logic.

## Quality and AI effectiveness

Before: 74 files in docs/, 649514 bytes; README was an extensive usage/evidence
ledger. After: 35 files, about 291 KB (55% fewer bytes). Exact final counts and source
integrity appear in metrics-after.json and source-integrity.json under the evidence
directory. The workspace has six
crates; the inventory is 189 Rust files/57782 physical lines and 33 web/src
files/9909 lines. These include tests/examples and are descriptive, not performance
or quality proof.

Existing large modules and complex policy UI became grounded backlog stories,
without changing their behavior during cleanup. No fresh runtime speed, allocation
or memory improvement is claimed. Prior local results remain historical.
Self-review found documentation/packaging issues before handoff; independent review,
external defect escape rate and agent velocity are unknown. No user intervention
was needed after the initial request. No generated LOC productivity claim.

## Retrospective and next planning

Helpful: inspect real code and release consumers before deleting docs; snapshot the
dirty tree; make one backlog the status authority; let routine specs proceed under
existing authority. Rework: initial consolidation retained too much slice history,
so current contracts needed another editorial pass.

Two actions:
1. Agent, DNS-004: establish current-source baseline and record all missing checks
   explicitly; success is reproducible command/source/fixture evidence.
2. Agent, DNS-007: inspect actual desktop/phone interactions before deciding UI
   changes; success is a ranked set of at most three reproducible operator issues.

Sprint 01 plans 7 relative points plus rework reserve, with no assumed velocity.
Structural work follows baseline acceptance; actual failures take priority. Later
host, hardware or external review work remains dependent on explicit access.
