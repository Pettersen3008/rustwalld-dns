# Code quality and ownership standards

Correct behavior, security, predictable latency and understandable modules are
required together. Do not add speculative abstractions, dependencies or configurable
modes without an actual story. Prefer deleting duplication to adding a framework.

## Rust structure

Use the [crate ownership map](../architecture.md). Libraries never depend on app;
DNS libraries never depend on runtime. Keep imports narrow and errors typed.
Pure matching/compilation must not acquire application responsibilities. HTTP,
credential/import parsing and SQLite belong in the outer layers. Every queue,
collection, connection pool, retry and retained report needs an explicit bound.

Aim for production modules below 500 lines; review any growth past 500 and split
by ownership before exceeding 800 where practical. Existing exceptions are debt,
not permission to split mechanically or hide code with includes. Do not introduce
new files above 1000 lines. Tests/fixtures and cohesive declarative CSS/catalogs
may be larger with an explicit rationale; prioritize readable structure over line
count. [Sprint 01](../planning/sprints/sprint-01.md) tracks observed existing debt.

Do not change public APIs just to move code. Preserve protocol, rule provenance,
immutable generations, cache identities and durable recovery during refactors.
Production forbids unsafe/unwrap/expect. Test allowances must be local and explicit.
No new lint suppression without a reason and narrower alternative considered.

## Frontend structure

Follow [web/README.md](../../web/README.md): app owns session/router, feature folders
own screens and workflows, components/ui owns small shared primitives, lib owns
API/schema helpers, styles owns semantic tokens. Keep feature-local behavior local;
extract shared components only when multiple callers share a real contract.
Use immutable draft updates and preserve session/draft ownership across navigation.

[Design acceptance](design.md) is part of Done. No dependency, polling loop,
telemetry field or query-path change solely to improve visual styling. Keep assets
local and preserve offline operation. Loading/error/empty/conflict states count.

## Repository hygiene

scripts/ contains reusable build, measurement and verification tools; extend an
existing harness before adding another. packaging/ owns install/container assets;
fuzz/ owns bounded parser targets and seeds. Generated datasets, recordings,
screenshots, binaries, raw metrics and scratch work belong in ignored target/.

Maintain current contracts in docs/architecture and docs/operations. Planning
belongs in docs/planning; implementation specs and durable decisions have separate
folders. Keep README as the quick start and navigation. Do not remove licenses,
attribution, security reporting or recovery instructions as “cleanup”.

Run `python3 scripts/check-docs.py` to check links and `python3 scripts/metrics.py`
for a descriptive source inventory. Size metrics do not prove quality, safety,
allocation counts or throughput. Review their deltas with observable behavior.
