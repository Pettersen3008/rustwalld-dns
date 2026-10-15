# Documentation cleanup and recovery

Reset date: 2026-10-15. Current contracts replace dated plans, duplicated delivery
ledgers and per-change measurement essays. Nothing here authorizes deletion of
unrelated source, test fixtures, licenses, credentials, caches or target/ artifacts.

## Recover old content

The exact pre-cleanup Markdown, including uncommitted and untracked pages, is saved
locally in `target/docs-reset-2026-10-15/before-docs.tar.gz`. Inspect with
`tar -tzf target/docs-reset-2026-10-15/before-docs.tar.gz`; extract into a temporary
directory under target/ to avoid overwriting current work. The adjacent inventory
records SHA256/size and git-status-before.txt records the original dirty tree.
The snapshot is ignored and local; copy it elsewhere before intentionally cleaning
target/ if that uncommitted historical content must survive. It is not a remote backup.

Previously committed versions remain accessible with `git log -- docs/PATH` and
`git show COMMIT:docs/PATH`. Git does not preserve the old uncommitted edits; the
local snapshot does. Legacy ADRs 001–003 lived in architecture/console/deployment
pages and were updated over time; their current contracts were consolidated.
ADR 0004 starts the immutable decision series.

## Old path to maintained context

Paths below are relative to docs/. “Performance” destinations retain methodology
and reusable reproduction tools, not all historical result tables. Raw historical
text remains in the snapshot/history. Read the current source before relying on it.

| Retired or rewritten path | Maintained context |
| --- | --- |
| `administration-design.md` | [architecture/security.md](architecture/security.md) |
| `architecture.md` | [architecture.md](architecture.md) |
| `badfilter.md` | [architecture/filtering.md](architecture/filtering.md) |
| `baseline.md` | [engineering/performance.md](engineering/performance.md) |
| `benchmarks.md` | [engineering/performance.md](engineering/performance.md) |
| `borrowed-decisions.md` | [engineering/performance.md](engineering/performance.md) |
| `cache-eviction.md` | [engineering/performance.md](engineering/performance.md) |
| `cache-forwarding.md` | [engineering/performance.md](engineering/performance.md) |
| `client-metadata.md` | [architecture/policy.md](architecture/policy.md) |
| `client-rule-scopes.md` | [architecture/filtering.md](architecture/filtering.md) |
| `client-tag-scopes.md` | [architecture/filtering.md](architecture/filtering.md) |
| `client-upstream-import.md` | [architecture/migration.md](architecture/migration.md) |
| `comparison.md` | [engineering/performance.md](engineering/performance.md) |
| `conditional-retrieval.md` | [architecture/feeds.md](architecture/feeds.md) |
| `console-design.md` | [engineering/design.md](engineering/design.md) |
| `container.md` | [operations/container.md](operations/container.md) |
| `control-plane-soak.md` | [engineering/performance.md](engineering/performance.md) |
| `cpu-query.md` | [engineering/performance.md](engineering/performance.md) |
| `denyallow.md` | [architecture/filtering.md](architecture/filtering.md) |
| `deployment-design.md` | [engineering/performance.md](engineering/performance.md) |
| `dnstype.md` | [architecture/filtering.md](architecture/filtering.md) |
| `doh-baseline.md` | [engineering/performance.md](engineering/performance.md) |
| `doh-design.md` | [architecture/upstreams.md](architecture/upstreams.md) |
| `doh-latency.md` | [engineering/performance.md](engineering/performance.md) |
| `dot-pipelining.md` | [engineering/performance.md](engineering/performance.md) |
| `downloaded-lists.md` | [architecture/feeds.md](architecture/feeds.md) |
| `ds-routing.md` | [architecture/local-dns.md](architecture/local-dns.md) |
| `embedding.md` | [architecture/embedding.md](architecture/embedding.md) |
| `encrypted-ingress.md` | [architecture/security.md](architecture/security.md) |
| `encrypted-resilience-baseline.md` | [engineering/performance.md](engineering/performance.md) |
| `encrypted-resilience.md` | [engineering/performance.md](engineering/performance.md) |
| `encrypted-upstreams.md` | [architecture/upstreams.md](architecture/upstreams.md) |
| `engine-split.md` | [engineering/performance.md](engineering/performance.md) |
| `filter-matching.md` | [engineering/performance.md](engineering/performance.md) |
| `filter-memory.md` | [engineering/performance.md](engineering/performance.md) |
| `homelab-product.md` | [product/scope.md](product/scope.md) |
| `integrations-design.md` | [operations/integrations.md](operations/integrations.md) |
| `management-ui.md` | [engineering/performance.md](engineering/performance.md) |
| `migration-parity.md` | [architecture/migration.md](architecture/migration.md) |
| `offline-policy-checks.md` | [architecture/policy-checks.md](architecture/policy-checks.md) |
| `open-source-refactor.md` | [engineering/performance.md](engineering/performance.md) |
| `operations.md` | [operations/install.md](operations/install.md) |
| `parallel-compilation.md` | [engineering/parallel-compilation.md](engineering/parallel-compilation.md) |
| `pattern-rewrite-import.md` | [architecture/migration.md](architecture/migration.md) |
| `privacy-design.md` | [architecture/security.md](architecture/security.md) |
| `property-tests.md` | [architecture/upstreams.md](architecture/upstreams.md) |
| `public-alpha.md` | [product/scope.md](product/scope.md) |
| `query-allocations.md` | [engineering/performance.md](engineering/performance.md) |
| `readiness-review.md` | [product/scope.md](product/scope.md) |
| `refactor-results.md` | [engineering/performance.md](engineering/performance.md) |
| `release-rebuild.md` | [engineering/performance.md](engineering/performance.md) |
| `releasing.md` | [operations/releasing.md](operations/releasing.md) |
| `resilience-baseline.md` | [engineering/performance.md](engineering/performance.md) |
| `rewrite-import-activation.md` | [architecture/migration.md](architecture/migration.md) |
| `rewrite-passthrough.md` | [architecture/local-dns.md](architecture/local-dns.md) |
| `rewrite-source-layout.md` | [architecture/migration.md](architecture/migration.md) |
| `roadmap.md` | [roadmap.md](roadmap.md) |
| `runtime-modules.md` | [architecture/embedding.md](architecture/embedding.md) |
| `rust-1.99-performance.md` | [engineering/performance.md](engineering/performance.md) |
| `safe-search.md` | [architecture/policy.md](architecture/policy.md) |
| `scheduled-refreshes.md` | [architecture/feeds.md](architecture/feeds.md) |
| `serve-stale.md` | [architecture/upstreams.md](architecture/upstreams.md) |
| `service-binding-records.md` | [architecture/local-dns.md](architecture/local-dns.md) |
| `service-blocking.md` | [architecture/policy.md](architecture/policy.md) |
| `service-catalog-v2.md` | [architecture/policy.md](architecture/policy.md) |
| `temporary-exceptions.md` | [architecture/policy.md](architecture/policy.md) |
| `tls-baseline.md` | [engineering/performance.md](engineering/performance.md) |
| `unbound.md` | [operations/integrations.md](operations/integrations.md) |
| `upstream-backoff-baseline.md` | [engineering/performance.md](engineering/performance.md) |
| `upstream-backoff.md` | [architecture/upstreams.md](architecture/upstreams.md) |
| `upstream-diagnostics-baseline.md` | [engineering/performance.md](engineering/performance.md) |
| `upstream-diagnostics.md` | [architecture/upstreams.md](architecture/upstreams.md) |
| `weekly-schedules.md` | [architecture/policy.md](architecture/policy.md) |
| `wildcard-rewrites.md` | [architecture/local-dns.md](architecture/local-dns.md) |
