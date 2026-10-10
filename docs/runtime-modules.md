# Runtime modules and metric snapshots

The runtime keeps its public `store::Store`, durable result/error types,
`refreshes::Refresher` and `refreshes::run` paths. Internals are split by the
resource or lifecycle they own:

| Module | Responsibility |
| --- | --- |
| `store.rs` | Bounded async command handle and worker startup |
| `store/types.rs` | Existing durable revision/history DTOs and errors |
| `store/worker.rs` | Command dispatch, priority, history flush and shutdown drain |
| `store/schema.rs` | Private database files, WAL, schema migration, durability and SQL IDs |
| `store/history.rs` | Atomic event batches, retained row count and bounded history reads |
| `store/revisions.rs` | Policy pointers, revision reads, commits and retention |
| `store/metrics.rs` | Persistence counters and their read-only snapshot |
| `refreshes/types.rs` | Existing serialized status/queue/outcome values |
| `refreshes/schedule.rs` | Monotonic generation-bound deadlines and bounded manual admission |
| `refreshes/job.rs` | Job/permit lifetime, validators, content and completion accounting |
| `refreshes/worker.rs` | Conditional fetching and assertion-gated shadow staging |

Tests move into each module's `tests.rs`. SQL strings, revision identifiers,
serialization names, batch bounds, flush interval, command priority and durable
publication ordering are unchanged. Refresh synchronization, retirement handling,
permit ownership, retry deadlines and the rule that timers never promote remain
unchanged. No lock crosses an await or network operation.

`UpstreamHealth::snapshot()`, telemetry `Metrics::snapshot()`,
`ResolverMetrics::snapshot()` and `StoreMetrics::snapshot()` return public plain
structs. Counter fields are `u64`; latency/failure buckets are fixed arrays of
`u64`. Upstream samples also include the address and admission state, and expose
`failure_count(kind)`. External callers cannot mutate the shared atomics.
Existing read-only upstream `failure_count` and `admission_status` methods remain.

Each counter uses the same relaxed load as earlier diagnostics. Fields are
independent observations: concurrent updates may occur between reads. An upstream
sample reads admission state after counters under its existing short mutex. A
sample owns its values and does not change when later requests complete. It is
not a transactionally consistent view of every DNS worker.

The app reads one sample per metrics source or upstream and keeps the existing
Prometheus names, histogram bounds, JSON field names and failure classifications.
Examples, benchmarks and tests use the same public inspection boundary. Query-path
counter increments and resolver behavior are unchanged.

Verification includes a comparison of all 42 store and 24 refresh function bodies
before and after the move, preserving literals byte for byte (only metric read
adaptation is normalized), existing durability/corruption/retention/deadline and
cancellation regressions, and HTTP checks for the complete counter set, histogram,
upstream JSON shape and detached samples. Local evidence and required workspace
and Rust 1.95 gates live under `target/review/runtime-tidy/`.
