# Embedding and runtime ownership

## Embedding and component use

Use `rustwalld-dns-core` for a DNS engine without the appliance. Use
`rustwalld-dns-runtime` when the host also wants the existing durable revision,
reviewed download and history workflows. Filter and resolver are independently
usable. All public APIs are documented by `cargo doc`; crate READMEs contain
checked examples.

Before registry publication, a sibling checkout can depend on:

```toml
[dependencies]
rustwalld-dns-core = { path = "../rustwalld-dns/crates/dns-core" }
tokio = { version = "1.53", features = ["rt-multi-thread", "macros", "net", "time"] }
tokio-util = { version = "0.7", features = ["rt"] }
```

Rust 1.95+ is required. A pinned Git revision of the public repository is another
option; use registry versions only after the separate crates.io publication.
The core reexports high-level policy inputs and telemetry so a host can build
its engine without importing app. Direct protocol use also requires Hickory.
HTTP/2 libraries in core's dependency tree implement encrypted DNS forwarding;
Axum, SQLite, TOML loading and serde_json are absent.

For an engine lifecycle:

1. Build configuration as values. Resolve file paths/secrets and validate listener
   admission in the host. Compile `PolicySnapshot` on a blocking/control executor;
   never compile or parse filters on the DNS executor.
2. Create bounded `Telemetry::channel`, then `Engine::controlled` with named cache
   and inflight bounds. Keep the returned `PolicyController` on the control plane.
   Events are best-effort; a full/closed channel cannot stall queries.
3. Share the engine with `Arc` and either call `answer` from host ingress or bind
   `Server` on a DNS executor. `ServerConfig` bounds UDP work, TCP connections and
   deadlines. Loopback/allowed-client restrictions still apply.
4. Compile a complete candidate with a fresh generation. Capture/check
   `PolicyVersion`, call `prepare`, persist if required, then `commit`. Aborting
   leaves active state unchanged and burns the ID. No control mutex spans awaits.
   Shadow publication changes telemetry comparisons, not DNS answers. Active
   publication clears shadow. Rollback recompiles old content with a new ID.
5. Cancel the server token and await its task. Resolver flights and connections
   retire within their configured bounds. Standalone `answer` users own their
   request task lifecycle and must call resolver shutdown when retiring the engine.

`Engine::restore` takes validated durable active/shadow snapshots plus the highest
revision identifier, including retired revisions. It starts with empty caches.
The host must not reset that high-water mark to the active ID. Never reuse a cache
partition for changed content. Snapshot accessors allow inspection without raw
ArcSwap writes or mutation of compiled configuration.

For durable reuse, `Runtime::start(RuntimeConfig, dns_handle)` validates/restores
SQLite and binds DNS. Obtain `runtime.control()` to attach host management UI or
commands. Run `Runtime::run(host_cancel)` on the control runtime and await it on
shutdown. Admitted staging continues when its caller cancels; shutdown drains
commit/publication before stopping SQLite. Dropping the runtime is best-effort
cancellation, not a substitute for awaited drain. The host owns signals, global
logging and HTTP authentication. A separate control executor protects DNS from
filter compilation, management and disk failure.

For large lists, enable filter/policy `parallel` or runtime `parallel-compilation`
and construct one `ParallelCompiler` on the control plane. `compile_parallel` /
`check_parallel` preserve policy gates; `Runtime::start_with_compiler` shares the
owned pool across bootstrap, restoration and admitted edits. Existing constructors
remain sequential. Bound concurrent compilation and leave CPU capacity for DNS;
see [workload and memory measurements](../engineering/parallel-compilation.md).

`ControlService` exposes typed errors/results; the app adapter preserves current
HTTP status codes and canonical ETags. Historical rollback reads a typed revision
and stages its config under a new ID. No persistence trait or plugin system is
needed for the current concrete SQLite workflow.

[Independent core tests](../../tests/consumers/core/src/lib.rs) exercise UDP/TCP,
blocking/allow precedence, shadow/active updates, stale versions, telemetry and
two independent engines against local mocks. [Component tests](../../tests/consumers/components/src/lib.rs)
import filter/resolver without app. [Runtime tests](../../tests/consumers/runtime/src/lib.rs)
exercise a locked SQLite commit, caller cancellation, awaited shutdown and restart.
`scripts/verify-crates.py` reruns these against extracted crate archives.

This makes reuse in Rustwalld possible, but does not verify its dependency graph,
listener ownership or shutdown model. A subsequent integration should choose core
or runtime, check Tokio/Hickory/Rustls feature compatibility, allocate bounded
executors and connect existing host configuration/events. No files in
`~/Work/rustwalld` are changed by this refactor.

## Runtime modules and metric snapshots

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
