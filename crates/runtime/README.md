# rustwalld-dns-runtime

Optional durable lifecycle and control service around `rustwalld-dns-core`.
Provides bounded SQLite/history workers, typed revisions, reviewed HTTPS filter
retrieval, refresh scheduling and backup verification. Hosts supply resolved
configuration values and executors; this crate owns no process signal handler,
HTTP server, CLI parser or global tracing setup.

```rust,no_run
use rustwalld_dns_runtime::{Runtime, RuntimeConfig};
use tokio_util::sync::CancellationToken;
# async fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
let runtime = Runtime::start(RuntimeConfig::default(), tokio::runtime::Handle::current()).await?;
let control = runtime.control().clone();
let stop = CancellationToken::new();
// The host cancels this token during shutdown; use a separate DNS executor in production.
runtime.run(stop).await?;
# Ok(())
# }
```

`start` validates, restores durable active/shadow revisions, and binds DNS without
serving. `run` supervises DNS/refresh work until cancellation, stops mutation
admission, drains admitted durable operations, then stops history persistence.
Dropping is best-effort cancellation; await `run` for graceful shutdown.

`ControlService` supports assertion reports, staged active/shadow revisions,
promotion through `Candidate::Shadow`, clear and historical drafts. Rollback stages
a historical configuration under a fresh generation. Admitted commit/publication
continues when a caller cancels. SQLite failure leaves live policy unchanged.
A durable commit precedes infallible publication. HTTP status/ETag mapping belongs
to the host adapter. Schema and management behavior match the standalone appliance.
Rust 1.95+, edition 2024; bundled SQLite requires a C toolchain. MIT OR Apache-2.0.

The optional `parallel-compilation` feature provides `Runtime::start_with_compiler`.
Pass an `Arc<rustwalld_dns_filter::ParallelCompiler>` to share one explicitly
bounded pool across bootstrap, active/shadow restoration, assertion checks and
admitted staging. Compilation stays on blocking/control workers. Awaited shutdown
still drains admitted commit/publication; externally retained control handles or
compiler Arcs keep the idle pool alive until they are dropped. `Runtime::start`
and independently constructed `ControlService` values remain sequential.
