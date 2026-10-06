# rustwalld-dns-core

Embeddable DNS policy engine and bounded UDP/TCP server. Hickory handles the DNS
protocol. The host owns executors, cancellation, credentials and policy storage;
the query path performs no filesystem, database, management or JSON work.

```rust
use rustwalld_dns_core::{Engine, EngineConfig, PolicyConfigSet, PolicySnapshot,
    PublicationTarget, Telemetry};
let snapshot = PolicySnapshot::compile(PolicyConfigSet::default(), 1)?;
let (telemetry, _events) = Telemetry::channel(128);
let (engine, controller) = Engine::controlled(snapshot, EngineConfig::default(), telemetry);
let candidate = PolicySnapshot::compile(engine.snapshot().config().clone(), 2)?;
let pending = controller.prepare(candidate, PublicationTarget::Active, controller.version())?;
// A durable host commits its revision here, before publication.
pending.commit();
assert_eq!(engine.active().generation(), 2);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Compile complete generations off the DNS executor. The separate controller
checks versions, serializes writers and burns reserved generation identifiers.
Aborting a reservation leaves live policy unchanged. Restoring durable state must
include the highest retired revision identifier; caches start empty. Publication
never waits on persistence. Requests already holding a snapshot may finish under
that generation. Active publication clears shadow state.

`Engine::answer` accepts a wire message and client address; `Server::bind` plus
`Server::run(CancellationToken)` provides bounded ingress and graceful retirement.
Events use a bounded channel and may be dropped under pressure; aggregate counters
record drops. Keep history consumers off DNS workers. See the `embedded` example.
No app, Axum, SQLite or JSON dependency. HTTP/2 dependencies implement DoH forwarding.

The current protocol contract refuses transfers, ANY, non-IN, signed queries,
nonrecursive requests and unknown EDNS options. Unsupported requests are not
silently forwarded. Zero cache capacities disable caching; hosts must select
finite sensible capacities and isolate DNS/control executors for latency.
Rust 1.95+, edition 2024; MIT OR Apache-2.0.
