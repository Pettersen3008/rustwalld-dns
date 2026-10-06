# rustwalld-dns-policy

Assertion-gated immutable DNS policy compilation, client admission/selection,
rewrites, temporary exceptions and rule provenance. Serializable input values
remain editable; compiled snapshots expose read-only accessors.

```rust
use rustwalld_dns_policy::{PolicyConfigSet, PolicySnapshot};
let config = PolicyConfigSet::default();
let snapshot = PolicySnapshot::compile(config, 1)?;
let result = snapshot.explain("127.0.0.1".parse()?, "example.test")?;
assert_eq!(snapshot.generation(), 1);
assert_eq!(result.decision.action, rustwalld_dns_filter::Action::Allow);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Compile on a blocking/control executor. Required assertions must pass before a
snapshot is returned; `PolicySnapshot::check` reports all assertion outcomes
without publication. Generation identifiers are supplied by the host and must
never be reused for changed content. Rollback recompiles under a fresh identifier.
Snapshots contain bounded forwarding resources; compilation does not resolve DNS.
The library does not load files, start an HTTP server or open a database.
Rust 1.95+, edition 2024; MIT OR Apache-2.0.

With the optional `parallel` feature, `compile_parallel` and `check_parallel` use
an explicit `rustwalld_dns_filter::ParallelCompiler`. Keep the pool on the control
plane and bound concurrent compilation. The same validation and assertion gates
apply; default constructors remain sequential even when this feature is enabled.
