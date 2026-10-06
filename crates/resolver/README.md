# rustwalld-dns-resolver

Bounded DNS forwarding over UDP with TCP fallback, authenticated DNS-over-TLS
and HTTP/2 DNS-over-HTTPS. Includes TTL-aware positive/negative caches, inflight
coalescing, admission, endpoint diagnostics and retirement. No app or persistence.

```rust,no_run
use hickory_proto::{op::{Message, Query}, rr::{Name, RecordType}};
use rustwalld_dns_resolver::Forwarder;
# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let forwarder = Forwarder::new(vec!["127.0.0.1:5354".parse()?], std::time::Duration::from_secs(1))?;
let mut query = Message::query();
query.metadata.recursion_desired = true;
query.add_query(Query::query(Name::from_ascii("example.test.")?, RecordType::A));
let response = forwarder.resolve(&query).await?;
# Ok(())
# }
```

The example requires an explicitly configured local resolver. Wire questions
must use fully qualified DNS names (including the root dot). Replies are validated
against transaction, opcode and questions; transport connections, deadlines,
backoff and request concurrency are bounded. TLS verification requires a server
name and explicit trust policy. `Resolver` adds generation/policy-partitioned
caching and coalescing; cache keys must not be reused for changed policy content.
Call `Resolver::shutdown` when retiring a lifecycle. No zero-allocation claim is
made for complete requests. Rust 1.95+, edition 2024; MIT OR Apache-2.0.
