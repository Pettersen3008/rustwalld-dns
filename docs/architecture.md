# ADR 001: a small forwarding data plane

Automation note (2026-10-06): GitHub Actions and `.github/` were removed at
the maintainer's request. References to CI below describe historical verification;
run the documented commands locally and retain artifacts under `target/`.

Status: accepted, initial implementation. Goal: local-first DNS policy/security
engine with a control plane that cannot stall DNS on storage or compilation.

Use stable Rust, Tokio and Hickory Proto 0.26 for wire parsing/serialization.
Hickory owns compression, RR encoding and truncation. Use ordinary bounded,
sharded caches before considering packed tries, custom parsers or lock-free maps.
Tokio's sockets need no mutex around network I/O. Axum 0.8 will own the API.
The resolved versions are recorded in Cargo.lock.

Ownership: `rustwalld-dns-core` owns ingress, response synthesis and admission;
`rustwalld-dns-resolver` owns validated forwarding, caches and coalescing;
`rustwalld-dns-filter` owns normalized exact/suffix rules and provenance;
`rustwalld-dns-policy` compiles client prefixes, filter/upstream profiles and
assertions into immutable generations. The optional `rustwalld-dns-runtime`
owns SQLite/history, typed revisions, downloads, scheduling and explicit lifecycle.
App owns file/config loading, HTTP/console adapters and CLI formatting; its binary
owns process signals and tracing setup. No DNS library depends on runtime or app.

A separate `PolicyController` checks versions and generation high-water marks,
then reserves publication without holding a mutex across I/O. The durable service
persists first; reservation commit performs infallible ArcSwap publication.
Aborting burns the identifier and leaves live state unchanged. Rollback compiles
a fresh generation; startup includes retired durable identifiers and empty caches.
Queries never acquire the control mutex and retain their original snapshot while
an update is published. Compiled snapshot fields cannot be mutated externally.
Active publication clears shadow state. See [embedding](embedding.md).

Compiled temporary exceptions additionally have a bounded one-way expiry bit:
observed wall-clock expiry cannot be reversed by a clock jump. Their absolute
and monotonic deadlines do not depend on a control-plane timer. See
[temporary exceptions](temporary-exceptions.md).

Filter domains share immutable `Arc<str>` storage between rules and matcher keys;
provenance shares one list-name allocation per list. Query lookup borrows `&str`
without reference-count operations. The logical payload estimate is compiled
once so management status reads do not scan entire rule sets. This replaces
measured duplicate string storage while retaining ordinary maps, rule IDs and
source lines. See [filter memory measurements](filter-memory.md).

Forwarding is sequential fallback, never unsolicited racing. Each exchange uses
a randomized ID and an OS-selected ephemeral connected UDP socket; validate ID,
QR, opcode and the complete question before accepting it. Retry truncation via
TCP. Bound the entire exchange, listeners, connections, frames, cache, inflight
keys and telemetry. Refuse nonrecursive requests, updates, transfers and signed
queries; only one IN question is supported. Unknown EDNS options are refused
until their cache/forwarding semantics are implemented. Pass DO/CD explicitly;
clear AD: this server does not perform DNSSEC validation.

Accepted TCP streams use TCP_NODELAY once per connection. DNS length/payload are
separate writes; disabling Nagle prevents an observed delayed-ACK stall between
them on persistent connections. Admission, frame/deadline bounds and protocol
handling remain unchanged. See [matched wire measurements](comparison.md).

Default DNS/API binds are loopback and unprivileged. Non-loopback DNS listeners
require explicit client CIDRs. Management binds must remain loopback for now.
Reject direct self-upstreams; indirect forwarding loops are bounded by timeouts
and admission, and must also be prevented by operators.

Alternative: hickory-server/resolver could manage forwarding and caching for us.
Use hickory-proto with explicit transport code to make admission, cache keys,
response validation and policy boundaries inspectable. This increases protocol
responsibility; local packet regression tests and fuzz targets are required.

Cache complete validated upstream messages, not independently extracted records:
never promote unsolicited additional records to separate cache entries. Cache key
includes canonical name, type, class, upstream profile, DO/CD and generation.
Expire conservatively at the minimum RR TTL, decrement every TTL on hits, and
cache NXDOMAIN/NODATA only with SOA, using min(SOA TTL, SOA MINIMUM) (RFC 2308).
Keep final policy answers out of the upstream cache. Coalesced work must survive
one waiter's cancellation and release its slot after timeout/completion.
Construct the owned canonical forwarding message only for an admitted upstream
flight. Cache hits and coalesced waiters derive the existing semantic key from
the accepted client request without building an unused forward; DO/CD remain
keyed and client question/size restoration stays in the engine. See
[forwarding allocation measurements](cache-forwarding.md).
Decision-cache hits borrow the normalized domain plus policy/generation, creating
owned keys only on misses. Sharded maps use hashbrown's safe equivalent-key API
with explicit `RandomState`; FIFO capacity and lock boundaries remain intact.
See [borrowed decision measurements](borrowed-decisions.md).

CPU accounting lives only in a Linux benchmark example. Shared fixture builders
keep Criterion and CPU scenarios aligned; the CPU executable excludes allocation
instrumentation. Proc reads, setup and reporting stay outside measured queries
and production libraries. See [CPU/query methodology](cpu-query.md).

Hot-path telemetry uses try_send; database work and JSON never run in Engine.
The SQLite worker counts retained history through its compact index and trims
only excess oldest rows. It preserves sparse IDs and atomic batches, while
avoiding a full newest-row walk on every small batch. Matched paced comparisons
measure this control-plane CPU improvement; burst history remains best-effort.
Once policy/shadow matching finishes, query telemetry takes ownership of the
normalized name buffer. Rewrites and temporary allows avoid unused decision-key
construction. The parser, cache representations and telemetry admission remain
unchanged; see [query allocation measurements](query-allocations.md).
Compilation, policy assertions and persistence complete before atomic promotion.
SQLite unavailability must reject management changes without disrupting the
active generation. Shadow evaluates a candidate without changing DNS answers.
Offline/API checking shares a private snapshot builder with strict compilation,
but returns only bounded assertion diagnostics. Unchecked snapshots cannot be
returned through this diagnostic API. See [policy checks](offline-policy-checks.md).
Downloaded-list metadata stays in configuration; matching still consumes the
same compiled list structures. A control-plane HTTPS fetch produces a checked
draft, never a live snapshot or independently persisted feed registry. Downloads
have separate bounded admission from mutations and pin destination IPs; stale
previews retain the caller's original revision tag. See
[reviewed lists](downloaded-lists.md).
Client/subnet annotations are optional revisioned configuration. A sparse
network-to-config index serves control-plane explanations; the DNS selection
maps and telemetry remain free of group, owner, VLAN-label, tag and note data.
Only the winning binding's metadata is reported; labels never affect admission
or create policy inheritance. See [client metadata](client-metadata.md).

Verification: local mock authoritative UDP/TCP servers; A/AAAA/CNAME, truncation,
malformed/compression loops, mismatched IDs/questions, timeout/fallback, SOA
negative TTL, cache partitioning, burst coalescing/cancellation, reload under
traffic, telemetry saturation and graceful shutdown. No public DNS is needed for
tests. fmt, clippy and workspace tests are mandatory after each working slice.

Primary references (reviewed 2026-10-05):
- https://docs.rs/hickory-proto/0.26.3/hickory_proto/
- https://docs.rs/tokio/1.53.2/tokio/net/
- https://docs.rs/axum/0.8.9/axum/
- https://www.rfc-editor.org/rfc/rfc1035 (wire format, UDP limits)
- https://www.rfc-editor.org/rfc/rfc7766 (TCP support/framing)
- https://www.rfc-editor.org/rfc/rfc5452 (response matching)
- https://www.rfc-editor.org/rfc/rfc2308 (negative caching)
- https://www.rfc-editor.org/rfc/rfc6891 (EDNS)
- https://www.rfc-editor.org/rfc/rfc9619 (one question)

## Authenticated upstream transport

Explicit `transport.kind = "tls"` or `"https"` profiles compile rustls trust/identity state
before publication. Resolver-owned bounded socket pools reuse warm encrypted connections
with exclusive checkout and cancellation-safe disposal. Bootstrap IPs avoid
recursive hostname resolution; strict certificate checks and sequential TLS-only
fallback avoid silent downgrade. See [TLS decision](encrypted-upstreams.md).
HTTPS uses POST wire messages over authenticated HTTP/2 with explicit header/body
bounds, TTL/Age validation and separately bounded driver/socket lifetimes. See the
[HTTPS decision](doh-design.md). Management HTTP remains outside the DNS executor.

Opt-in downloaded-list schedules run in one app worker sharing bounded HTTPS
admission with manual previews. Changed bytes use the existing assertion/durable
shadow publication path; generation preconditions reject stale fetches. Shadows
pause further checks and require explicit promotion. Runtime deadlines/status
are bounded and independent of DNS. Shutdown cancels fetches and drains admitted
publication before SQLite stops. No timer, source lookup or additional lock is
added to DNS workers. Existing shadow evaluation retains its normal cost. See
[scheduled refreshes](scheduled-refreshes.md).

Scheduled retrieval may use bounded conditional HTTP validators tied to publisher
identity/trust and a stored content fingerprint. Hints cannot validate edited
live text or a dismissed shadow's bytes. Generation/content validation and changed
candidate clones run off executor. HTTP 304 changes only runtime status; no
compilation, durable write or snapshot swap. Restart uses a full GET. See
[conditional retrieval](conditional-retrieval.md).
