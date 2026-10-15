# DNS engine architecture

The workspace has six crates: five reusable libraries and the standalone app.
Hickory owns DNS wire parsing/serialization. Tokio owns bounded network work.
The management plane compiles and persists policy without stalling DNS workers.

| Crate and folder | Owns | Dependency boundary |
| --- | --- | --- |
| rustwalld-dns-filter, crates/filtering | Pure compiled matching, source provenance | No app/runtime dependencies |
| rustwalld-dns-resolver, crates/resolver | Validated upstream exchanges, raw cache, coalescing, encrypted pools | No app/runtime dependencies |
| rustwalld-dns-policy, crates/policy | Client selection, assertions, local records, immutable policy snapshots | Composes filter/resolver; no app/runtime |
| rustwalld-dns-core, crates/dns-core | Engine, admission, response synthesis, publication and UDP/TCP ingress | Composes policy/filter/resolver; no app/runtime/SQLite/management JSON |
| rustwalld-dns-runtime, crates/runtime | Durable revisions, SQLite/history, downloads, scheduling, lifecycle | Uses DNS libraries; never imported by them |
| rustwalld-dns, crates/app | Files, CLI, authentication, import, HTTP/console and process wiring | Outer application layer |

The React console lives in `web/src/` by feature. Tests, examples and benchmarks
live with the crate whose observable contract they exercise. Independent host
consumers are in `tests/consumers/`; parser fuzz targets are in `fuzz/`.

Core's engine facade owns configuration, snapshots and opaque pending state.
Private engine modules own admission, local/cache decisions, forwarding,
outcome/shadow evaluation and wire handling. These retain the same pinned state
and public API; transport admission and controller publication remain separate.

## Query lifecycle

Admission accepts one supported IN question and pins the immutable generation and
source client context. Local answers and compiled filters run without control-plane
I/O. Allow rules override blocks. Cache hits and coalesced waiters avoid constructing
an unused forwarding envelope. A new admitted upstream flight constructs a fresh
request; client EDNS options are ignored, never forwarded. DO/CD participate in
cache semantics; replies clear AD because the engine does not validate DNSSEC.

Resolver exchanges validate ID, QR, opcode and complete question. UDP truncation
falls back to TCP; encrypted profiles authenticate their configured identities
without plaintext downgrade. Timeouts, sockets, connection/stream pools, frame sizes,
cache entries and inflight keys have explicit bounds. No lock crosses await/I/O.

Raw cache identity includes canonical question/type/class, resolver content and
DO/CD. Cache complete validated messages; never promote unsolicited additional
records into independent entries. Positive expiration uses minimum RR TTL;
negative caching requires SOA and min(SOA TTL, SOA MINIMUM). Decrement all TTLs.
Final policy blocks never enter the raw upstream cache. Optional stale answers
are considered only after upstream failure and retain expiry/resource bounds.

Filter decisions partition by immutable generation, policy, required qtype and
compiled client/tag equivalence class. Reachable response CNAME/value inspection,
exception expiry and schedule transitions recheck before final synthesis. Pending
work retains its original generation. Best-effort telemetry uses bounded try_send;
storage, JSON, parsing and plugin execution never enter this path.

## Publication and persistence

The controller validates revision/generation high-water marks and reserves a new
publication without holding a mutex across I/O. Compile and assertion checking
run off DNS executors. Runtime persists the revision/pointer before infallible
ArcSwap publication. Aborts burn identifiers. Active publication clears shadow;
rollback compiles a fresh generation. Startup accounts for retired durable IDs
and starts with empty caches. A query keeps its pinned snapshot across promotion.

SQLite failure rejects management mutations while the last good DNS generation
continues. History is bounded, best-effort NORMAL transactions; revision/pointer
commits use FULL. Privacy has its own durable revision and logging flag; auth
credentials are separate private state. Neither is policy export data. Shutdown
stops ingress, drains bounded work, cancels refreshes and drains admitted durable
publication before storage stops. The host owns executors and signal handling.

## Read the affected contract

[Filtering](architecture/filtering.md), [local DNS/routes](architecture/local-dns.md),
[policy controls](architecture/policy.md), [migration](architecture/migration.md),
[feeds](architecture/feeds.md), [transports/cache](architecture/upstreams.md),
[security/privacy](architecture/security.md), [embedding](architecture/embedding.md)
and [API/limits](architecture/api.md) contain the detailed bounds and compatibility.

The original ADRs 001–003 were living documents covering the data plane, console
and deployment. Their current contracts are consolidated here, in
[design](engineering/design.md) and [operations](operations/install.md).
[ADR 0004](decisions/0004-agent-workflow.md) starts the immutable decision series;
future accepted ADRs are superseded with a new record rather than rewritten.
