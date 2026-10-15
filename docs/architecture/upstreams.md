# Upstream transport caching and failure handling

## DNS-over-TLS

Authenticated DoT uses bounded persistent connections. DoH has its own
[HTTP contract](upstreams.md) for status/content-type/body limits, redirects,
HTTP/2 pooling and cancellation. Existing UDP/TCP profiles and stored revisions remain
readable; absent `transport` means UDP with TCP fallback.

`resolver` owns TLS and pooled sockets. `policy` compiles identity, certificate
roots and pool bounds before publication, without connecting to any server.
Each profile uses explicit bootstrap IP:port addresses and one DNS authentication
name. Sequential fallback tries these addresses using TLS only. Providers with
different certificate names require separate profiles. There is no opportunistic
plaintext downgrade, implicit hostname resolution or certificate bypass.

Use tokio-rustls/rustls with an explicit ring provider and safe TLS versions.
Bundled Mozilla roots avoid operating-system trust loading during queries. An
optional inline public CA PEM replaces those roots for private resolvers; parsing
is bounded to 64 KiB / 32 certificates and occurs during compilation. Certificate
chain, validity and hostname checks remain enabled. CA changes require a revision.

Each pooled connection pipelines at most eight queries, following
[RFC 7766 section 6.2.1.1](https://www.rfc-editor.org/rfc/rfc7766.html#section-6.2.1.1).
A short mutex holds the pending map; no lock spans an await. One driver owns
both TLS halves: its reader matches complete Hickory-decoded replies to waiters
by message ID, and its writer consumes a bounded eight-frame channel. Request
admission is limited to eight times the configured physical connection count.
The driver retains the physical permit until both socket halves are dropped.

IDs start at a random offset, advance without reuse, and retire the connection
after the 65,536th reservation. Cancellation immediately removes the caller's
pending entry and marks the connection suspect, preventing new admissions.
Existing waiters finish; their cancelled siblings' late replies are discarded
using at most eight tombstones. The driver closes when a suspect connection
has no pending queries. Malformed/truncated/signed/trailing DNS data, mismatched
questions/opcodes and unsolicited or duplicate IDs fail every pending query
and close the connection. Invalid content is never retried.

The per-address deadline includes request admission, physical admission, TCP
connect, TLS handshake and DNS exchange. A reused connection lost to I/O may
retry once under that same deadline. `Notify` signals released capacity, with
a bounded periodic recheck for cancellation races. Idle reuse expires after
60 seconds on checkout. Dropping the pool aborts remaining drivers; `Drop` never
spawns tasks. Drivers retain connection state, not a policy generation.
At most 32 profiles × 8 addresses × 8 sockets can be retained in one snapshot;
inflight queries may briefly retain an older snapshot during publication.

Hickory remains the DNS parser. Two-byte framing bounds responses to 65,535
bytes and strict decoding consumes the entire frame. Cached responses partition
by upstream content identity, including changed trust/identity. No public
configuration or durable revision format changed. A writer behind an async
mutex was considered; a bounded channel gives one socket owner without holding
any lock across network I/O.

Reproduce pipelining measurements with the resolver TLS benchmarks and encrypted
failure rehearsal. See [methodology](../engineering/performance.md).

Evidence required: local TLS servers verify warm reuse, pool bounds, trusted and
untrusted/expired/wrong-name certificates, stalled handshakes/replies, reconnect,
malformed/mismatched responses, cancellation, sequential fallback, and retirement.
Real DNS tests exercise filtering, caching and generation invalidation with TLS.
Criterion records cold and warm exchanges against a loopback TLS fixture; public
DNS is never queried by tests or benchmarks. Existing Rust/browser gates, audit,
deny and DNS fuzzing remain required.

References reviewed: [RFC 7858](https://www.rfc-editor.org/rfc/rfc7858.html)
(connection framing/reuse), [RFC 8310](https://www.rfc-editor.org/rfc/rfc8310.html)
(strict privacy and authentication domain names), and
[tokio-rustls](https://docs.rs/tokio-rustls/0.26.6/tokio_rustls/).

The trust-anchor data is CDLA-Permissive-2.0, permitted only for `webpki-roots`
in deny.toml. Its full license ships in release bundles as LICENSE-WEBPKI-ROOTS.
PEM decoding uses the maintained `rustls-pki-types::pem::PemObject` API; the
unmaintained rustls-pemfile wrapper is deliberately excluded.

## DNS-over-HTTPS

Goal: add a complete authenticated DoH upstream slice while retaining the DNS
pipeline, bounded admission, sequential fallback and immutable generations.
Done means local HTTPS tests, real DNS/cache/generation tests, console validation,
security gates and reproducible cold/warm measurements pass.

An explicit `transport.kind = "https"` profile contains a certificate DNS name,
POST path, optional inline CA PEM, and 1..8 connections per bootstrap IP:port.
Compile trust and HTTP URIs off the DNS executor. Reuse existing TLS validation;
require negotiated ALPN h2. There is no runtime hostname lookup, plaintext or
HTTP/1 fallback, redirect following, proxy environment handling, cookie store,
or GET/JSON DNS dialect. Existing UDP and TLS revisions remain readable.

Update (2026-10-10): DoH now multiplexes requests; see "Multiplexing" below. The
original single-stream design is kept here for context.

`resolver` owns HTTP/2 via h2/http/bytes and tokio-rustls. A short mutex contains
only idle connection handles. An admitted exchange exclusively owns a handle;
one outstanding request per connection deliberately avoids a second multiplexed
pending-query/admission implementation. A small connection pool supplies initial
concurrency. HTTP/2 multiplexing remains an option after measurements demonstrate
benefit. A reqwest client was considered but its connector, redirect, environment
and pool behavior give less direct control over these bounds.

Each connection has one driver task owning its physical-connection permit. An
abandoned/error connection aborts that task; the permit releases only when the
TLS socket is actually dropped. This prevents cancellation/replacement from
exceeding the cap. Idle handles do not keep a retired snapshot alive: dropping
the pool aborts its drivers. Old queries may finish on old generations. The
per-address deadline covers request admission, physical-slot admission, connect,
TLS/HTTP2 handshake, headers and body. One stale-connection retry stays on that
same encrypted endpoint under that same deadline. Invalid content is not retried.

HTTP/2 receive windows are 65,535 bytes, frames 16 KiB, decoded headers 16 KiB,
HPACK table 4 KiB, send buffers 65,535 bytes, reset bookkeeping bounded, and server
push disabled. Responses require 2xx status, one application/dns-message media
type, identity/no content encoding, and a DNS body of 12..65,535 bytes. Bodies
are streamed with explicit length bounds; redirects/status errors never resolve
a different hostname. HTTP Age subtracts from TTLs before the DNS cache; negative
SOA TTL is first clamped to min(SOA TTL, MINIMUM). Malformed/duplicate Age and
length fields fail. Numeric Age overflow saturates to expire DNS TTLs, following
RFC 9111 delta-seconds rules. Hickory handles wire parsing and existing response matching;
DoH query ID is zero, and client IDs are restored by the DNS engine.

Verification: trusted/wrong-name/untrusted/expired certificates; missing h2 ALPN;
warm reuse and connection limits; stalled handshake/headers/body, cancellation,
reconnect and retired drivers; malformed DNS and HTTP envelopes; oversized bodies
with/without Content-Length, headers; sequential fallback with no redirect or
plaintext leakage; Age semantics including negative caching; real DNS filtering,
cache hits, coalescing and generation changes; browser edit/stage workflow.
Fuzz bounded HTTP envelope/DNS decoding separately from socket state. Criterion
uses only local HTTPS fixtures; no public DNS traffic or zero-allocation claims.

Primary references reviewed: [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484.html)
(POST wire bodies, ID zero, HTTP status/media type, TTL/Age),
[h2 client Builder](https://docs.rs/h2/0.4.19/h2/client/struct.Builder.html)
(explicit HTTP2 bounds), existing tokio-rustls and DoT trust contracts.

### Multiplexing

Measured benefit, so multiplexing replaces exclusive checkout:

- A connection carries up to eight concurrent requests (`STREAMS_PER_CONNECTION`).
  Request admission per address is `max_connections × 8`, and physical sockets
  stay bounded by `max_connections`. h2 additionally honours the server's
  `SETTINGS_MAX_CONCURRENT_STREAMS`. Before those settings arrive, one stream is
  opened at a time.
- New requests take the least-loaded live connection with free stream capacity,
  or open a connection while a physical slot is free. Otherwise they wait for a
  capacity notification (rechecked every 25 ms as a safety net), never on the
  physical semaphore, so capacity freed elsewhere is used at once.
- Streams are independent: a cancelled or failed request resets only its own
  stream. A request abandoned without an HTTP answer (deadline or transport
  failure) marks its connection suspect. New requests avoid it, and the socket
  closes after its remaining streams finish, so a server stuck on one
  connection is replaced as before.
- Retry once, within the original deadline:
  - A `REFUSED_STREAM` (never processed, RFC 9113 §8.7) retries on any
    connection.
  - A stale reused connection (I/O error or graceful GOAWAY) retries on a new
    connection.
  - Invalid DNS content is never retried.
- Each connection's receive window is eight full DNS messages, so concurrent
  large answers cannot block each other.

## Bounded upstream failure admission

The measured malformed-response outage spent most sampled DNS-worker user CPU
in cryptographic leaf routines. Reconnecting for every new uncached name repeated
that work without increasing availability. The resolver now limits retries at the
endpoint boundary; filtering, cache hits and immutable snapshot publication do
not enter this gate.

### Contract

Each compiled endpoint owns one fixed-size state and a short mutex. Three
consecutive qualifying completions open a 250 ms cooldown. Requests skip a
cooling or probing endpoint and continue sequential fallback without waiting.
If all endpoints are skipped, DNS returns SERVFAIL, which is never cached.
After cooldown, the next request admits one recovery probe. A qualifying probe
failure backs off to 500 ms, 1 s, then at most 2 s. There are no background probe
tasks, endpoint maps, allocated timers or locks spanning an await/network I/O.
A successful probe restores normal admission and resets delay. Recovery is
traffic driven and can be delayed by the cooldown plus the configured exchange
deadline; generation publication creates fresh state.

Qualifying failures: connection/I/O, TLS authentication/protocol, HTTP protocol,
status/envelope, or rejected DNS replies. Certificate and response validation
remain mandatory, including for probes. SERVFAIL and REFUSED are validated,
query-specific outcomes: they reset a qualifying streak and restore a probing
endpoint but still trigger fallback for that query. Cancellation, local encoding
errors and deadlines do not penalize an endpoint. Deadlines include local pool
waits and cannot currently distinguish remote stalls from local admission delay.
Stall-only outages therefore keep the existing bounded timeout/fallback behavior.

Completions carry an epoch. Attempts already in flight when cooldown begins
cannot reset or extend it; late completions cannot release a newer probe. The
attempt guard releases a cancelled probe for the next query without increasing
its delay. Completed transport failures still contribute to diagnostic counters
regardless of epoch. Existing admitted requests may finish normally, including
on a retired generation. Counters are generation scoped.

### Observability and verification

The upstream API exposes backoff_skips, recovery_probes and admission state
(ready/cooldown/probing plus retry_after_ms). These are separate from attempts
and failures: skipped work was never an endpoint attempt. An elapsed cooldown
still reports cooldown with zero remaining milliseconds until traffic probes it.
Live API reads remain nontransactional; at quiescence attempts equal successes
plus all fixed failure counters. No query identities are stored in admission.

Deterministic clock-injected state tests cover maximum delay, stale completions,
one-probe exclusion, domain-specific outcomes and cancellation. Real local TLS
and HTTP/2 tests exercise bad DNS, fallback, fresh generations, simultaneous
queries, a stalled/cancelled probe and validated recovery. The process rehearsal
reconciles attempts + skips with lookups and keeps setup recovery outside its
latency windows. See upstream-backoff-baseline.md for measured results.

A meaningful alternative was a global retry budget or retrying each request.
A global gate would couple healthy profiles and clients; per-query retries retain
the measured handshake storm. Fixed endpoint state is simpler and isolates
failures without racing queries across public providers. Configurable strategy,
stall-stage classification and proactive health checks are deferred until needed.

## Upstream failure diagnostics

A failed endpoint exchange used to disappear behind the final `Unavailable`
error. Preserve a fixed set of reasons in the resolver and show their counters in
`GET /api/v1/upstreams` and the console. DNS behavior, sequential fallback,
certificate verification and retry limits remain unchanged.

### Ownership and accounting

`resolver::FailureKind` has twelve categories: deadline, connection, TLS
authentication, TLS protocol, HTTP protocol, HTTP status, HTTP envelope, DNS
response, SERVFAIL, REFUSED, cancellation and local error. Each endpoint owns a
fixed atomic array plus attempts, successes, inflight and successful-latency EWMA.
No query names, error strings, unbounded labels or per-query logs are retained.
Serialization and display happen in the control plane.

An attempt starts when an endpoint is selected, including waiting for admission
into its connection pool. Its RAII guard records exactly one success or failure;
dropping an unfinished endpoint future records cancellation. A coalesced lookup
can outlive its original client; client departure alone does not count as an
endpoint cancellation. At quiescence:

    attempts = successes + sum(failures)
    inflight = 0

Individual relaxed atomic reads are live observations, not a transactional
snapshot. A success can follow a failure; historical failures do not mean that an
endpoint is currently down. Success latency excludes failed attempts. A stale
warm-connection retry remains part of the same endpoint attempt.

Deadline includes pool admission, connection, handshake and response time. TLS
certificate errors use rustls typed errors, never message matching. Missing h2
ALPN is TLS protocol; h2 resets/protocol faults are HTTP protocol. Non-2xx status
is HTTP status. Invalid media type, encoding, Age, length or oversized body is
HTTP envelope; malformed/mismatched/truncated DNS is DNS response. UDP still
ignores unsolicited malformed/mismatched packets until its deadline, so those
attempts end as deadline rather than trusting an invalid packet's reason.

Counters belong to immutable-generation resolver profiles. The API includes the
active generation. Promotion/rollback creates fresh counters; requests pinned to
old generations finish and update the old profile. Blocked, rewritten, cached
and single-flight follower queries do not start endpoint attempts.

A dynamic map or structured per-failure log on the DNS path would retain richer
errors but adds allocation, cardinality and persistence pressure. Fixed counters
provide bounded diagnostics without those dependencies. No schema migration or
configuration change is needed; API fields are additive.

### Verification

Exercise local UDP, TLS and HTTP/2 faults, sequential fallback, cancellation,
recovery, cached/blocked traffic and generation replacement. Check the accounting
identity only after work finishes. Real HTTP and desktop/mobile browser tests
verify the public API and display. Run the workspace gates, dependency audit/deny,
targeted DoH fuzzing and the real-process encrypted failure rehearsal.

## Serve-stale contract

Opt-in [RFC 8767](https://www.rfc-editor.org/rfc/rfc8767.html) fallback is a
startup cache setting, independent of revisioned policy. Zero disables it.
`ServeStale` validates a private duration capped at one day; engine/library
callers cannot construct an unchecked enabled window. Runtime/app configuration
uses `serve_stale_max_staleness_secs`, validated before serving.

The normal minimum-RR-TTL expiry remains unchanged. The bounded CLOCK cache
retains expired entries until replacement/eviction; they count towards the same
capacity and no extra stale map exists. Eligible expired answers use TTL 30 for
all records. Each caller checks staleness after the upstream flight fails;
coalesced callers cannot receive a stale result pinned before the retention
boundary. Stale reads do not update insertion/expiry times. Valid positive and
SOA-backed negative entries share this behavior. AD remains clear.

Policy runs before cache lookup, using the pinned immutable generation. After
an upstream wait, the engine rechecks temporary allowances, caps TTLs to their
remaining lifetime, and restores blocking if the exception expired. Stale does
not bypass rewrites/blocks or cross the existing upstream identity/question/DO/CD
cache key. `rustwalld_stale_answers_total` increments only after that final policy
check, and telemetry/history use source `stale`. Console cache filters and traffic
counts include stale answers, while the query path column retains `stale`.

Only `Forwarder::resolve` exhaustion triggers fallback. Flights distinguish
upstream failure from shutdown; logical overload, server shedding and shutdown
return SERVFAIL. No background refresh, per-query control-plane work, extra
connection race or new network deadline is introduced. An uncacheable completed
refresh invalidates the old key, preventing resurrection of known superseded
data. Errors and invalid envelopes leave the old state intact, as required by
[RFC 8767 section 4](https://www.rfc-editor.org/rfc/rfc8767.html#section-4).
BoundedCache removal swaps the last slot into the released position and
updates its index/clock hand; existing CLOCK insertion/hit behavior is preserved.
The default-off path does not introduce a new forwarding-key clone.

Tests use local UDP fixtures for real warming, expiry, SERVFAIL/timeouts,
successful fallback and recovery. They cover default off, coalesced replies,
blocks/rewrites after publication, changed upstream identity, temporary TTL caps
and a prepared query finishing after expiry, overload/shedding/shutdown, and
zero-TTL refresh invalidation. Synthetic-time cache tests cover exact retention
boundaries, immutable stale deadlines, all TTLs, capacity/eviction and DO/CD
partitions. Configuration tests cover omission, zero, the one-day limit and
rejection above it. Evidence lives under `target/review/serve-stale/`.

## Cache and encrypted-pool model tests

Proptest 1.11 is a resolver dev-dependency with only `std` enabled. Normal
resolver dependencies do not include it. Failure persistence goes directly to
ignored `target/review/property-tests/`, with a reproducible RNG seed supported
through `PROPTEST_RNG_SEED`.

The CLOCK oracle is a linear rotating queue with reference bits. All generated
keys collide into one uniformly sized shard, so exact hit/replacement/eviction
results can be compared without reproducing the hash-table/slot-index/clock-hand
implementation. Capacities include zero. A separate plain-map oracle checks
borrowed-key removal, replacement and regrowth, with enough capacity for the
entire generated key domain. Existing concurrent multi-shard tests and targeted
cache fuzzing continue to check bounded churn and removal with eviction.

Pool traces vary one to three physical connections, up to six rounds, one to
40 simultaneous callers per round, arbitrary cancellation masks and cancellation
delays. Zero cancels before first poll; later delays exercise connection setup,
capacity waits, active exchanges and completion races. A cancelled call may have
finished already; every surviving call must return its own question and expected
answer. Each round must finish with all request permits free and no pending
claims, then resolve a fresh probe successfully. This is the liveness witness for
capacity stranded by cancellation. Per-claim test assertions check DoT pending
and DoH stream limits, with additional observations while requests run.

After every trace, all forwarder/pool owners are dropped. The local peer must
observe every connection close, all physical permits must return, and all request
permits must remain free. Drivers/fixtures are local, with independent 10 ms
reply delays and sufficient server stream capacity. No public DNS or wall-clock
latency assertion is involved. These are finite randomized lifecycle tests,
complementing deterministic out-of-order/malformed/lost-connection regressions;
they are not an exhaustive scheduler proof.

Default cache models run 128 cases each, and pool models 32 each. Expand locally:

```sh
PROPTEST_CASES=128 PROPTEST_RNG_SEED=20261010 \
  cargo test --locked -p rustwalld-dns-resolver --lib properties
```
