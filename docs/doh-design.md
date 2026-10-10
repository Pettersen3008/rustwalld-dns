# DNS-over-HTTPS transport decision

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

## Multiplexing (2026-10-10)

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

Evidence: `crates/resolver/benches/https.rs`, `doh_concurrent` group. The
loopback mock answers after 10 ms and allows 100 streams per connection; two
connections per address. AMD Ryzen 7 9800X3D, Linux 7.2, Rust 1.99.0, cores 4–9.

| Concurrent queries | Exclusive checkout | Multiplexed | Throughput |
| ---: | ---: | ---: | ---: |
| 8 | 44.45 ms | 11.19 ms | 180 → 715 queries/s |
| 32 | 177.77 ms | 22.41 ms | 180 → 1,428 queries/s |

Single-query `doh_loopback` warm and cold timings did not regress (−2% and −4%).
New tests prove that requests overlap on at most two connections and that a
refused stream is retried; both fail on the previous implementation. Raw output
is kept in `target/review/doh-mux/`.

The encrypted-resilience fixture historically advertises just one HTTP/2 stream.
Its 22 ms versus 11 ms DoT p99 disappears at `--https-streams 100` with the same
daemon binary; see [the measured diagnosis](doh-latency.md).
