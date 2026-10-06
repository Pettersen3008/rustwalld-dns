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
