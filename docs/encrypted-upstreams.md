# DNS-over-TLS decision and verification plan

Authenticated DoT is the first encrypted transport slice. DoH has a separate
[HTTP contract](doh-design.md) for status/content-type/body limits, redirects,
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

Pipelining's local measurements and rehearsal are recorded in
[DoT pipelining](dot-pipelining.md). No zero-allocation claim is made.

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
