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

A short mutex owns only idle sockets. Each admitted exchange owns its socket
across awaits; a semaphore limits active + idle sockets to 1..8 per address.
Existing global inflight admission bounds waiting requests. One exchange at a
time per connection avoids response demultiplexing complexity; a small pool
provides concurrency. Pipelining is a later measurement-driven option.

The per-address deadline includes pool admission, TCP connect, TLS handshake and
DNS exchange. Cancellation/error discards the socket. A stale reused socket may
retry once on I/O failure within that same deadline, on that same TLS endpoint.
Invalid DNS is never retried on its connection. Idle reuse expires after 60 s;
expired sockets are closed when selected for checkout, or when the snapshot is released.
There is no task that retains a retired generation just to reap idle sockets.
At most 32 profiles × 8 addresses × 8 sockets can be retained in one snapshot;
inflight queries may briefly retain an older snapshot during publication.

Hickory remains the DNS parser. Two-byte length framing limits responses to
65,535 bytes. ID, question, opcode, response direction, signatures and truncation
are checked using the existing validation contract. Cached responses partition
by upstream profile and immutable generation, including changed trust/identity.

An actor owning multiplexed connections was considered. Exclusive checkout is
smaller and makes timeout/cancellation safe without a second pending-query table.
It deliberately gives up pipelining; benchmark warm versus cold TLS before adding
that complexity. No zero-allocation claim is made.

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
