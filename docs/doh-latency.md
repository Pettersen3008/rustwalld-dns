# DoH rehearsal latency diagnosis (2026-10-10)

The 22 ms HTTPS versus 11 ms TLS fresh-query p99 comes from the local HTTPS
fixture's advertised concurrency, rather than TLS setup, Nagle, flushing or
HTTP/2 byte flow control. `Mock::start` advertises
`SETTINGS_MAX_CONCURRENT_STREAMS = 1`. The pool shares an established connection
between the two fresh-query clients; h2 correctly queues the second stream until
the first finishes. Each fixture reply waits 10 ms, which Tokio rounds to about
11 ms on this machine. Each client therefore observes about two fixture waits.
The DoT fixture uses two independent connections before pipelining is added.

Controlled full rehearsals used the **same daemon binary**, SHA-256
`332ca3e45526a973f50e7189cab05dc1d6a3de197e9c41552178341825d21f3a`,
Rust 1.99.0, AMD Ryzen 7 9800X3D, Linux 7.2, four fixture workers and two DNS
workers. Five seconds per phase, two clients per lane, otherwise identical
configuration; no concurrent builds or other test jobs. Only the HTTPS fixture's
stream setting changed:

| Advertised HTTPS streams per connection | TLS fresh p99 | HTTPS fresh p99 | HTTPS baseline fresh replies |
| ---: | ---: | ---: | ---: |
| 1 (historical fixture) | 11.1 ms | 22.1 ms | 456 |
| 100 | 11.1 ms | 11.1 ms | 910 |

The same improvement appears in recovery, malformed-primary/fallback and reset
phases. Both rehearsals have zero client timeouts, incorrect replies and clipped
samples; every endpoint has zero active connections after exit. These are local
rehearsal results, not a production throughput claim.

No production transport change is warranted by this experiment: neither its
socket setup nor byte windows nor request/response flushing changed, and their
combined overhead fits inside the 11.1 ms result. Both transports already set
`TCP_NODELAY`, and the small DNS messages fit well below the HTTP/2 stream and
connection byte windows. The regression test
`fixture_stream_limit_controls_overlap_on_a_warm_connection` verifies one warm
connection, three successful exchanges, peak overlap of one versus two, and
closure after dropping the forwarder, without a latency assertion. A deliberately
restrictive server can still serialize streams assigned to one connection; this
measurement does not promise optimal connection distribution for every server
setting.

The rehearsal now accepts `--https-streams 1..100` and records the setting in its
JSON report. The default remains 1 to preserve historical comparisons. Use 100
for the multiplexing rehearsal:

```sh
cargo build -p rustwalld-dns --release --locked
cargo run -p rustwalld-dns --release --example encrypted_resilience --locked -- \
  --binary target/release/rustwalld-dns --duration-ms 5000 --https-streams 1 \
  --output target/review/doh-latency/streams-1.json
cargo run -p rustwalld-dns --release --example encrypted_resilience --locked -- \
  --binary target/release/rustwalld-dns --duration-ms 5000 --https-streams 100 \
  --output target/review/doh-latency/streams-100.json
```

Evidence and verification logs are under `target/review/doh-latency/`. Parser,
security and dependency gates are unchanged by this fixture-only investigation.
