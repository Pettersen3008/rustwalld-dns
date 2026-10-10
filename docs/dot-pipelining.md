# DoT pipelining evidence (2026-10-10)

DoT now multiplexes eight pending queries per connection instead of exclusively
checking out each socket. The reader matches complete validated messages by ID;
out-of-order completion is supported. The physical pool limit, endpoint deadline,
certificate policy and sequential fallback are unchanged. See
[the connection contract](encrypted-upstreams.md).

## Criterion

AMD Ryzen 7 9800X3D, Linux 7.2, Rust 1.99.0, release optimization, shared unpinned
workstation, the same benchmark, reply delays and certificate configuration.
Fixture changes add counters and an optional concurrent rehearsal mode. Each batch starts concurrent
queries against a local server that delays each reply by 10 ms independently;
two connections per address. Criterion uses a 1 s warm-up, 2 s measurement and
10 samples for concurrent batches. No public DNS, builds or other test jobs run
during measurements.

| Scenario | Exclusive checkout | Pipelined |
| --- | ---: | ---: |
| Eight concurrent queries, 10 ms fixture | 44.403 ms | 11.171 ms |
| 32 concurrent queries, 10 ms fixture | 177.61 ms | 22.396 ms |
| One warm query, no fixture delay | 11.940 µs | 12.866 µs |
| One cold query, no fixture delay | 215.55 µs | 222.43 µs |

Concurrent batches improve by about 75% / 87%. Warm single-query cost increases
about 0.9 µs (8%); cold increases about 6.9 µs (3%). Cold includes TCP, a full TLS
handshake and driver setup; root/config compilation is excluded. The first
candidate cold sample was noisy (340.51 µs, interval 307–381 µs); an isolated
repeat with the same code measured 222.43 µs (221–224 µs). Both logs are retained.
These are loopback timings, not absolute production performance or allocation
claims.

```sh
cargo bench --locked -p rustwalld-dns-resolver --bench tls -- \
  --warm-up-time 1 --measurement-time 2
```

## Failure rehearsal

The TLS fixture now accepts pipelined requests and independently delays replies;
its historical serial fixture remains available for comparison. HTTPS advertises
100 concurrent streams. Both transports still deliberately wait 10 ms per
successful query. All fault phases, old-generation pinned requests, promotions
and durable recovery use the real child daemon. The historical DoH stream-limit
comparison remains in [its diagnosis](doh-latency.md).

```sh
cargo build -p rustwalld-dns --release --locked
cargo run -p rustwalld-dns --release --example encrypted_resilience --locked -- \
  --binary target/release/rustwalld-dns --duration-ms 5000 --https-streams 100 \
  --output target/review/dot-pipelining/encrypted-resilience.json
```

The five-second-per-phase run returned 17,999,011 TLS and 21,747,584 HTTPS
replies with zero client timeouts, incorrect replies or histogram clips. Every
fixture endpoint has zero active connections after exit. There were 46 TLS and
47 HTTPS promotions with pinned old-generation requests and durable recovery.
The daemon SHA-256 is
`bed7434d45566a0d8214fa23b4f7e7b66b5d6dab4a24e98fa62211bc8e357878`.

| Phase fresh-query p99 | TLS | HTTPS |
| --- | ---: | ---: |
| Baseline | 12.8 ms | 11.1 ms |
| Primary stalled | 95.1 ms | 91.9 ms |
| Primary malformed DNS | 11.6 ms | 11.1 ms |
| Primary reset | 11.1 ms | 11.1 ms |
| Both stalled | 162.9 ms | 163.1 ms |
| Recovery | 11.1 ms | 11.8 ms |
| Recovery after promotions | 11.1 ms | 11.1 ms |

Sampled upstream sockets peaked at four TLS / eight HTTPS (workload cap eight),
then quiesced to one each before exit. Cache entries stayed within 64 and
inflight work peaked at four, within its limit of 32. Sampling alone does not
prove every instantaneous bound; cancellation/capacity tests check the pool's
lifecycle separately. Malformed-outage cache-probe p99 was 22 µs for both.

Local fmt, workspace all-target/all-feature Clippy, workspace tests, Rust 1.95
check, cargo audit and cargo deny pass. The strict DoT decoder and TLS
configuration targets ran for 30 seconds each (about 1.9M / 2.7M executions)
without failures. Regression tests cover out-of-order responses, late cancelled
replies, all-waiter failure on connection loss/malformed/unknown IDs, bounded
admission and cancellation recovery, pool disposal and lifetime ID exhaustion.

Results and local verification are retained under `target/review/dot-pipelining/`.
