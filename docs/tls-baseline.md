# DNS-over-TLS baseline

Automation note (2026-10-06): GitHub Actions and `.github/` were removed at
the maintainer's request. References to CI below describe historical verification;
run the documented commands locally and retain artifacts under `target/`.

Measured 2026-10-05 on AMD Ryzen 7 9800X3D (8 cores / 16 threads), Linux
7.2.5-3-omarchy x86_64, rustc 1.98.1. Cargo release profile uses thin LTO and one
codegen unit. These are local exchange measurements on a shared, unpinned
workstation, not appliance-wide latency percentiles or Internet resolver capacity.

```sh
cargo bench -p rustwalld-dns-resolver --bench tls --locked -- \
  --warm-up-time 1 --measurement-time 2 --sample-size 20
```

A local Tokio TLS server presents a generated ECDSA certificate for resolver.test;
the client verifies it against an explicit fixture root. One A query / exchange,
no cache or coalescing, one outstanding client exchange. Hickory parses each reply.
Both peers set TCP_NODELAY. No public DNS is contacted. Warm exchanges reuse one
socket; cold exchanges use a fresh client/session cache and include TCP connection,
full TLS handshake, authenticated DNS exchange and forwarder/socket disposal.
Configuration/root compilation is excluded from cold measurements.

Final Criterion time estimates (linear-regression slope, 95% confidence intervals):

| Exchange | Estimate | Confidence interval |
|---|---:|---:|
| Warm socket | 13.818 µs | 13.599–14.114 µs |
| Cold TCP + TLS + DNS | 213.39 µs | 211.34–216.49 µs |

These are approximately 15× apart for this workload. They were captured after the
final socket-retirement change. Raw logs: target/tls-benchmark-final.log; Criterion JSON/plots:
target/criterion/dot_loopback. These generated artifacts are intentionally ignored
by Git; CI uploads Criterion results. The cold/warm comparison motivates bounded
reuse, not a strict network performance gate. No allocation, CPU/query or RSS
measurement was made for this transport; no zero-allocation claim is made.

Functional evidence includes trusted warm reuse; wrong-name, untrusted and expired
certificate rejection; 32 parallel successful exchanges through a two-connection
pool; timeout/cancel recovery; malformed DNS framing/content and truncation
rejection; sequential TLS fallback; a UDP observer detecting no plaintext fallback;
and real UDP client queries through TLS with filtering, cache hits, concurrent
miss coalescing and fresh generations after identity changes. Browser tests cover
TLS validation and durable shadow staging on desktop and mobile. The clean Debian
container smoke also validates an OpenSSL CA-signed leaf, warm reuse through the
installed non-root binary, and TLS revision recovery after backup/upgrade/restore.
Final gates: 41 Rust tests, 12 browser tests, five packaging tests; clippy/fmt,
audit/deny and npm audit pass. Final fuzz runs: 2,009,901 TLS configuration inputs
and 826,010 DNS inputs, each over 21 s, without a reported crash. These short runs
are regression evidence, not exhaustive security testing.

The full workspace, clippy, formatting, audit/deny, browser and deployment checks
are recorded in target/tls-*.log. During initial validation one maintenance test
process stalled; it was stopped, and a fresh workspace run plus ten repeated
parallel maintenance runs passed. The stall was not reproduced or attributed to
this transport change. This initial implementation is not a production soak test.
