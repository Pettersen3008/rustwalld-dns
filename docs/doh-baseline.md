# DNS-over-HTTPS baseline

Automation note (2026-10-06): GitHub Actions and `.github/` were removed at
the maintainer's request. References to CI below describe historical verification;
run the documented commands locally and retain artifacts under `target/`.

Measured 2026-10-05 on AMD Ryzen 7 9800X3D (8 cores / 16 threads), Linux
7.2.5-3-omarchy x86_64, rustc 1.98.1. Cargo release uses thin LTO and one codegen
unit. The workstation is shared and unpinned. These are local transport exchange
measurements, not appliance-wide latency percentiles or Internet resolver capacity.

```sh
cargo bench -p rustwalld-dns-resolver --bench https --locked -- \
  --warm-up-time 1 --measurement-time 2 --sample-size 20
```

A loopback Tokio/rustls/h2 server presents a generated ECDSA certificate for
resolver.test. The client authenticates it against an explicit fixture root and
requires h2 ALPN. Both peers set TCP_NODELAY. Each exchange sends one POST wire
message and validates/parses the DNS reply, without cache/coalescing. One client
exchange is outstanding. Tests and benchmarks never query public DNS.

Warm exchanges reuse one authenticated HTTP/2 connection. Cold exchanges use a
fresh client and TLS session cache, including TCP connection, full TLS handshake,
HTTP/2 setup, DNS exchange and signaling driver cancellation on forwarder drop.
Actual driver/socket retirement completes asynchronously on the runtime.
Configuration/root compilation is outside the cold timing window.

Final Criterion time estimates (linear-regression slope, 95% confidence intervals):

| Exchange | Estimate | Confidence interval |
|---|---:|---:|
| Warm HTTP/2 connection | 16.083 µs | 16.006–16.152 µs |
| Cold TCP + TLS + HTTP/2 + DNS | 240.44 µs | 237.87–243.19 µs |

Raw log: target/doh-benchmark-final.log; Criterion JSON/plots:
target/criterion/doh_loopback. Generated artifacts are ignored by Git; CI uploads
Criterion results. The approximately 15× cold/warm difference supports bounded
connection reuse for this workload. It does not justify a strict network CI
performance gate. Allocations, CPU/query and RSS were not measured for this
transport; no zero-allocation claim is made. One outstanding exchange per
connection is the initial contract; multiplexing needs separate measurements.

Functional evidence: trusted/wrong-name/untrusted/expired certificate handling,
missing h2 ALPN, warm reuse and remote close recovery; 32 concurrent exchanges
through two connections; stalled handshake/headers/body and cancel recovery with
a one-connection cap; bounded headers/bodies with and without Content-Length;
malformed/mismatched/trailing DNS, invalid HTTP envelopes and protocol-error retry
rejection; sequential fallback, no redirect/plaintext leakage; HTTP Age including
overflow expiry and negative SOA lifetimes. Real UDP DNS queries verify filtering,
response-cache hits, duplicate-miss suppression, client ID restoration, generation
isolation and retirement. Browser tests cover HTTPS validation and shadow staging
on desktop and mobile without changing live filtering.

Final source gates: 53 Rust tests and 14 browser tests; fmt, Clippy, cargo audit,
cargo deny, frontend formatting/build and npm audit pass. Final bounded fuzz runs:
968,495 HTTP envelope/DNS response inputs, 1,896,347 TLS configuration inputs and
1,278,956 DNS inputs, each over 21 s, with no reported crash. These short runs are
regression evidence, not exhaustive security testing or operational soak evidence.
Logs are retained in target/doh-*.log.

Five packaging tests pass, including deterministic repacking and manifest checks.
The clean Debian container smoke installs the real binary/console as a non-root
service user, verifies warm CA-signed DoT and HTTP/2 DoH through UDP/TCP clients,
and preserves the HTTPS revision through WAL backup, upgrade and restore. Runtime
networking is isolated with `--network none`; no host service is installed.
Native systemd sandbox activation remains a deployment-host check. The smoke
validates unit syntax and process identity rather than starting systemd.
