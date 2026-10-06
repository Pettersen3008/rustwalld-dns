# Management-failure resilience baseline

Measured 2026-10-05 on a shared, unpinned workstation. These are observations for
this workload, not absolute capacity claims or a strict network CI performance
gate. Other build/fuzz activity was possible; no allocation or CPU/query claim.

Hardware: AMD Ryzen 7 9800X3D, x86_64; Linux7.2.5-3-omarchy; Rust1.98.1.
Measured binary SHA-256: `a35de072596986787ebb683b2e9cfe2b31acf3b8effa9dc5e41a5f86aaae4abf`.

Release profile: thin LTO, one codegen unit. Real child appliance with separate
DNS/control runtimes, real SQLite and a loopback-only mock upstream. Four clients
alternate `blocked.test` and warmed `cached.test` A queries without think time.
Each phase lasts five seconds. Telemetry queue16 deliberately forces drops.

| Phase | DNS replies | p50 µs | p95 µs | p99 µs | p99.9 µs | Timeouts / wrong answers |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Baseline | 2,164,614 | 8 | 13 | 15 | 21 | 0 / 0 |
| 48 stalled HTTP request bodies | 2,160,153 | 8 | 13 | 15 | 22 | 0 / 0 |
| 200,001-rule candidate | 2,154,417 | 8 | 13 | 15 | 21 | 0 / 0 |
| SQLite write lock | 2,121,735 | 9 | 13 | 16 | 27 | 0 / 0 |

HTTP admission returned429; persistence-dependent publication returned503. Active
generation remained1, shadow generation2, cache contained one upstream answer,
and total upstream exchanges remained one (warm-up). All blocked/cache probes
stayed local. The candidate HTTP request lasted107ms inside its five-second DNS
sample window; the table does not isolate only that shorter overlap interval.
SQLite lock held for the entire persistence-failure phase. Counters after that
phase: 8,598,725 dropped telemetry events and291 failed history-event writes.
Drops were deliberately expected with a queue of16, not a recommended production
queue sizing result. No DNS failure counter increments were recorded.

Reproduce:

```
cargo build -p rustwalld-dns --release --locked
cargo run -p rustwalld-dns --release --example resilience --locked -- --binary target/release/rustwalld-dns --duration-ms 5000 --output target/resilience.json
```

The harness also asserts packet ID, question and response-code correctness, the
expected cached A record, failed publication, generation retention, telemetry
loss and bounded request admission. It sends no public DNS queries. Raw JSON and
command logs are under ignored target/resilience*. CI retains its smaller smoke
report separately. Longer adversarial traffic, physical disk exhaustion, actual
native systemd sandbox activation and a dedicated latency runner remain separate
verification; this result does not prove isolation under every resource failure.
