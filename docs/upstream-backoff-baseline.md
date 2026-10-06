# Upstream admission baseline

Measured 2026-10-05 on AMD Ryzen 7 9800X3D, x86_64 Linux, rustc 1.98.1.
Shared, unpinned workstation; all resolvers and traffic were loopback fixtures.
Two DNS workers, separate control runtime, two clients per blocked/cache/fresh
lane, 80 ms endpoint deadlines and two warm connections per address.

Before production binary SHA256: 5039f4adef40ba62c1ecd63d06f7c515f0629f49ee6d3af954b015e69966a9c3
After production binary SHA256: f877bd843bcbeeb581711659fc1b73ce869d85b3ba82ad53e003addb83c1f940

Harness examples were built separately, followed by the production-only binary.
Builds, browser tests, containers and profilers were stopped during measured runs.

| Transport / phase | Blocked p99 before / after (µs) | Cache probe p99 before / after (µs) |
|---|---:|---:|
| tls / baseline | 15 / 16 | 16 / 16 |
| tls / outage | 153 / 21 | 153 / 21 |
| tls / outage-stall | 15 / 15 | 16 / 16 |
| tls / recovery | 15 / 15 | 16 / 16 |
| tls / post-promotion-recovery | 15 / 15 | 16 / 16 |
| https / baseline | 15 / 16 | 16 / 16 |
| https / outage | 163 / 25 | 163 / 25 |
| https / outage-stall | 15 / 16 | 16 / 17 |
| https / recovery | 15 / 17 | 16 / 17 |
| https / post-promotion-recovery | 16 / 16 | 16 / 16 |

Five-second malformed-outage phases: TLS attempts fell from 16,309 per endpoint
to 8/7; HTTPS from 15,313 to 7/8. Cooling/probing endpoints were skipped instead
of repeatedly opening TLS connections. Fresh outage queries now usually receive
an immediate SERVFAIL; those failures are never cached. This is an intentional
admission/recovery behavior change, not an identical upstream-work benchmark.

All recorded phases in both five-second runs and the reverse-order two-second
repeat completed with zero incorrect replies, timeouts or histogram clips. The
repeat cache-probe p99 was 149→21 µs TLS and 167→21 µs HTTPS. New endpoint
attempts in that repeat were 7/7 TLS and 6/7 HTTPS. The five-second changed run
performed 43 promotions per transport with pinned old-generation completion.
Peak sockets remained 5 (cap 8), inflight 4 (cap 32), cache 64 (cap 64), native
threads 7; RSS peaks were 12,580 KiB TLS and 13,280 KiB HTTPS. Threads are not
Tokio tasks, samples are not exact peaks between polls, and RSS is not rule size.

Raw artifacts: target/backoff-baseline-{before,after}.{json,log} and
target/backoff-repeat-{before,after}.{json,log}. Reproduce with:

```sh
cargo build --release --locked -p rustwalld-dns --example encrypted_resilience
cargo build --release --locked -p rustwalld-dns --bin rustwalld-dns
target/release/examples/encrypted_resilience --binary target/release/rustwalld-dns \
  --duration-ms 5000 --output target/backoff-rehearsal.json
```

The rehearsal restores primary readiness before each timing window. Secondary
cooldown may carry across consecutive failure modes, deliberately exercising
real state continuity; it is recovered before the pinned-retirement fixture.
Two failed process smoke attempts during harness adaptation exposed outdated warm-up
and retirement assumptions. They were setup failures, not excluded timing runs;
only completed, reconciled runs above support the performance comparison.

These runs demonstrate the local target under this workload, not a statistical
10% regression gate, CPU/query, zero allocations, kernel attribution or long
production soak. No new allocator claim is made. Deadline-only stalls retain
bounded timeout/fallback and can include local pool admission. See
upstream-backoff.md for eligibility and traffic-driven recovery limits.
