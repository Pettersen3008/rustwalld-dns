# Upstream diagnostics baseline

Measured 2026-10-05 on AMD Ryzen 7 9800X3D (8 cores / 16 threads), Linux
7.2.5-3-omarchy x86_64, rustc 1.98.1. Shared unpinned workstation; release thin
LTO and one codegen unit. The saved pre-change daemon and the diagnostic daemon
ran sequentially with no concurrent build, browser test or fuzz job. Ordinary
desktop activity remained. This single paired run is not a statistical regression
gate or a hardware-independent throughput claim.

Both runs use five seconds per phase, two loopback UDP clients per blocked/cache
probe/fresh-name lane, two DNS workers, four local encrypted endpoints, 80 ms
per-endpoint deadlines and two connections per address. The saved harness omits
new diagnostic API checks; the new harness reads them outside timed phases.
The final binary is the production-only release build packaged by release.py.
An earlier diagnostic build also selected examples, which unified dev features;
its different hash and preliminary results are retained in
`target/diagnostics-resilience-after.json` but are not the final shipping results.
`target/diagnostics-resilience-shipping.json` is an additional correctness run
that overlapped the container check; it is excluded from this latency comparison.
The final shipping rehearsal ran with all other checks idle.
Cache probes include occasional FIFO misses and deliberate promotion misses.
Timing, histogram bounds and resource sampling are described in
[encrypted resilience](encrypted-resilience.md).

Before daemon SHA-256: `c3752505e50e193909bf94cf22f3fd0846580b1d15db6f7201e2d478748e7a6f`.

After daemon SHA-256: `5039f4adef40ba62c1ecd63d06f7c515f0629f49ee6d3af954b015e69966a9c3`.

Raw artifacts: `target/diagnostics-before/resilience.json`,
`target/diagnostics-resilience-final.json`; short CI-shaped run:
`target/diagnostics-resilience-ci.json`. These are local generated evidence,
not required tracked fixtures.

Observed p99 microseconds (before → after):

| Phase | TLS blocked | TLS cache probe | HTTPS blocked | HTTPS cache probe |
|---|---:|---:|---:|---:|
| Healthy | 15 → 18 | 16 → 19 | 15 → 21 | 16 → 22 |
| Primary malformed DNS | 16 → 21 | 17 → 22 | 22 → 17 | 24 → 18 |
| Primary reset/close | 17 → 22 | 17 → 23 | 17 → 17 | 17 → 17 |
| Both malformed DNS | 151 → 173 | 152 → 173 | 164 → 165 | 165 → 165 |
| Both stall | 15 → 19 | 16 → 19 | 15 → 15 | 16 → 16 |
| Concurrent promotions | 16 → 18 | 16 → 20 | 15 → 15 | 16 → 16 |
| Recovery after promotions | 16 → 16 | 16 → 17 | 15 → 16 | 16 → 16 |

The malformed-outage cache-probe target remains unmet (150 µs). TLS cache-probe
p99 in the final five-second comparison increased from 152 to 173 µs; HTTPS was
165 µs in both runs. This cannot establish a statistically significant regression
from one workstation pair. Short repeats below help characterize variation, but
no claim of regression-free performance or a selected mitigation is made.

After-run evidence:

| Transport | Replies | Promotions | Peak RSS KiB | Peak sockets / limit | Peak inflight / limit |
|---|---:|---:|---:|---:|---:|
| TLS | 14,881,295 | 25 | 12,412 | 5 / 8 | 4 / 32 |
| HTTPS | 19,333,376 | 28 | 13,452 | 5 / 8 | 4 / 32 |

Every lane had zero timeouts, incorrect replies or histogram clipping. Each
steady phase reconciled attempts with successful exchanges plus the fixed reason
counters. Malformed-outage attempts recorded DNS-response failures on both
endpoints; stalled attempts recorded deadlines; TLS closes recorded connection
errors and h2 resets/oversized headers recorded HTTP-protocol errors. Recovery
after publication had zero failure counters in the new generation. Old requests
finished without contaminating it. Cache entries remained within 64, native
process threads within seven, and quiescent inflight returned to zero.

Workspace verification: 59 Rust tests, 16 desktop/mobile browser tests, fmt and
Clippy gates, audit/deny and 773,741 targeted DoH fuzz executions without a crash.
Counters retain twelve fixed atomics per endpoint rather than query names or
error strings. No new allocator measurement or zero-allocation claim is made.


## Short repeat checks

Two further matched pairs ran one-second phases, sequentially with checks idle,
using the same saved and production-only daemon hashes. They are smaller windows
and are listed separately from the five-second comparison.

| Pair | TLS baseline cache p99 | TLS shipping cache p99 | HTTPS baseline cache p99 | HTTPS shipping cache p99 |
|---|---:|---:|---:|---:|
| 1 | 153 | 153 | 164 | 165 |
| 3 | 154 | 161 | 165 | 163 |

Artifacts are `target/diagnostics-repeat-{1,3}-{before,shipping}.json`. Both
shipping repeats had zero incorrect replies/timeouts and reconciled endpoint
counters. The results demonstrate variability; they neither confirm nor dismiss
the longer TLS increase as a statistically significant regression. A dedicated
runner and controlled build features are needed before setting a strict gate.

An intervening saved-baseline attempt (pair 2) failed the initial coalescing
expected-reply assertion before producing phase histograms. Its failure log is
retained at `target/diagnostics-repeat-2-before.log`. The archived helper reports
only lost/wrong booleans, so this run cannot distinguish a receive timeout from an
unexpected response without reproducing it with richer diagnostics. It was not
included as a successful timing sample. This remains a baseline/rehearsal
reproducibility concern for a longer soak; all completed shipping runs and the
mandatory current test/CI-shaped runs passed.

## User-space CPU diagnosis

Samply 0.13.1 refused its permission preflight at perf_event_paranoid=2. A
read-only own-process user-event probe succeeded. A repository-local perf 7.2.3
binary and its dependencies, verified against Arch package signatures, recorded
user CPU without changing sysctls, capabilities or host installations.

A separate `profiling` Cargo profile inherits release optimization and includes
full debug symbols. Its daemon SHA-256 is `875ca6b44ac6b83c67df69d1c32064545a2579effd2ecf12db0aaa31330c734d`.
The harness attaches perf only to that real daemon during the three-second
malformed-outage phase for each transport. Recording uses `cpu-clock:u`, 997 Hz
and 16 KiB DWARF stack snapshots. Report filtering keeps `dns-worker` threads;
control workers, fixture servers and clients are excluded. No other build/test
job ran concurrently. Raw artifacts remain local:
`target/diagnostics-profiles/{tls,https}-outage.data`, flat/inclusive reports,
`summary.json` and `target/diagnostics-profile-rehearsal.json`.

| Transport | DNS-worker user samples | Conservative cryptographic self samples | Share | Lost samples |
|---|---:|---:|---:|---:|
| TLS | 3,222 | 2,238 | 69.5% | 0 |
| HTTPS | 3,279 | 2,114 | 64.5% | 0 |

The conservative classification counts leaf symbols containing `ring_core_`,
`__ecp_` or `fe4_`, without double-counting ancestor frames. The largest leaf is
P-256 Montgomery multiplication (14.7% TLS / 14.0% HTTPS); SHA-512 and Curve25519
routines also dominate. Full ancestor chains are incomplete across some assembly
frames, so these percentages describe sampled **leaf user CPU**, not complete
handshake inclusive costs, kernel CPU, CPU/query or wall-clock latency.

In the profiled run the TLS/HTTPS malformed-outage primary recorded 9,774/9,054
attempts respectively; every attempt failed DNS validation, and each fallback
also failed DNS validation. Cache-probe p99 was 153/169 µs. These instrumented
values are diagnostic and are not combined with the quiet release comparison.

Repeated connection establishment after rejected replies is therefore a strong
candidate for the outage's CPU pressure in these local certificate fixtures.
The sample supports testing bounded per-endpoint failure backoff/admission before
parser, trie or lock-free-container work. It does not establish that cryptography
alone causes every tail-latency excursion or generalize to every public endpoint,
certificate chain or TLS resumption configuration. A mitigation still needs a
correctness contract, recovery/cancellation tests and the same quiet comparison.
No retry, selection, authentication or validation behavior changed in this slice.

Reproduce with perf already available locally:

```sh
cargo build --profile profiling -p rustwalld-dns --bin rustwalld-dns --locked
cargo build --release -p rustwalld-dns --example encrypted_resilience --locked
DEBUGINFOD_URLS= target/release/examples/encrypted_resilience \
  --binary target/profiling/rustwalld-dns --duration-ms 3000 \
  --profile-outage-dir target/outage-profiles --perf /path/to/perf \
  --output target/profile-rehearsal.json
DEBUGINFOD_URLS= /path/to/perf report --stdio --no-children \
  --comms dns-worker --percentage relative --sort symbol -g none \
  -F overhead,sample,symbol --field-separator ';' --percent-limit 0 \
  -i target/outage-profiles/tls-outage.data
```

Use a distinct output directory for each run. The developer-only helper fails on
attach errors, sends SIGINT to its owned sampler after draining traffic, accepts
perf's flushed SIGINT exit and reaps the process. On harness failure, its guard
kills/reaps the sampler. It disables debuginfod downloads and build-ID-cache
updates. Ordinary benchmarks never launch a profiler. This is separate from DNS
operation and is intentionally outside the production binary.
