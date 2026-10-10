# Reusable-library refactor evidence

Status: local refactor verification completed, 2026-10-06. Five reusable libraries
and the optional durable runtime are delivered; standalone external behavior is
protected by the retained protocol, API, process, browser and recovery fixtures.
Development remains private under Pettersen3008, without `.github/` or CI/CD.
No files in `~/Work/rustwalld` were changed.

## Source and method

Baseline Git commit: `d7fc877`. Original source, production binary, five Criterion
executables and process harnesses were retained before refactoring. No external
locked dependency version changed. Rust 1.98.1 / LLVM 22.1.8, thin LTO and one
release codegen unit were used on both sides; Rust 1.95 was tested separately.
Hardware: model name	: AMD Ryzen 7 9800X3D 8-Core Processor. Linux 7.2.5, x86_64, glibc 2.44.

Final Criterion comparisons use the original package selections and dependency
features: four sequential launches in old/new/new/old order, 1-second warm-up,
2-second measurement, 20 samples. Values below are means of the two launch medians
per build. Workloads, timed expressions and allocation instrumentation were
preserved; API-compatible test fixtures use checked publication outside timing.
No compiler/browser/fuzz/container jobs run during these measurements. This is a
shared desktop, not a dedicated stable latency runner.

An initial workspace-wide benchmark build unified extra dependency features,
including Tokio filesystem support, and showed warm DoH about 4.7% slower. That
comparison was confounded. It is retained under `target/refactor/final/`; corrected
package-specific builds have matching external dependency fingerprints and the
accepted results are under `target/refactor/matched/`. No transport optimization
was made to disguise a build mismatch.

## Matched timing and allocations

| Case | Original | Refactor | Observed change |
| --- | ---: | ---: | ---: |
| `decision_cache_blocked_wire` | 612.80 ns | 608.05 ns | -0.8% |
| `dns_cache_hit_wire` | 929.45 ns | 909.05 ns | -2.2% |
| `dns_cache_long_name_wire` | 2.21 µs | 2.14 µs | -3.0% |
| `dns_cache_dnssec_wire` | 1.02 µs | 1.01 µs | -1.2% |
| `temporary_allow_dns_cache_wire` | 942.48 ns | 947.27 ns | +0.5% |
| `local_rewrite_wire` | 702.78 ns | 708.55 ns | +0.8% |
| `telemetry_empty_blocked_wire` | 651.70 ns | 652.64 ns | +0.1% |
| `telemetry_full_dns_cache_wire` | 935.89 ns | 914.94 ns | -2.2% |
| `bounded_cache_working_set_hit` | 16.62 ns | 16.51 ns | -0.7% |
| `bounded_cache_fifo_churn` | 31.92 ns | 32.09 ns | +0.5% |
| `doh_loopback/warm` | 16.06 µs | 16.06 µs | -0.1% |
| `doh_loopback/cold` | 238.45 µs | 241.71 µs | +1.4% |
| `dot_loopback/warm` | 13.82 µs | 14.09 µs | +1.9% |
| `dot_loopback/cold` | 210.06 µs | 212.24 µs | +1.0% |
| `filter/exact/100000` | 15.22 ns | 15.30 ns | +0.5% |
| `filter/suffix/100000` | 36.58 ns | 37.29 ns | +1.9% |
| `filter/miss/100000` | 36.94 ns | 38.52 ns | +4.3% |
| `filter/working_set/100000` | 56.39 ns | 55.48 ns | -1.6% |

Whole-query cases range from about −3.0% to +1.1%; warm HTTPS is effectively
unchanged. All matched cases are within 4.4%. Small differences and randomized
map placement are not presented as guaranteed speedups. No parser, cache layout,
transport algorithm or query instrumentation was changed.

All twelve warm allocation cases retain the same count and bytes: blocked 8 / 1127,
cached 10 / 1149, long-name cached 32 / 6413, DNSSEC cached 11 / 1421, temporary allow
10 / 1149 and rewrite 10 / 2231. Empty/full event queues retain their original
counts. These are fixture measurements, not a zero-allocation claim.

The separate CPU probe ran one million queries per batch, three batches per
launch, old/new/new/old. It rejected upstream work (zero upstream requests) and
kept process-tick quantization visible. Median CPU ns/query across six batches:

| Scenario | Original | Refactor |
| --- | ---: | ---: |
| blocked | 580 | 565 |
| cache | 890 | 870 |
| temporary | 915 | 905 |
| rewrite | 640 | 630 |
| long-cache | 2385 | 2120 |
| dnssec-cache | 985 | 965 |

CPU figures are diagnostic; old long-name batches varied substantially. Retain
all batches and do not claim an 11% algorithmic improvement from their median.

## Large filter data and memory

The unchanged matching fixture ran 100k, 1M, 5M and 10M rules. Broader working-set,
exact, suffix and miss cases are retained in Criterion output. Fresh-process
memory probes were rebuilt from the exact baseline commit and final filter crate.
Each size/build gets a separate process; RSS/HWM include allocator/compiler
transients and are distinct from the logical payload estimate.

| Rules | Identical payload bytes | Original RSS KiB | Refactor RSS KiB | Original peak KiB | Refactor peak KiB |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 100,000 | 11,238,897 | 19,876 | 19,876 | 25,768 | 25,776 |
| 1,000,000 | 113,388,897 | 205,144 | 206,236 | 291,968 | 292,004 |
| 5,000,000 | 571,388,897 | 833,660 | 832,680 | 1,253,148 | 1,250,500 |
| 10,000,000 | 1,143,888,897 | 1,663,632 | 1,662,416 | 2,502,072 | 2,499,220 |

Payloads/effective counts match exactly; RSS differs by at most about 0.6% in these
launches. Ten-million-rule peak is about 2.4 GiB on both builds. Compile time and
RSS are workload/allocator/hardware observations, not product capacity guarantees.

## Recovery, checks and review

- All 123 original test function identifiers remain; four controller cases were
  added. Workspace tests, CPU-probe tests, strict all-target/all-feature Clippy,
  formatting, documentation/doctests and benchmark compilation pass.
- Three independent Cargo consumers pass through public core/components/runtime
  APIs. They cover local UDP/TCP, allow precedence, reload/shadow/stale versions,
  independent engines, rejected foreign controllers/reused IDs, a locked SQLite
  commit, caller cancellation, awaited shutdown and durable restart.
- Workspace and consumer checks pass on Rust 1.95. Five verified Cargo archives
  build through Cargo's temporary local registry; consumers run again against
  extracted archives. Every library includes README and license notices.
- All 38 desktop/mobile browser tests pass; console format/build and npm audit
  pass. Fourteen Python orchestration/installer tests pass.
- RustSec audit and cargo-deny advisory/license/source checks pass. Seven existing
  fuzz targets ran for 20 seconds each on nightly with sanitizers and retained
  seed corpora; no crashes found. Short fuzzing does not prove absence of bugs.
- Real-process recovery used the original saved harness against both binaries in
  alternating order. All answers were correct, with zero timeouts or clipped
  samples; HTTP admission/publication rejection and durable state remained valid.
- Initial 1-second stress windows recorded refactor p99 spikes up to 75 µs versus
  15–19 µs on the original. Longer reversed 3-second runs mostly measured 15 µs on
  both; one refactor compilation phase was 24 µs. The final refactor run was 15 µs
  in every phase. Retain the outliers as unexplained desktop variability; a local
  microbenchmark does not establish a tail-latency guarantee.
- Saved encrypted-upstream failure harness and three 100k-rule control recovery
  cycles pass, including bounded resources, failed writes, reviewed refresh,
  connection retirement and durable restart. Correctness-rejection modes remain
  part of the existing verification workflow.
- Packaged non-root install, UDP/TCP, authenticated DoT/HTTP2 DoH, reviewed HTTPS
  lists, offline publisher recovery, conditional retrieval, upgrade preservation,
  schema-2 WAL backup/restore and expired-exception recovery pass in the isolated
  networkless deployment container. Native sandbox activation was not exercised.

Review found and corrected public mutation bypasses, JSON-indexed store replies,
HTTP coupling in scheduled staging, controller/engine pairing, counter reset
exposure and an unnecessary initial-policy clone. Compiled fields are read-only;
controller reservations validate versions/high-water marks before durable commit;
publication is infallible after persistence; queries never take the control mutex.
Runtime cancellation drains admitted mutation before stopping SQLite. No blocking
review defect remains. Native operation and shared-desktop timing remain limits.

## Evidence and reproduction

Ignored artifacts: `target/refactor/baseline/`, `target/refactor/matched/`,
`target/refactor/final/`, verification logs under `target/refactor/`,
`target/criterion/`, `target/crate-verification.json` and browser traces under
`web/test-results/`. These generated artifacts are not Git source or uploaded
telemetry. Baseline production SHA-256:
`47ff93e78391cd327bc280b7c153018b75e836c2a29db77f5717658428fef75a`.
Verified refactor production SHA-256:
`edf6a622382c7e1857fcd7dd3cd48742aa95e9f7e78b7ebdb6dcfb7c000bea5e`.

Use [CONTRIBUTING](../CONTRIBUTING.md), [embedding](embedding.md),
[benchmark methodology](benchmarks.md) and [release preparation](releasing.md).
For a fresh before/after comparison, build the baseline in a separate checkout,
retain its executables, then build each final benchmark with its same package
selection/profile/features. Run alternating measurements with other jobs idle;
keep all samples, allocation/correctness checks and failures.

Native deployment-host validation and a clean 24–72-hour representative-network
soak remain pending release gates. Registry publication and actual Rustwalld
integration are separate future work; the public alpha does not claim them.
