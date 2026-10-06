# CPU per local DNS query

Automation note (2026-10-06): GitHub Actions and `.github/` were removed at
the maintainer's request. References to CI below describe historical verification;
run the documented commands locally and retain artifacts under `target/`.

Goal: close the CPU/query measurement gap without changing the DNS data plane.
Done means a reproducible local probe, validated CPU accounting and guards,
shared Criterion fixtures, complete checks and retained results/limits.

Use a Linux-only `dns-core` example with the existing warmed short blocked/cache,
temporary-allow, rewrite and long/DO/CD cache fixtures. Move fixture construction
into one shared benchmark support module; production libraries remain unchanged.
A current-thread Tokio runtime has no unrelated async workers. Measure batches
using `/proc/self/stat` user/system ticks, with `getconf CLK_TCK` once before
query measurement. Proc reads, fixture construction, response validation,
allocator probes and output occur outside the timed loop. The loop includes
`Engine::answer`, Tokio entry, response/event drops and a fail-fast upstream guard.
CPU deltas retain a small sampling-boundary overhead; large batches make it small
relative to tick quantization. This is batch accounting, not instruction profiling.
CPU and allocation measurements use separate executables, so allocator-counter
hooks are not linked into the CPU probe.

Alternative: report whole-child CPU from the existing `scripts/measure.py`.
That includes startup, warm-up, compilation/fixture work and reporting, so it
cannot attribute CPU to completed queries. Kernel tick accounting is coarse but
needs no new dependency, unsafe code, perf permissions or host configuration.
Report raw ticks, query counts and a conservative two-tick rounding allowance;
short batches must be labeled low precision rather than treated as zero CPU.

Keep iterations/batches bounded, stop on upstream attempts during warm-up or
measurement and reconcile
expected blocked/cache/rewrite/temporary counters. Validate representative wire
answers, IDs and answer addresses before/after measurement. A Python driver captures bounded TSV output,
validates rows and writes a standalone JSON artifact with hardware/OS, binary
hash, affinity, whole-process peak RSS and per-scenario medians. The driver runs a
trusted benchmark executable whose output is bounded to 30 rows; it validates a
64 KiB output limit and enforces a 300-second process deadline. Whole-process
RSS and wall iteration times are not per-query memory or network percentiles.

Verification: CPU stat/parser/CLI and driver rejection tests; short CI artifact
with honest precision labels; longer quiet CPU-pinned local batches, separate
allocator probes and unchanged Criterion comparisons. Run required formatting,
Clippy/workspace checks. No parser/dependency/security or UI change means fresh
fuzzing/browser runs are unnecessary. Rebuild and verify the release manifest;
confirm its runtime binary/assets match the preceding tested payload.

Kernel counter semantics are documented in
[proc filesystem documentation](https://docs.kernel.org/filesystems/proc.html).

## Reproduction and results

```sh
cargo test --locked -p rustwalld-dns-core --example cpu_probe
cargo build --release --locked -p rustwalld-dns-core --example cpu_probe
python3 scripts/cpu-probe.py --cpu 2 --output target/cpu-query.json
```

Choose an allowed CPU for `--cpu`, or omit it. Run with other builds, tests and
network benchmarks idle. Default work is three batches of two million queries
per scenario, following 10,000 warm-up queries. Fixtures use closed telemetry,
four annotated client bindings and loopback-only upstreams with 50 ms timeouts.
Cached responses have 3,600-second TTLs; temporary allows also last one hour.

Two sequential CPU-2-pinned runs on an AMD Ryzen 7 9800X3D, Linux x86_64, Rust
1.98.1 release build, 2026-10-06:

| Warm local scenario | Full run 3 median CPU ns/query | Full run 4 median CPU ns/query |
| --- | ---: | ---: |
| Blocked decision cache | 585 | 575 |
| DNS response cache | 875 | 875 |
| Temporary allow + response cache | 905 | 905 |
| Local rewrite | 640 | 645 |
| Maximum-length mixed-case DO/CD cache | 2,175 | 2,185 |
| Short-name DO/CD cache | 990 | 1,245 |

Each run completed 36 million measured queries with zero upstream attempts.
Every batch exceeded the 20-tick precision minimum. `CLK_TCK=100` gives a
conservative 10 ns/query two-tick rounding allowance at this batch size; it is
not a statistical confidence interval. These are baseline estimates of this
loop, not an optimization comparison, throughput claim or network percentiles.
Whole-child peak RSS was 25,896/26,068 KiB, including startup and potentially
the driver's inherited memory before exec; use the separate footprint probes
for memory comparisons.

The short DO/CD scenario's second run has 970/1,265/1,245 ns batches. Retain its
26% higher median: the cause of that slower interval was not isolated. A focused
repeat using three five-million-query batches measured 988 ns/query median,
with 4 ns/query tick allowance, zero upstream attempts and the same binary.
Thus clock resolution is sufficient, but this shared desktop still has material
timing variability; `low_precision=false` is only a tick-resolution check.
These measurements do not justify a strict CPU regression gate.

Retained final artifacts: `target/cpu-query/run-{3,4}.json`,
`dnssec-repeat.json` and corresponding logs. Earlier `run-{1,2}.json` used the
probe before the warm-up guard and address/ID checks; retain them as preliminary
evidence rather than selectively substituting their faster numbers. Final runs
report executable SHA-256
`0d7e97fa20e50d743c4e9c3e4311dcb4c086a15894fff87618ffd534ae4755d7`.
`nm` verified the executable has no allocation-counter symbols. The short run
reports low-precision CPU estimates as null, and the deliberately emptied cache
fails immediately with `probe failed or attempted upstream work`.

## Fixture comparison and limits

Moving fixture construction out of Criterion changes no production code or timed
query loop. A CPU-2-pinned before/after comparison used the saved preceding bench
binary, 30 samples, 1-second warm-up and 2-second measurement. All 12 allocator
probes retained identical counts/bytes: blocked 8/1,127; short cache 10/1,149;
long cache 32/6,413; DO/CD short cache 11/1,421; temporary allow 10/1,149;
rewrite 10/2,231. Closed/empty/full telemetry cases also retained their counts.

Eleven mean comparisons ranged from −0.6% to +4.0%. The expired-exception case
initially increased from 619.5 to 719.6 ns (+16.2%); its samples contained a
transient slower interval. Investigate rather than discard that result: a
reversed-order repeat with 50 samples, 2-second warm-up and 5-second measurement
gave 641.0 ns before and 638.2 ns after (−0.45%). The initial >10% change did not
reproduce. This supports retaining the shared fixture module, without claiming
a performance improvement or a stable CI latency guarantee.

Retain `target/cpu-query/criterion-{before,after}.log`,
`criterion-repeat-{before,after}.log` and `criterion-summary.json`. Criterion
uses allocator hooks and a different loop from the CPU probe; their numbers
must not be compared as evidence of an optimization.

## Verification and release

The formal review removed allocation-counter linkage from CPU measurement,
added fail-fast warm-up guarding and checked representative answer addresses/IDs.
The required formatting, strict all-target/all-feature workspace Clippy and
119 workspace tests pass, plus three explicit example tests. Python checks cover
accounting, malformed/inconsistent reports and the existing five installer tests.
CI retains a short six-scenario JSON report with honest precision labels and
the deliberate upstream rejection log.

Rebuild the daemon separately from benchmark examples. Its SHA-256 remains
`76c4624733dc4c83ffd3ebf67afcb8bce6e8eb9f50e755fc796ba67e0f7c4863`.
The final bundle includes this document; all manifest hashes/current source
identity and binary/web/config/unit/installer equality to the preceding tested
release are checked in `target/cpu-query/release-verification.json`. Existing
real-daemon reload/failure and clean-container recovery evidence therefore
applies to the identical runtime payload. This benchmark-only slice needs no
fresh parser fuzzing, dependency audit or browser run. Native systemd sandbox
activation remains a deployment-host check.

Historical scope: the appliance-comparison follow-up subsequently changed TCP
socket setup and the application's SQLite retention worker. The measurements
and runtime-equality statement above apply to this earlier release, not the new
payload. See [comparison evidence](comparison.md) for current daemon identities,
matched runtime measurements and fresh packaged recovery verification.
