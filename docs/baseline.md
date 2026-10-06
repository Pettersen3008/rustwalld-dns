# Initial baseline — 2026-10-05

Automation note (2026-10-06): GitHub Actions and `.github/` were removed at
the maintainer's request. References to CI below describe historical verification;
run the documented commands locally and retain artifacts under `target/`.

Hardware: AMD Ryzen 7 9800X3D, 8 cores / 16 threads, 30 GiB RAM.
Linux 7.2.5-3-omarchy; rustc 1.98.1; release profile with thin LTO and one
codegen unit. Tokio DNS benchmark uses two worker threads. These short runs on a
shared workstation establish a baseline; they are not dedicated-runner limits.

## Full packet processing, excluding sockets

Criterion after warm-up, 20 samples, 0.5 s warm-up / 1 s measurement. Includes
Hickory parse/serialization, policy selection, cache access and a nonblocking
telemetry emit to a closed queue. The allocator probe wraps a single warmed
query on a current-thread runtime; it excludes UDP packet/task admission.

| Path | Criterion estimate | Allocations/query | Allocated bytes/query |
| --- | ---: | ---: | ---: |
| Decision-cache blocked reply | 0.630 us | 10 | 1,151 |
| DNS response-cache reply | 1.012 us | 13 | 1,259 |

Both paths performed zero upstream exchanges. Zero heap allocation is **not yet
achieved**. The parser, name conversion, response cloning and telemetry event
strings remain ordinary allocation paths. No custom parser or packed structure
was introduced to improve these numbers.

## Real loopback UDP

5,000 sequential queries per local path. One mock upstream deliberately sleeps
25 ms per exchange. Clients send one query at a time; throughput includes client
socket I/O and response parsing, so it is not a saturated server capacity claim.

| Path | p50 | p95 | p99 | p99.9 | Throughput | Upstream exchanges |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Decision-cache blocked | 7 us | 8 us | 12 us | 31 us | 132,629/s | 0 |
| DNS response-cache | 9 us | 11 us | 31 us | 1,642 us | 63,338/s | 0 |
| 50 cold requests with 25 ms fixture | 26,152 us | 26,206 us | 26,345 us | 26,345 us | 38/s | 50 |
| 128 concurrent duplicate misses | 37,679 us | 41,468 us | 41,487 us | 41,523 us | 3,081/s | 1 |
| Blocked traffic during 100k-rule reload | 7 us | 7 us | 9 us | 20 us | 134,710/s | 0 |

The response-cache p99.9 spike must remain visible; noisy workstation scheduling
and the loopback client are included in this measurement. No strict tail guarantee
is established. An earlier 256-packet simultaneous UDP burst lost packets in the
kernel receive buffer. The wire fixture now uses 128 concurrent clients. A separate
integration test verifies 1,000 engine waiters collapse to one upstream lookup,
including cancellation of the initiating waiter.

Reload compilation: 35 ms, atomic store: about 2 us. No DNS errors/restart during
the measured reload traffic. The history queue deliberately saturated; 11,084
events were dropped while DNS continued answering. Whole-workload CPU: 0.083 s
user + 0.086 s system over 1.537 s wall; peak process RSS 40,112 KiB. This CPU total
includes fixture/client/reload work and must not be presented as isolated engine
CPU/query. A later [local CPU/query probe](cpu-query.md) measures warmed engine
batches separately; these earlier workload totals remain aggregate measurements.

## Compiled rule sizes

Exactly half exact and half suffix rules, deterministically generated, all unique.
Provenance and normalized rules are retained. Compile times include input parsing,
deduplication and same-action subsumption analysis.

| Rules | Compile time | Logical payload estimate |
| --- | ---: | ---: |
| 100,000 | 31 ms | 15,977,780 bytes |
| 1,000,000 | 615 ms | 161,777,780 bytes |
| 5,000,000 | 4,386 ms | 817,777,780 bytes |
| 10,000,000 | 8,107 ms | 1,637,777,780 bytes |

Payload estimates exclude map/allocator overhead and are not RSS. Peak child RSS
for the entire four-dataset benchmark run: 3,795,124 KiB (~3.62 GiB), including
transient compilation structures. Logical payload is ~160–164 bytes/effective
rule. This is a correctness/provenance baseline with substantial room for memory
improvement, not a packed filter database.

Repeated fixed-name microbenchmarks across these datasets measured roughly
14 ns exact, 34–44 ns suffix and 34–37 ns miss before the escaped-label correction.
These are warmed fixed keys, not a random working-set benchmark. After the
correctness fix, the 100k rerun measured ~37.8 ns suffix and ~37.7 ns miss; the miss
estimate changed ~9%. Keep the escaped-label behavior; protocol correctness takes
precedence. There is no statistically controlled performance gate yet.

## Verification

- 26 workspace tests pass, including real UDP/TCP/HTTP and process lifecycle.
- Strict workspace Clippy and formatting pass; all benchmark targets build.
- `cargo audit`: 239 locked dependencies scanned, no reported vulnerabilities.
- `cargo deny`: advisories, bans, licenses and sources pass. Transitive duplicate
  versions are reported as warnings rather than silently hidden.
- AddressSanitizer fuzz runs: DNS parser/roundtrip 1,413,577 cases (21 s), filter
  compiler 994,538 cases (21 s), then 172,080 filter cases (11 s) after the escaped
  label fix. No crash was found. Short campaigns are not proof of parser safety.
- Code-path/dependency review confirms no SQLite/filesystem/JSON/config parsing
  calls in normal Engine/Resolver evaluation. No production unsafe/unwrap/expect.
  Independent executors isolate management scheduling; the DB has its own thread.

Local `/tmp` quota affected tool installation, rustdoc, native compilation and
initial SQLite test scratch files. Tool/compiler scratch was moved to
`target/tool-tmp`; SQLite test databases now use auto-cleaned directories next to
the app crate. The successful final checks used `TMPDIR=$PWD/target/tool-tmp`.
No desktop/system configuration was changed.

Reproduce using README commands and scripts/measure.py. Local raw logs and
Criterion artifacts are under target/ and intentionally excluded from Git. CI
uploads Criterion artifacts. Regex benchmarks are skipped because regex is
explicitly deferred. A deterministic broader 8,192-name working set and
fresh-process filter memory comparison were subsequently added; see
[shared filter storage](filter-memory.md). The later [CPU/query probe](cpu-query.md)
adds warmed local batch accounting. Fully random traffic, detailed instruction
attribution and statistical regression enforcement remain separate milestones.
