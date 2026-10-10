# Engine prepare/forward split: latency evidence

`Engine::answer` became `Engine::prepare` (synchronous: refusals, blocks,
rewrites and response-cache hits) plus `Engine::forward` for cache misses, so
servers can bound slow upstream waits separately from fast local answers. This
note records that the query path did not get slower while gaining that
structure.

Changes measured together, against commit `002301d` (the code reviewed on
2026-10-09):

- Synchronous `Resolver::lookup`. A cache hit no longer creates the resolver's
  async future.
- CLOCK `BoundedCache` with one hash per operation ([details](cache-eviction.md)).
- Shared `finish` with in-place reply finalization. Moving the reply `Message`
  by value through helpers had cost 2–13 ns on block and rewrite paths.
- Rewrite answers grouped by record type at compile time, so a hit clones only
  the matching records.
- The shadow snapshot is read with `ArcSwap::load` instead of `load_full`
  (no shared reference-count increment).

## Results (2026-10-10)

`crates/dns-core/benches/engine.rs`, single-thread Tokio, warmed caches, no
upstream exchanges. AMD Ryzen 7 9800X3D, Linux 7.2, Rust 1.99.0, one pinned core
(`taskset -c 6`), Criterion 2 s warm-up and 4 s measurement. The baseline and
candidate binaries come from identical benchmark sources apart from API renames.

| Scenario | Before | After | Change |
| --- | ---: | ---: | ---: |
| `decision_cache_blocked_wire` | 542.8 ns | 533.0 ns | −2.2% |
| `decision_cache_blocked_with_exceptions_wire` | 555.4 ns | 538.4 ns | −3.3% |
| `expired_temporary_decision_cache_wire` | 553.5 ns | 543.4 ns | −2.2% |
| `local_rewrite_wire` | 648.1 ns | 603.2 ns | −7.0% |
| `dns_cache_hit_wire` | 853.4 ns | 792.0 ns | −7.9% |
| `dns_cache_dnssec_wire` | 938.5 ns | 868.2 ns | −7.9% |
| `dns_cache_long_name_wire` | 2068.6 ns | 1766.6 ns | −15.6% |
| `temporary_allow_dns_cache_wire` | 880.6 ns | 827.8 ns | −6.0% |
| `telemetry_empty_blocked_wire` | 583.4 ns | 574.3 ns | −1.4% |
| `telemetry_full_blocked_wire` | 541.2 ns | 527.6 ns | −2.6% |
| `telemetry_empty_dns_cache_wire` | 891.7 ns | 825.6 ns | −7.3% |
| `telemetry_full_dns_cache_wire` | 853.7 ns | 786.0 ns | −7.9% |

Allocator probes report the same allocation counts per warm query for every
scenario. The rewrite path allocates fewer bytes (2,231 → 1,415 per query).
These are synthetic warm-path timings, not network latency percentiles; the
loopback resilience harness (`crates/app/examples/resilience.rs`) measured p50
7 µs / p99 about 10 µs for UDP through the real binary during compilation,
persistence failure and stalled downloads. Raw output is kept in
`target/review/engine-ab/`.

```sh
cargo bench --locked -p rustwalld-dns-core --bench engine
```
