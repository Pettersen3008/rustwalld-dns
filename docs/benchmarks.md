# Performance contract and methodology

Targets are not measured claims: local blocked p50 <20 us / p99 <100 us; DNS
cache p99 <150 us. Never trade DNS correctness for these targets.

Criterion: exact/suffix block, filter miss, decision hit, response-cache hit,
compile/reload; deterministic synthetic domains at 100k, 1M, 5M and 10M rules.
Large fixtures are generated, not checked in. Record rule count, compile duration,
RSS, estimated payload bytes/effective rule, and actual allocator counts where
measured. Payload estimates are not allocator/RSS claims.

The filter suite also measures 8,192 precomputed exact/suffix names selected
across each dataset. The Linux `filtering` example `footprint` reports RSS/HWM
in a fresh process per size; allocator-retained compiler transients remain part
of process RSS. See [shared filter storage](filter-memory.md) for methodology
and before/after results.

Network benchmark uses loopback mock upstreams: warmed local paths, cold upstream,
concurrent identical misses and reload during traffic. Record count, p50/p95/p99/
p99.9, wall throughput and upstream exchanges; include CPU model, OS, Rust and
release settings. Measure allocations in a separate single-thread allocator
probe so unrelated Tokio tasks cannot corrupt attribution. Do not label Hickory
parse/clone paths zero-allocation without evidence.

Warm wire-engine allocator probes also cover local rewrites and live empty/full
telemetry queues. Empty-queue timing consumes prior events outside each timed
iteration; compare before/after within a scenario. See
[query string ownership](query-allocations.md) for exact fixture conditions and
allocation counts, including the remaining parser/cache/encoder allocations.
The [forwarding comparison](cache-forwarding.md) also covers maximum-length
mixed-case names and DO/CD cache hits, with upstream normalization deferred
until a new bounded flight is admitted.
The [borrowed decision comparison](borrowed-decisions.md) measures key allocation
savings, reversed-order pinned repeats, response-message cloning, a 1,024-key
working set and bounded FIFO churn. It retains unfavorable initial results and
does not claim a cache latency improvement.

The Linux [CPU/query probe](cpu-query.md) shares these fixture constructors but
runs without allocation-counter hooks. Warm current-thread batches account for
user/system CPU ticks around the query loop, including Tokio entry, response
drops and the upstream guard. Retain raw ticks and rounding limits; insufficient
ticks produce a null estimate rather than a zero-CPU claim. The driver records
binary identity, affinity and hardware. CI exercises short accounting/failure
checks; CPU regression thresholds require longer runs on a stable machine.

Run under stable load, warm up, repeat on the same hardware. Keep Criterion
artifacts and concise result summaries. Investigate >10% change; >20% normally
fails a stable local benchmark gate after repeated confirmation. Network-dependent
upstream numbers are diagnostic, never strict CI gates. This initial repository
establishes baselines; automated regression thresholds require a stable runner.

Review hot-path imports/call graph for SQLite/filesystem/config/HTTP leakage.
Bounded structures plus overload/cancellation tests are separate acceptance
criteria from speed measurements.

When measuring a shipping binary, build examples separately and then build only
that binary (or use release.py). Selecting binaries and examples in one Cargo
invocation can unify dev-dependency features and produce a different executable.
Retain and verify its SHA-256 against the release manifest. Benchmark with other
build/test/container jobs idle; report failed runs and short repeats as well as
the chosen long-run numbers.
