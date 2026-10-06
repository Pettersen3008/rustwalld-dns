# Borrowed decision-cache lookup

Goal: eliminate the measured owned domain-key allocation on warm decision-cache
hits, preserving normalized name matching, policy/generation partitioning,
bounded FIFO shards, randomized hashing and owned telemetry. Done means matched
allocation/timing evidence, collision/partition/eviction/concurrency regressions,
full checks and tested release recovery.

The engine previously created `DecisionKey { domain: String, policy, generation }`
before lookup. Hits immediately discard the key. The shared `BoundedCache` owns
its stored keys and FIFO order; both decision and response caches use it.

Use hashbrown 0.17.1's safe `Equivalent` lookup on the existing sharded map.
This version was already locked transitively; it is now a direct resolver dependency
with default features disabled and the built-in `inline-more` feature selected.
Keep `std::collections::hash_map::RandomState`
explicit for every map and shard selector. No custom hasher, raw-entry API,
lock-free container or new cache eviction policy.

`BoundedCache::get<Q: Hash + Equivalent<K> + ?Sized>(&Q)` hashes and compares a
borrowed lookup. The DNS engine adds `DecisionLookup<'a>` with a borrowed domain
and the same policy/generation fields as the owned key. Both derive `Hash` in the
same field order; equivalence compares all three fields. Only a miss constructs
the owned key for insertion. Rewrite/temporary behavior and telemetry ownership
remain unchanged. Response-cache callers continue using owned semantic keys.

Alternative: reorganize the cache into nested per-generation/per-policy maps.
That changes capacity and locking behavior. Standard `Borrow` cannot directly
express this borrowed composite key without a broader trait-object interface.
The existing map library's concrete lookup contract is the smaller boundary.

Risks: equivalent values must hash identically, equality must never omit policy
or generation, and shard selection must use the borrowed key's identical hash.
Randomized hashing must remain explicit rather than using a faster default that
weakens resistance to attacker-chosen names. A shared map change also needs
response-cache hit/churn measurements and concurrent boundedness checks.

Plan: save current sources/binary and warm wire baselines; measure the response
cache, a 1,024-key working set and FIFO churn; implement the borrowed lookup;
verify hash/equivalence across unusual names and policy/generation values, forced
collisions, updates/evictions and bounded concurrent use. Run full formatting,
Clippy, tests, audit/deny and targeted cache fuzzing for the new dependency path;
repeat matched benchmarks and real-daemon failure traffic before packaging.

The required identical-hash contract is documented by
[hashbrown Equivalent](https://docs.rs/hashbrown/0.17.1/hashbrown/trait.Equivalent.html).

## Review and correctness evidence

Review found no production correctness defect. It identified a test coverage
gap: differing hashes can conceal an equality predicate that omits a namespace
field. The actual decision lookup now explicitly tests inequality for differing
domains, policies and generations, alongside identical hash/lookup results for
owned and borrowed keys. Cases include root, escaped dot/backslash, raw-label
ASCII escapes, punycode, maximum-length names and integer boundary values.

Cache regressions cover unsized borrowed strings, disabled capacity, value
replacement, forced hash collisions and FIFO update/eviction order. Eight
concurrent workers insert/read/evict while checking the configured entry bound.
The engine's existing real DNS suite covers casing, DO/CD, separate upstream
profiles, policy promotion, raw labels, temporary expiry, queue overload and
coalesced cancellation. No parser, encoder, DNS protocol acceptance, response
cache key, persistence schema or console change.

The new `cache_lookup` fuzz target runs bounded insert/lookups with composite
domain/policy/generation keys. It compares owned/borrowed results, rejects wrong
key payloads and checks capacity; seed fixtures exercise partitioning, FIFO and
disabled caches. CI runs it separately from fast tests. Its sanitized process
RSS is not a production cache-memory measurement.

The lockfile adds only the direct resolver edge to the existing hashbrown
0.17.1 package, with no package-version update. Both shard selection and map
hashing still explicitly use `RandomState`; the library's default hasher feature
is not selected by this dependency declaration.

## Measurements (2026-10-06)

AMD Ryzen 7 9800X3D, Linux 7.2.5-3-omarchy, rustc 1.98.1;
release thin LTO / one codegen unit. Shared host. Allocation probes use the
existing single-thread Tokio warm wire fixtures, with zero upstream lookups and
no unrelated workers. These are short IN A names except the long-name fixture,
which uses 63/63/63/61 mixed-case labels and DO/CD with EDNS. No zero-allocation
claim or guarantee for every domain, cold cache or cold telemetry channel.

| Warm scenario | Allocations before / after | Allocated bytes before / after |
| --- | ---: | ---: |
| Blocked decision-cache | 9 / 8 | 1,139 / 1,127 |
| DNS-cache hit | 11 / 10 | 1,160 / 1,149 |
| Long-name DNS-cache hit | 33 / 32 | 6,666 / 6,413 |
| DO/CD DNS-cache hit | 12 / 11 | 1,432 / 1,421 |
| Temporary allow, DNS cache | 10 / 10 | 1,149 / 1,149 |
| Local rewrite | 10 / 10 | 2,231 / 2,231 |

Live empty/full telemetry queues have the same savings as their corresponding
blocked/cache fixtures; unrelated/expired exceptions also save the blocked
domain-key allocation. Stored keys/FIFO entries remain owned, and misses still
allocate their keys. Empty-root keys already required no domain allocation.

The initial all-default-features-disabled experiment showed a 10.5% response-
cache mean regression and a 10% exception-path change on an unpinned run. It was
not retained. Enabling the library's supported `inline-more` feature brought
the response-cache comparison to about +1.5%; the full unpinned inline run still
showed mostly +0–2.3% changes, with the long-name case around +4.7%. We therefore
repeated saved binaries on CPU 6, reversing order, with other project jobs idle.
These repeats are not proof of causal attribution for the earlier shared-host
outlier. No host affinity policy, governor or permissions were changed.

Pinned runs use 50 samples, one-second warm-up and three-second measurement.
Before/after arithmetic mean nanoseconds, with percentage changes:

| Workload | Pair 1 (before then after) | Pair 2 (after then before) |
| --- | ---: | ---: |
| Blocked decision-cache | 624.7 / 600.5 (-3.86%) | 622.1 / 609.4 (-2.05%) |
| DNS-cache hit | 937.7 / 940.6 (+0.31%) | 926.3 / 941.6 (+1.66%) |
| Long-name DNS-cache | 2,194.0 / 2,235.1 (+1.87%) | 2,168.4 / 2,201.4 (+1.52%) |
| DO/CD DNS-cache | 1,035.3 / 1,047.0 (+1.13%) | 1,034.1 / 1,051.3 (+1.66%) |
| Blocked with exception | 633.1 / 610.7 (-3.53%) | 633.0 / 614.4 (-2.94%) |
| Response-message clone | 150.1 / 150.6 (+0.32%) | 150.4 / 152.2 (+1.18%) |
| 1,024-key cache working set | 16.7 / 16.6 (-0.40%) | 16.9 / 16.8 (-0.28%) |
| Bounded FIFO churn | 32.2 / 32.1 (-0.23%) | 32.9 / 32.7 (-0.86%) |

Retain the measured allocation reduction and blocked-path improvement. Cache
timings were slightly slower in these repeats, within 2%; do not claim a cache
speedup. Saved before/final benchmark binaries, hashes, raw logs and exact means
are in `target/borrowed-decision/benchmark-summary.json` and `*-pin-*.log`.
Iteration times are not network percentiles or absolute throughput claims.

```sh
cargo bench --locked -p dns-core --bench engine -- wire --save-baseline borrowed-decision-before --sample-size 30 --warm-up-time 1 --measurement-time 2
cargo bench --locked -p resolver --bench cache -- --save-baseline borrowed-decision-before --sample-size 30 --warm-up-time 1 --measurement-time 2
# Repeat the saved before/final binaries in both orders; engine uses the five
# selected affected wire cases, while cache runs all three scenarios.
taskset -c 6 target/borrowed-decision/engine-inline-bin --bench '^(decision_cache_blocked_wire|dns_cache_hit_wire|dns_cache_long_name_wire|dns_cache_dnssec_wire|decision_cache_blocked_with_exceptions_wire)$' --save-baseline borrowed-pin-inline-1 --sample-size 50 --warm-up-time 1 --measurement-time 3
taskset -c 6 target/borrowed-decision/cache-inline-bin --bench --save-baseline borrowed-pin-inline-1 --sample-size 50 --warm-up-time 1 --measurement-time 3
```

## Final quality gates

Formatting (including the separate fuzz workspace), strict all-target/all-feature
Clippy and all 119 Rust tests pass. Fresh audit scans 272 locked dependencies
with no vulnerable advisory match; deny passes advisories/bans/licenses/sources
with existing duplicate-version diagnostics. The final inline configuration's
cache fuzz campaign completes 208,980 cases in 31 seconds with no failure; the
earlier configuration completed 405,529 cases. The installed nightly emits the
existing atomic `fetch_update` rename warning; stable Clippy is clean. No parser
fuzz campaign or browser run was needed: DNS parsing/encoding, protocol admission
and console behavior did not change. Full malformed/transport/API regression
suites still run with the workspace.

Logs are under `target/borrowed-decision/`, including `fuzz-inline.log`,
`workspace-tests.log`, `clippy.log`, `audit.log` and `deny.log`.

## Production rehearsal

Build the example separately before the production-only executable, avoiding
dev-dependency feature unification. The measured final binary SHA-256 is
`76c4624733dc4c83ffd3ebf67afcb8bce6e8eb9f50e755fc796ba67e0f7c4863`;
the saved preceding release is
`7429d5b07d91b5406508eff68fcf60681a0a01a7c466ce28aaad42507336430a`.

Five installer tests pass. The first reproducibility run correctly detected
different release IDs because the verification document was edited during its
two repacks; the unchanged-input rerun passes. That workflow mistake and its
failure log are retained as `installer-input-change.log`; installer logic was
not changed.

The matched real-process harness uses four clients alternating blocked/cached
replies, five-second phases and a 200,001-rule shadow candidate. No other project
build/test/fuzz job ran during timing. Network quantiles are diagnostic on this
shared host and do not demonstrate an end-to-end speedup.

| Phase | Before p99 / p99.9 µs | After p99 / p99.9 µs |
| --- | ---: | ---: |
| Warm baseline | 15 / 21 | 16 / 26 |
| Stalled management HTTP | 17 / 32 | 17 / 30 |
| Shadow compilation | 16 / 28 | 17 / 30 |
| SQLite writer failure | 17 / 30 | 16 / 26 |
| Stalled scheduled HTTPS body | 16 / 27 | 17 / 31 |

Both binaries returned zero wrong replies/timeouts and made two upstream
exchanges; the current binary validated 10,423,216 replies. Reports are
`target/borrowed-decision/resilience-{before,after}.json`. The exercised bad
management, compilation, persistence and publisher behavior preserved DNS
service. These short tests are not a production-host soak or a universal bound
on latency. Native systemd sandbox activation remains a deployment-host check.

The rebuilt release passes the clean network-isolated container gate: non-root
installation, UDP/TCP, authenticated warm DoT/HTTP2 DoH, reviewed/conditional/
scheduled lists, shadow/upgrade/backup/restart recovery, annotations and expired
exceptions. The final documentation repack retains the tested runtime payload;
all manifest hashes, current source identity and the measured binary digest are
verified in `target/borrowed-decision/release-verification.json`.
See `deployment-smoke.log` for the exact gate. No host service, public resolver,
firewall rule or performance permission was changed.
