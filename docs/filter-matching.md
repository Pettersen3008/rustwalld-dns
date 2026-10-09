# Single-walk filter matching

`FilterSnapshot` previously kept four indexes (allow/block × exact/suffix) in
std `HashMap`s with SipHash. A name that matched nothing walked every label
twice, once for allow suffixes and once for block suffixes, with a SipHash per
lookup. hashbrown skips hashing for an empty map, so block-only configurations
paid about one lookup per label, but any allowlist doubled the work.

The snapshot now has one exact index and one suffix index. Each entry holds the
allow and block rule IDs for that name (`u32::MAX` is the "none" sentinel, so an
entry stays 24 bytes like before), and evaluation is a single walk:

1. An exact allow wins immediately.
2. Walk the name towards the root. The first suffix allow wins immediately; the
   first (most specific) suffix block is remembered. If the snapshot has no
   suffix allows at all, that block ends the walk.
3. Otherwise an exact block, then the remembered suffix block, then the default
   allow.

Results, including the reported rule and matcher, are unchanged. The test
`single_walk_matches_reference_on_random_overlapping_rule_sets` compares 4,000
random overlapping rule sets against a naive reference model; the previous
implementation passes the same test.

The indexes use hashbrown with `foldhash::fast::RandomState`, seeded per process.
Keys come from operator-selected lists, and query-path lookups never insert, so
lookups cannot build collision chains. The client-keyed decision and response
caches keep randomized SipHash ([cache eviction](cache-eviction.md)).

## Evidence (2026-10-09)

AMD Ryzen 7 9800X3D, Linux 7.2, Rust 1.99.0. Criterion runs used one pinned core
(`taskset -c 6`) with 1 s warm-up and 2 s measurement. The baseline is commit
`9396fa8`, run with identical benchmark code, which now adds mixed scenarios with
a 128-rule allowlist.

| `filter/…` (1M rules) | Before | After | Change |
| --- | ---: | ---: | ---: |
| `exact` | 14.6 ns | 11.5 ns | −21.7% |
| `suffix` | 36.0 ns | 11.6 ns | −67.8% |
| `miss` | 34.3 ns | 9.8 ns | −71.1% |
| `working_set` | 69.5 ns | 45.8 ns | −34.1% |
| `mixed_block_exact` | 36.2 ns | 11.4 ns | −68.4% |
| `mixed_block_suffix` | 101.9 ns | 25.0 ns | −75.1% |
| `mixed_allow_suffix` | 32.2 ns | 13.3 ns | −58.8% |
| `mixed_miss` | 96.3 ns | 20.2 ns | −79.6% |

Compilation of the 1M-rule fixture (`compilation` bench, cores 4–9): sequential
538 → 375 ms (−30%); two workers 408 → 350 ms (−14%); four workers 403 → 339 ms
(−16%). With a fresh process per size (`footprint` example), RSS and peak RSS
change by under 0.2% (1M: 205,112 → 205,640 KiB; 5M: 832,460 → 833,384 KiB),
and the payload estimate is identical. Raw output is kept in
`target/review/filter-matching/`.

```sh
DNS_BENCH_SIZES=100000,1000000 cargo bench --locked -p rustwalld-dns-filter --bench matching
cargo bench --locked -p rustwalld-dns-filter --features parallel --bench compilation
cargo build --release --locked -p rustwalld-dns-filter --example footprint
```
