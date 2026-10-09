# CLOCK eviction and single hashing for bounded caches

`BoundedCache` backs both the per-generation decision cache and the response
cache. It previously evicted in insertion (FIFO) order, kept a second copy of
every key in a `VecDeque`, and hashed each key twice: once to choose a shard and
again inside the shard's `HashMap`.

It now uses CLOCK (second-chance) eviction over a fixed slot array per shard,
indexed by a `hashbrown::HashTable` of slot positions:

- One randomized SipHash per operation (names are client controlled). Middle
  bits (`hash >> 32`) select the shard, independent of the low bucket bits and
  top control-tag bits hashbrown uses inside the shard.
- A hit sets the slot's reference bit. Insertion into a full shard sweeps the
  hand, clearing reference bits until it finds an unreferenced slot, so the
  sweep ends within one revolution. New entries start unreferenced, so a stream
  of one-off names cannot flush entries that are being read.
- The bound stays exact (`capacity / shards`, remainder spread), and no
  per-entry list or duplicate key is kept.

Alternatives: LRU needs a linked list and a write on every hit; SIEVE has a
similar hit ratio to CLOCK but needs mid-list removal. CLOCK has the same
locking shape as before: one short mutex per shard, never across awaits.

## Evidence (2026-10-09)

Same binary build settings, one pinned core (`taskset -c 6`), AMD Ryzen 7
9800X3D, Linux 7.2, Rust 1.99.0, Criterion 1 s warm-up and 3 s measurement.
Baseline is the FIFO implementation with identical benchmark code.

| Benchmark | FIFO | CLOCK | Change |
| --- | ---: | ---: | ---: |
| `response_cache_hit_message_clone` | 152.0 ns | 114.8 ns | −24.7% |
| `bounded_cache_working_set_hit` | 16.57 ns | 15.18 ns | −8.4% |
| `bounded_cache_u64_churn` (was `bounded_cache_fifo_churn`) | 32.06 ns | 17.41 ns | −45.7% |
| `bounded_cache_string_churn` (new, decision-key shape) | 68.39 ns | 34.99 ns | −48.8% |

`referenced_entries_survive_one_off_insertions` reads a hot key between 10,000
insertions of distinct keys; the FIFO implementation evicted it after 385.
Raw Criterion output is kept under `target/review/cache-clock/`.

```sh
cargo bench --locked -p rustwalld-dns-resolver --bench cache
```
