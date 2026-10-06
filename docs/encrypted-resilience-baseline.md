# Encrypted-upstream resilience baseline

Measured 2026-10-05 on AMD Ryzen 7 9800X3D (8 cores / 16 threads), Linux
7.2.5-3-omarchy x86_64, rustc 1.98.1. Shared, unpinned workstation; release thin
LTO and one codegen unit. No other build/test/fuzz job ran during the final
rehearsal. Ordinary desktop activity was not isolated.

Measured daemon SHA-256:
`c3752505e50e193909bf94cf22f3fd0846580b1d15db6f7201e2d478748e7a6f`.

```sh
cargo build -p rustwalld-dns --release --locked
cargo run -p rustwalld-dns --release --example encrypted_resilience --locked -- \
  --binary target/release/rustwalld-dns --duration-ms 5000 \
  --output target/encrypted-resilience-final.json
```

The real child appliance uses two DNS workers, separate control workers, SQLite,
64 DNS-cache entries, 64 decision-cache entries, 32 logical inflight slots, a
64-event telemetry queue and 256 retained history rows. Four local certificate
fixtures provide two alternating primary/fallback pairs per transport. A profile
allows two connections per address and an 80 ms per-address deadline. Successful
fixture replies deliberately wait 10 ms. Client receive timeout is 500 ms.

Two UDP clients per lane continuously issue blocked, cache-probe or unique fresh
A queries. Each phase is five seconds, with a possible final request extending
the sample window. TLS and HTTPS run sequentially (20 phases total). Timing starts
before client wire encoding and ends after parsing/validating the reply; query-name
construction is excluded. The fixture/client runtime has four workers. It shares
the workstation with the child, so this is not a capacity claim or strict network
performance gate. No public DNS is queried.

Histograms are bounded: exact microseconds through 1 ms, then 100 µs upper-bound
buckets through 1 s. No sample clipped. The `cached` lane probes one warmed name
per phase; FIFO eviction can cause rare misses, and promotions deliberately change
the generation/cache key. Its latency includes those misses. Actual DNS-cache-hit,
coalesced and logical-upstream counters are recorded separately. Their sum matches
all unblocked queries in each steady phase, proving blocked requests bypassed the
resolver. Fresh names differ across phases and clients.

Observed p99 microseconds:

| Phase | TLS blocked | TLS cache probe | TLS fresh | HTTPS blocked | HTTPS cache probe | HTTPS fresh |
|---|---:|---:|---:|---:|---:|---:|
| Healthy baseline | 15 | 16 | 22,000 | 16 | 16 | 22,100 |
| Primary stalled before reply | 15 | 16 | 93,100 | 15 | 16 | 98,900 |
| Primary stalled body | — | — | — | 15 | 16 | 104,100 |
| Primary malformed DNS | 16 | 17 | 22,000 | 17 | 17 | 22,000 |
| Primary reset/close before reply | 16 | 17 | 22,000 | 17 | 17 | 22,100 |
| Primary oversized HTTP headers | — | — | — | 17 | 18 | 22,100 |
| Both return invalid DNS | 152 | 152 | 890 | 164 | 164 | 931 |
| Both stall | 16 | 16 | 174,800 | 15 | 16 | 179,000 |
| Recovery | 16 | 16 | 22,000 | 16 | 16 | 22,000 |
| Concurrent promotions | 16 | 16 | 103,100 | 15 | 16 | 105,100 |
| Recovery after promotions | 16 | 16 | 22,000 | 15 | 16 | 21,000 |

The complete malformed-response phase repeatedly discards connections and issues
new encrypted lookups without the healthy fixture's 10 ms pacing. Local-path p99
then rises to 152–164 µs; cache-probe p99 exceeds the 150 µs design target. This is
a measured limitation requiring investigation, not proof of a particular CPU
bottleneck. All local-path p99.9 values remain at or below 200 µs in this run.
Fresh misses during complete outages correctly receive SERVFAIL; their short
invalid-response latency is not successful resolution performance. Dual-stall
latency includes two sequential deadlines, client work and scheduler overhead.

TLS returned 15,958,017 phase replies; HTTPS returned 19,670,395. Across all lanes
there were zero client timeouts, incorrect replies or histogram clips. Replies
check ID, question, direction, opcode, truncation, response code and expected A
data. Steady healthy/fallback phases reconcile fixture exchanges with logical
lookups. Expected cache evictions were observed (e.g. TLS baseline: 895 fresh
queries, 910 logical lookups and 941,948 cache hits).

Each transport's initial burst sends 16 identical fresh misses: one logical
lookup, 15 coalesced followers, one stalled primary exchange and one successful
fallback exchange. No inflight overloads occurred.

TLS promoted 26 revisions during mixed traffic; HTTPS promoted 27. Each promotion
holds a named old-generation request at the healthy fallback until the authenticated
API has validated, asserted, persisted and published the new revision. The held
request is confirmed still pending after publication, then completes correctly.
The old endpoint pair closes before reuse. Publication-through-retirement times
were 23–114 ms (TLS) and 23–107 ms (HTTPS), excluding probe admission/preparation
and the 50 ms pause between promotions. Final known-good recovery publishes a new
generation (28 TLS, 29 HTTPS). After graceful exit, read-only SQLite verification
matches the runtime generation and complete recovered policy content. Retained
history is 256 rows; revisions are 28/29, within the configured 32-revision bound.
This run does not force revision eviction; longer repetitions exercise that bound.

Linux /proc socket observations match namespace TCP rows to the child-owned FD
inodes and fixture ports. Polling runs about every 10 ms plus file/API work:

| Resource | TLS peak | HTTPS peak | Quiescent / limit |
|---|---:|---:|---|
| Owned upstream TCP sockets | 5 | 5 | 2 idle, sampled cap 8 |
| Logical inflight lookups | 4 | 4 | 0, configured cap 32 |
| DNS-cache entries | 64 | 64 | 64, configured cap 64 |
| Total child FDs | 26 | 26 | 23 |
| Native threads | 7 | 7 | 7 |
| RSS KiB | 12,600 | 13,348 | 12,600 / 13,348 |

Initial RSS was 11,388 / 11,504 KiB. These RSS observations include SQLite,
allocator retention and all daemon work. They are not allocations/query or
proof of leak freedom. Native threads do not count Tokio tasks. Sampling cannot
prove every instantaneous bound. Current + retiring endpoint pairs supply the
eight-socket workload cap; explicit retirement and zero active fixture connections
after graceful exit check eventual driver/socket disposal. The report separates
the last periodic sample from the quiescent snapshot.

Evidence: target/encrypted-resilience-final.json and .log; earlier debug and
300 ms CI-sized reports; an eight-clients-per-lane short run with zero timeouts or
wrong answers (peak 10 inflight lookups). CI uploads its 300 ms report separately.
The workspace passes 55 tests, fmt and all-target/all-feature Clippy. Cargo audit
(272 dependencies) and deny pass. Two example unit tests validate histogram
rounding, merging and timeout/error/clipping accounting. TLS/HTTPS regression
tests include the new close-before-reply and HTTP2-reset fixture modes.

Only fixtures, development dependencies, the rehearsal, CI and documentation
changed. Parser fuzzing and browser flows were not repeated because production
parser/UI behavior did not change. No allocation or CPU/query claim is made.
The 100-second run and short high-client check are regression rehearsals, not a
production-host soak. Physical disk exhaustion, native systemd activation,
long-duration memory growth and independent network clients remain separate work.
