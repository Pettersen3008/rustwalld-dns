# Cache and encrypted-pool model tests

Proptest 1.11 is a resolver dev-dependency with only `std` enabled. Normal
resolver dependencies do not include it. Failure persistence goes directly to
ignored `target/review/property-tests/`, with a reproducible RNG seed supported
through `PROPTEST_RNG_SEED`.

The CLOCK oracle is a linear rotating queue with reference bits. All generated
keys collide into one uniformly sized shard, so exact hit/replacement/eviction
results can be compared without reproducing the hash-table/slot-index/clock-hand
implementation. Capacities include zero. A separate plain-map oracle checks
borrowed-key removal, replacement and regrowth, with enough capacity for the
entire generated key domain. Existing concurrent multi-shard tests and targeted
cache fuzzing continue to check bounded churn and removal with eviction.

Pool traces vary one to three physical connections, up to six rounds, one to
40 simultaneous callers per round, arbitrary cancellation masks and cancellation
delays. Zero cancels before first poll; later delays exercise connection setup,
capacity waits, active exchanges and completion races. A cancelled call may have
finished already; every surviving call must return its own question and expected
answer. Each round must finish with all request permits free and no pending
claims, then resolve a fresh probe successfully. This is the liveness witness for
capacity stranded by cancellation. Per-claim test assertions check DoT pending
and DoH stream limits, with additional observations while requests run.

After every trace, all forwarder/pool owners are dropped. The local peer must
observe every connection close, all physical permits must return, and all request
permits must remain free. Drivers/fixtures are local, with independent 10 ms
reply delays and sufficient server stream capacity. No public DNS or wall-clock
latency assertion is involved. These are finite randomized lifecycle tests,
complementing deterministic out-of-order/malformed/lost-connection regressions;
they are not an exhaustive scheduler proof.

Default cache models run 128 cases each, and pool models 32 each. Expand locally:

```sh
PROPTEST_CASES=128 PROPTEST_RNG_SEED=20261010 \
  cargo test --locked -p rustwalld-dns-resolver --lib properties
```

The expanded run passed 128 traces per model (512 cases, 16.6 s) on 2026-10-10.
Evidence, normal-dependency tree, MSRV/build gates and dependency checks are kept
under `target/review/property-tests/`.
