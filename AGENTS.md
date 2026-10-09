# rustwalld-dns engineering contract

Build a local-first DNS policy/security engine. Work in complete tested slices.
The checklist and decisions are in docs/roadmap.md and docs/architecture.md.

This repository intentionally has no CI/CD or `.github/` folder. Run verification
locally and retain generated evidence under ignored `target/`. Do not add hosted
workflows unless the maintainer explicitly changes this preference.

DNS correctness, security and predictable latency take priority over throughput.
Use Hickory for DNS protocol handling. Profile before changing the parser or
introducing custom tries, lock-free containers, io_uring or zero-copy machinery.

The DNS libraries must not depend on app. Query processing must never perform
filesystem, database, HTTP management, filter/config parsing or JSON operations.
Never execute plugins on the query path. Keep networking, caches, inflight work,
connections and telemetry bounded. No lock may span an await or network I/O.

Compile complete immutable generations off the DNS executor. Validate policy
assertions and durable revisions before ArcSwap publication. Keep rule provenance
and generation identifiers. Rollback is a new generation; never reuse a live
cache key for changed policy content. Keep HTTP and SQLite failures away from DNS.

Production code forbids unsafe, unwrap and expect. Test/benchmark fixtures may
use unwrap explicitly. No claim of zero allocation or absolute performance
without allocator/hardware/workload evidence. Matchers accept normalized ASCII
names without a trailing root dot; allow rules take precedence over block rules.

Before shipping meaningful changes run:

    cargo fmt --all --check
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    cargo test --workspace --locked

Run the relevant Criterion or loopback benchmark for performance work. Use
DNS_BENCH_SIZES to expand filter datasets. Network tests use local mock resolvers
and must not query public DNS. Run cargo audit/deny and targeted fuzzing for
security/dependency/parser changes. Details are in README.md.

The current MVP deliberately refuses transfers, ANY, non-IN, signed queries and
nonrecursive requests. EDNS options are ignored (RFC 6891) and never forwarded;
upstream requests carry a fresh envelope. Extend protocol/cache semantics and
regression tests together when lifting those limits or forwarding options.
