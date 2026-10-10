# Contributing

Start with [architecture](docs/architecture.md), [roadmap](docs/roadmap.md) and
[AGENTS.md](AGENTS.md). Work in complete, reviewable slices. DNS correctness,
security and predictable latency take priority over throughput.

The project is maintained by [@Pettersen3008](https://github.com/Pettersen3008).
Every contributor change must arrive as a pull request and receive the
maintainer's approval before merging. The root [CODEOWNERS](CODEOWNERS) covers
all files. New commits that change an approved PR's diff invalidate its approval; dependency updates
have the same review requirement. Auto-merge is disabled. The owner retains
administrative control for their own maintenance and release changes; other
contributors are not granted direct push or merge access.

Discuss substantial features or architecture changes in an issue before starting
a large implementation. Keep PRs focused and use the
[PR template](pull_request_template.md). Follow the
[community conduct](CODE_OF_CONDUCT.md); support and sanitized feedback go through
[SUPPORT.md](SUPPORT.md), and vulnerabilities go through
[SECURITY.md](SECURITY.md).

Contributions are licensed under the project's existing MIT OR Apache-2.0 terms.
Preserve third-party notices and include only code/assets you have the right to
contribute. No contributor license agreement is required.

This repository intentionally has no hosted CI/CD or `.github/` directory.
GitHub Actions are disabled. Contributors run checks locally and retain generated
evidence under ignored `target/review/`; summarize sanitized results in the PR.
The maintainer verifies changes locally before merging, including Dependabot PRs.

Use the pinned `rust-toolchain.toml` for reproducible local performance/release
work. Libraries support Rust 1.95 and edition 2024; local checks test that floor separately
from the pinned measurement toolchain. Linux is the verified appliance platform. A C toolchain is
needed for bundled SQLite; console work needs Node 22.12+ and npm.

Before submitting a meaningful change:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
cargo +1.95.0 check --workspace --all-targets --locked
cargo bench --workspace --no-run --locked
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps --locked
python3 scripts/verify-consumers.py
python3 scripts/verify-crates.py --allow-dirty
```

Use `cargo +1.95.0 test --workspace --locked --target-dir target/msrv` to test the
MSRV. Installation of development tools is separate: `cargo install cargo-audit
cargo-deny cargo-fuzz --locked`; fuzzing needs nightly. Run `cargo audit`,
`cargo deny check` and relevant fuzz targets for dependency/security/parser work.
[README](README.md) contains console, fuzz, deployment and benchmark commands.
Python orchestration checks use `python3 -m unittest discover -s scripts/tests -v`.

Network tests use local mock resolvers. Never query public DNS during checks.
Production code forbids unsafe, unwrap and expect; test fixtures may explicitly
allow unwrap. Keep compilation, persistence, JSON and management outside query
processing. No lock spans an await or network I/O. Keep all ingress, caches,
flights, connections, queues and telemetry bounded.

For performance changes, state a hypothesis and preserve an unchanged baseline.
Run workloads serially with matching toolchains, profiles, features, inputs and
instrumentation. Record hardware, allocations, correctness, unfavorable results
and uncertainty. Use `DNS_BENCH_SIZES` for larger filter sets. Do not relax DNS
semantics, remove history, change benchmark cases or add complexity to hit a
percentage. Profile before replacing Hickory or data structures. See
[benchmark methodology](docs/benchmarks.md) and [refactor evidence](docs/refactor-results.md).

Describe the concrete trigger and resulting behavior in pull requests. Explain
why a boundary changed and how it was verified. Keep implementation choices
local; avoid speculative traits, builders and feature matrices. Prefer typed
errors, explicit ownership, narrow imports and useful names. New tests should
exercise observable contracts and failure modes rather than mirror code.

Version 0.1 APIs may evolve with documented breaking changes. Stable standalone
configuration, HTTP and SQLite formats require migration/regression evidence.
See [release preparation](docs/releasing.md). Publishing and host activation are
separate actions; passing local checks does not complete a representative-network
soak.
