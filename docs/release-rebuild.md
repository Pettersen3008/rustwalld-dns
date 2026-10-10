# Release rebuild verification

This pass refreshes the native default bundle after the DoH fixture diagnosis,
bounded DoT pipelining, opt-in serve-stale, property models and runtime/snapshot
refactor at `2001f30`. The bundle includes the new feature/design notes and exposes
`serve_stale_max_staleness_secs = 0` explicitly in its installed config template.

Build the executable and console from source; identical built inputs must repack
byte for byte. Verify manifest member hashes, executable permissions and the
default feature list. The Debian smoke runs with `--network none`, using local
CA-signed encrypted resolver/publisher fixtures and a real installed non-root
process. It covers upgrade preservation, SQLite WAL backup/restore, durable
active/shadow recovery, conditional retrieval, exception expiry and explicit
shadow promotion. It also enables stale fallback only in its isolated config,
expires a one-second answer, receives TTL-30 answers over UDP and TCP during
SERVFAIL, checks two stale metric increments and rejects an uncached outage query.

Commands and final evidence are retained under `target/review/release-rebuild/`:

```sh
python3 scripts/release.py --output target/review/release-rebuild/bundles
python3 -m unittest discover -s scripts/tests -v
scripts/deployment-smoke.sh target/review/release-rebuild/bundles/RELEASE.tar.gz
python3 scripts/verify-consumers.py
python3 scripts/verify-crates.py
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
cargo +1.95.0 check --workspace --all-targets --locked
```

The manifest/archive checksum and final source revision belong in the ignored
JSON evidence, avoiding a circular archive identity in these bundled notes.
On 2026-10-10 the full Rust/console build, 14 packaging/script tests, isolated
Debian recovery smoke and all three independent consumer workspaces passed.
All five library archives were packaged and built, then their extracted sources
passed the independent consumer checks. Checkout consumers were checked with
default/optional features on Rust 1.99 and 1.95;
workspace fmt, all-target/all-feature Clippy, tests and Rust 1.95 check passed.
Cargo audit and deny passed, and npm reported zero vulnerabilities during its
locked install. Dependency and production parser code are unchanged; this pass
adds no performance claim or benchmark algorithm change.

Local packaging/consumer checks do not publish libraries or create a GitHub
Release. Native deployment activation and the 24–72-hour representative-network
soak remain separate release exit gates.
