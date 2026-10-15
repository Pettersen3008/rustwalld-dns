# Local verification and evidence

Run from the repository root with the pinned toolchain. This project intentionally
has no hosted CI/CD. All network tests use local mock resolvers; never query public
DNS. Save command output under ignored target/review/ and summarize results in the
story. Run benchmarks serially while build, browser, fuzz and container work is idle.

## Required for meaningful changes

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
python3 scripts/check-docs.py
```

Run relevant focused regressions first. Changes to scripts/packaging also need
`python3 -m unittest discover -s scripts/tests -v`. The deployment test repacks
prebuilt inputs; first build the release binary and console. Repacking alone does
not prove those inputs were built from the current source.

## Libraries features and compatibility

```sh
cargo +1.95.0 check --workspace --all-targets --locked
cargo +1.95.0 test --workspace --locked --target-dir target/msrv
cargo test --workspace --all-features --locked
cargo bench --workspace --no-run --locked
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps --locked
python3 scripts/verify-consumers.py
python3 scripts/verify-crates.py --allow-dirty
```

Use clean source for final archive/release validation. Optional feature tests
supplement default-feature tests. Validate serial/parallel identity when compiler
code changes; [parallel compilation](parallel-compilation.md) explains the bounds.

## Console

```sh
cargo build -p rustwalld-dns --locked
bun install --cwd web --frozen-lockfile
(cd web && bun run format:check && bun run lint && bun run build)
mkdir -p target/tool-tmp
(cd web && TMPDIR="$PWD/../target/tool-tmp" bun run test)
(cd web && TMPDIR="$PWD/../target/tool-tmp" bun run test:auth)
(cd web && bun audit)
```

Install fixture Chromium once with `cd web && bunx --no-install playwright install
chromium` if absent. Tests start a real daemon and loopback mocks, not a prototype
API. Never reuse a service already on fixture ports. Inspect changed desktop/mobile
screens visually and check keyboard/theme/error states per [design](design.md).
HTTPS browser fixtures intentionally trust their self-signed certificate; Rust
secure_ingress tests independently verify trust, hostname and plaintext rejection.

## Security dependencies and parsers

Run `cargo audit` and `cargo deny check` in the root and fuzz workspace; Bun audit
for dependency/UI changes. Use relevant seeded sanitizer fuzz targets separately
from load/benchmark work. Install cargo-fuzz/nightly if missing; record any gap.

```sh
cargo audit
cargo deny check
(cd fuzz && cargo audit && cargo deny check)
# Fresh seeded corpora keep initialization inside the smoke budget. Keep older
# accumulated corpora separately for longer regression/research runs.
mkdir -p target
FUZZ_RUN_DIR=$(mktemp -d target/fuzz-smoke.XXXXXX)
mkdir -p "$FUZZ_RUN_DIR/filter_compile" "$FUZZ_RUN_DIR/engine_prepare" "$FUZZ_RUN_DIR/migration"
cp fuzz/seeds/filter_compile/* "$FUZZ_RUN_DIR/filter_compile/"
cp fuzz/seeds/engine_prepare/* "$FUZZ_RUN_DIR/engine_prepare/"
cp fuzz/seeds/migration/* "$FUZZ_RUN_DIR/migration/"
timeout --kill-after=5s 90s cargo +nightly fuzz run filter_compile "$FUZZ_RUN_DIR/filter_compile" -- -max_total_time=30 -max_len=524288
timeout --kill-after=5s 90s cargo +nightly fuzz run engine_prepare "$FUZZ_RUN_DIR/engine_prepare" -- -max_total_time=30 -max_len=4096
timeout --kill-after=5s 90s cargo +nightly fuzz run migration "$FUZZ_RUN_DIR/migration" -- -max_total_time=30 -max_len=1048576
```

The outer timeout includes compilation. Build the target separately with
`cargo +nightly fuzz build TARGET` if a cold build exceeds that budget. A timeout
is incomplete verification, not a pass. LibFuzzer's max_total_time can be consumed
by initialization/replay of a large accumulated corpus; preserve that result and
use fresh checked-in seeds when a bounded mutation smoke is intended.

Other targets are declared in fuzz/Cargo.toml: wire messages, TLS/DoH responses,
policy checks, cache/stale, service records, SafeSearch/catalogs, schedules,
credentials, identity and inventory. Seed the affected target from fuzz/seeds/;
keep discriminator bytes intact. A short run is supplementary evidence, not a
security audit or proof of parser safety. Preserve crashing inputs locally.

## Packaging failure recovery and deployment

```sh
python3 scripts/release.py
python3 -m unittest discover -s scripts/tests -v
scripts/deployment-smoke.sh target/releases/RELEASE.tar.gz
cargo run -p rustwalld-dns --release --locked --example resilience -- --binary target/release/rustwalld-dns --output target/resilience.json
```

Replace RELEASE with the actual produced archive. [Install/recovery](../operations/install.md)
and [containers](../operations/container.md) document isolated fixture commands,
encrypted outage, control-plane soak, container, Unbound and DHCP checks. Use the
matched shipping binary and manifest when making release claims. Keep host services,
network stack and router DNS/DHCP unchanged unless explicitly authorized.

Native systemd activation, target ARM hardware, independent security review and a
24–72-hour representative-network soak are separate [release gates](../product/scope.md).
Do not mark those Done using local/container evidence.

[Soak protocol](soak.md) and [security review scope](security-review.md) distinguish
future lab/reviewer acceptance from prepared local fixtures and source packets.
