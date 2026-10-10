# Release preparation

Five libraries are prepared as a coherent 0.1.0 dependency graph:
`rustwalld-dns-filter`, `rustwalld-dns-resolver`, `rustwalld-dns-policy`,
`rustwalld-dns-core`, `rustwalld-dns-runtime`. The standalone app is distributed
as a native bundle and has `publish = false`.

Run the required contributor checks and `python3 scripts/verify-crates.py` from a
clean checkout. Cargo packages and builds the selected archives in dependency
order using its temporary local registry. The script then extracts those
archives and runs the independent core, component and runtime consumers using
registry versions patched to the extracted sources. This verifies the archive
graph, licenses and examples without publishing or using checkout source paths.
`--allow-dirty` is available for reviewing work in progress. No verification is
waived with `--no-verify`.

Before registry publication:

- Confirm repository visibility and private security reporting before making the
  project public; the development repository is private.
- Confirm ownership/availability of all five registry names and authorize actual
  publication. A successful local archive check does not reserve names.
- Review license/trust-anchor notices, changelog, public docs, API support policy
  and locked dependency scans. Verify stable and Rust 1.95 consumer graphs.
- Publish filter and resolver first, then policy, core and runtime. Wait for each
  registry version to resolve and run the next crate's registry dry run before
  publishing it. Use matching version constraints; do not upload broken sibling
  references. Tags and release artifacts must identify the verified source.

Registry uploads and native service activation require separate authorization.
The development repository is private and has no GitHub Actions workflows. The Linux appliance additionally requires native
systemd/install/upgrade/recovery verification on the deployment host and a clean
24–72-hour representative-network soak. Local/container checks cover reproducible
fixtures and do not replace those gates.

Rust 1.95 is the tested MSRV. Performance/release builds pin Rust 1.99.0 separately.
API changes in 0.1.x may break Rust source compatibility with a changelog entry;
prefer additive changes and document migrations. Observable standalone formats
remain protected by integration/process/browser/recovery tests. No untested
Windows/macOS appliance support is promised.

The optional standalone compiler is built with `python3 scripts/release.py
--parallel-compilation`. Its manifest records `features: ["parallel-compilation"]`;
default bundles record an empty feature list. This identifies the owned two-worker
backend in addition to the binary hash. With `--skip-build`, the caller must first
build the matching Cargo feature mode and console; verify the binary SHA-256
against the bundle manifest. Library features remain independently selectable.

The latest default-bundle rebuild and installed stale-outage smoke are described
in [release rebuild verification](release-rebuild.md). Detailed logs, manifest
hashes and archives remain local under `target/review/release-rebuild/`.
