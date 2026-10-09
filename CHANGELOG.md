# Changelog

## 0.1.0 — unreleased

- Startup no longer fails when a stored temporary exception has more than seven
  days remaining on a lagging wall clock: compilation clamps the monotonic
  deadline. The seven-day limit applies at intake to exceptions that are new
  relative to the live revisions (`PolicyConfigSet::validate_new_exceptions`).
- Policy validation errors are structured (`PolicyError::{Field, Count,
  Generation}`) and name the failing configuration path with a bounded, escaped
  value. Names reject whitespace-only text and bidirectional formatting controls.
  Upstream addresses are judged by their canonical IP. `PolicyError` and
  `AssertionFailure` are `#[non_exhaustive]`; `PolicyListStats`,
  `MAX_METADATA_BYTES` and `is_unicast_destination` are exported; compiled
  snapshots implement summary `Debug`.
- Optional bounded Rayon compilation for large filters/policies, with deterministic
  IDs/provenance and the original validation/assertion gates. Durable runtime can
  share one owned pool across startup, restoration, checks and staging; standalone
  opt-in builds use two workers. Default constructors/builds remain sequential.
- Compilation-only Criterion, fresh-process memory comparisons and bounded local
  UDP histograms during reload; retain unfavorable workload/latency measurements.

- Pin development/release builds to Rust 1.99.0 while retaining the libraries'
  Rust 1.95 minimum. Normalize query names without copying an intermediate
  Hickory name; preserve protocol behavior and escaped-label semantics.
- Use fat LTO for standalone release builds after comparing unchanged engine,
  filter, cache and encrypted-transport benchmarks; retain panic unwinding.
- Ignore nested Cargo targets, generated local configuration and environment
  overrides; retain reproducible lockfiles, benchmark fixtures and fuzz seeds.
- Reusable libraries: rustwalld-dns-filter, rustwalld-dns-resolver,
  rustwalld-dns-policy, rustwalld-dns-core and optional rustwalld-dns-runtime.
- Read-only compiled snapshots and checked generation/version publication with
  abortable reservations; restored engines retain durable generation high-water
  marks and start with empty volatile caches.
- Typed durable revision service, bounded worker replies and explicit runtime
  cancellation/drain, independent of HTTP, CLI and process signals.
- Organized core, policy, route and test modules, public examples, independent
  consumer fixtures, checked archives and a tested Rust 1.95 minimum.
- Standalone DNS/HTTP/configuration/console/SQLite behavior remains compatible.
  Internal Rust package names/imports and mutable engine fields changed before
  the first public library release; direct ArcSwap writes require the controller.

The baseline remains at Git commit d7fc877. Native deployment and a clean
24–72-hour representative-network soak remain release gates.
