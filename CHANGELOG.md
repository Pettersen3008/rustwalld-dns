# Changelog

## 0.1.0 — unreleased

- SQLite worker: blocking receive with a 10 ms batch flush instead of a 10 ms
  sleep-poll; in-memory retained-row count instead of `COUNT(*)` per batch (the
  `queries_created` index is dropped; older binaries recreate it); history at
  `synchronous=NORMAL`, revisions/pointers at `FULL`; new files are 0600 and WAL
  mode is checked. `RevisionSummary.id` and `HistoryEntry.{id,generation}` are
  `u64`.
- Startup: the file policy is compiled only to seed a new store (no double
  compilation, and a broken file no longer blocks a stored revision); restart
  after retention no longer resurrects revision 1 with new content; an
  unrestorable shadow is cleared instead of aborting startup. Malformed stored
  revision JSON and real pointer read errors are reported (`StoreError` is typed
  and `#[non_exhaustive]`; `Store::load` added), and maintenance names dangling
  pointers. App `Config::read` validates settings; `Config::validate` still
  checks the policy for `--check-config`.
- A wildcard DNS listener (`0.0.0.0:53`, `[::]:53`) no longer rejects remote
  upstreams on the same port; self-forwarding checks compare canonical
  addresses, so `[::ffff:127.0.0.1]:53` is rejected for `127.0.0.1:53`.
- Explanations (`PolicySnapshot::explain`, `GET /api/v1/explain`) include
  `permitted`; the console labels non-admitted clients as dropped. Assertion
  failure messages summarize the matched rule with at most three sources.
- Policies with identical list inputs share one compiled `FilterSnapshot`, and
  distinct compiled rules are capped at 10,000,000 per snapshot (previously per
  policy, so reused lists multiplied memory).
- IPv4-mapped IPv6 client bindings and allowed networks now match their IPv4
  clients (compiled as the IPv4 network); mapped prefixes below /96 are rejected.
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
