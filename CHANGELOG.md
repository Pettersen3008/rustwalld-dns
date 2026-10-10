# Changelog

## 0.1.0 — unreleased

- Dev-only proptest models compare CLOCK eviction with a rotating queue and
  cache removal/regrowth with a map, and stress DoT/DoH cancellation across
  admission, connection setup and active requests. They check reply identity,
  per-connection limits, capacity recovery and socket/permit disposal; see
  [test depth](docs/property-tests.md).

- Opt-in serve-stale returns retained expired answers with TTL 30 only after
  every upstream fails, within a validated maximum age of one day. Default off;
  policy blocks/rewrites, temporary deadlines and upstream partitions remain
  enforced. Adds `rustwalld_stale_answers_total` and `stale` history sources;
  uncacheable refreshes invalidate older answers. See [setting and tests](docs/serve-stale.md).

- DoT pipelines eight pending queries per pooled connection, with unique message
  IDs, out-of-order reply matching, cancellation cleanup, strict connection
  retirement and bounded writer/admission queues. Local failure tests and the
  `dot_concurrent` benchmark cover the shared connection lifecycle; see
  [measurements](docs/dot-pipelining.md).

- Explain the encrypted rehearsal's DoH latency gap: its one-stream fixture
  serialized two clients. With only the fixture limit changed to 100, HTTPS
  fresh p99 falls from 22.1 to 11.1 ms with the same daemon; TLS stays at 11.1 ms.
  Add `--https-streams` and an overlap/lifecycle test ([evidence](docs/doh-latency.md)).

- DNS-over-HTTPS multiplexes up to eight requests per HTTP/2 connection within
  the existing socket cap: 32 concurrent misses against a 10 ms server complete
  in 22 ms instead of 178 ms (~8x throughput, [evidence](docs/doh-design.md)).
  Refused streams are retried once; timed-out requests retire their connection.
- Query path is 2–16% faster than before this review on every warm wire
  scenario with unchanged allocation counts ([evidence](docs/engine-split.md)):
  replies finalize in place, and rewrite answers are grouped by record type at
  compile time (`CompiledPolicy::rewrite` returns a borrowed slice).
- Every public item of the library crates is documented and
  `#![warn(missing_docs)]` keeps it so; `cargo doc` is clean with
  `-D warnings`. Truncating casts use checked conversions, functions over 100
  lines were split, `ResolveError` no longer exposes `h2::Error`,
  `Forwarder::health()` is an accessor and public enums that may grow are
  `#[non_exhaustive]`.
- Management API: every mutation requires `If-Match` (428 when missing); `Host`
  must be an IP literal or `localhost` (421 otherwise, against DNS rebinding);
  tokens compare as SHA-256 digests in constant time and 401s carry
  `WWW-Authenticate: Bearer`; extractor errors use the `{"error": ...}` shape;
  `/healthz` bypasses request admission; configuration-sized responses and
  compilations share a separate limit of two and serialize from the pinned
  snapshot without cloning; the idle timeout no longer resets a connection whose
  request is still being processed. `ControlService` fields are private: use
  `engine()`, `listen()`, `store()`, `is_mutating()`, `queue_refresh()`,
  `preview_download()` (now using the configured compiler) and friends.
  Candidate cloning, serialization and diffing run off the async executor, and
  configuration types implement `PartialEq`/`Eq`. `max_udp_upstream_waits` is
  configurable (default 1,024).
- Filter matching walks each name once over merged allow/block indexes with a
  per-process seeded foldhash: 22–80% faster evaluation, 14–30% faster
  compilation, unchanged decisions and memory ([evidence](docs/filter-matching.md)).
- `BoundedCache` evicts with CLOCK (second chance) and hashes each key once:
  hot entries survive one-off names, cache hits are 8–25% and insertions ~2x
  faster ([evidence](docs/cache-eviction.md)).
- The response cache and coalescing are keyed by upstream content identity
  (`UpstreamId`) instead of policy generation, so publishing unchanged upstream
  profiles (including scheduled list refreshes) keeps warm answers.
  `Resolver::lookup`/`forward` split the synchronous probe from forwarding.
- DNS ingress: `Engine::prepare` answers refusals, blocks, rewrites and cache
  hits synchronously; only misses wait, under a separate
  `max_udp_upstream_waits` bound, so a slow upstream cannot starve local
  answers. EDNS options are ignored (RFC 6891) and never forwarded instead of
  refused. `Engine::answer` takes a `Transport`; the positional `Engine::new`
  is removed. Listener errors such as `EMFILE` pause only that listener
  instead of stopping DNS. New overload and listener-error metrics.
- Upstream TCP fallback and DoT send one framed write with `TCP_NODELAY`;
  upstream UDP buffers match the advertised size, retrying oversized replies
  over TCP.
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
