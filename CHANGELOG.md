# Changelog

## Unreleased

- Close plain DNS-over-TCP connections from sources outside `allowed_clients` at
  accept, so non-admitted peers can no longer hold `max_tcp_connections` slots
  for the idle timeout and starve admitted TCP clients (DNS-040).
- Exercise the appliance pipeline across a routed hop on three disposable VMs:
  path/admission proof, qualification, sentinel, cancellation and a declared
  routed-link fault with recovery (DNS-039).

- Add bounded offline reconciliation of saved soak reports, distinguishing passing,
  failed and incomplete evidence while retaining provenance/coverage limits.
- Open native soak run/sample leaves without following symlinks or waiting for FIFO
  writers; preserve atomic handoff and document trusted-parent/filesystem limits.
- Initialize entering-phase metadata before sampling so rejected observations
  retain accurate failed-run timing and prior completion origins.

- Return only committed Hickory bytes after response truncation, removing partial
  record tails while preserving transport limits and complete fitting replies.
- Verify target-local HTTPS collection with explicit bounded CA/SAN trust; reject
  environment trust/key logging and retain PID/socket/framing/deadline checks.
- Preserve CD in soak requests, require complete wire oracles and advertised UDP
  bounds; add large downstream reply/fallback and live SIGINT acceptance across
  isolated disposable VMs with verified teardown.

- Extend the private DNS fixture with explicit private IPv4 binding and fixed
  Hickory reference exports; qualify collector/driver, failure handling and Docker
  backup/restore across two isolated disposable VMs with verified teardown.

- Add a bounded target-local Linux soak collector with PID/API ownership checks,
  real resource/counter samples and fail-closed HTTP/storage/deadline validation.

- Add a bounded remote soak example with strict run records, UDP/TCP answer
  oracles, explicit load/cancellation accounting, resource collector input and
  capped window/bin evidence; preserve existing local rehearsals.

- Correct control/encrypted rehearsal report descriptions to the shared
  2-second, 21,001-bin histogram; sampling and query behavior are unchanged.

- Add an explicit fresh-VM systemd mode to the package smoke, with effective
  sandbox probes, unsafe-target refusal and failure cleanup. Verify native
  service/DNS/recovery on Debian 13/KVM; leave the service disabled and guest off.

- Extend isolated package smoke checks with service-user permissions and
  same-binary release reversal; prepare bounded native-host acceptance/recovery.
- Correct package-fixture TTL checks to accept the documented zero-TTL schedule
  boundary while retaining typed record content and source TTL bounds.

- Bring the Local DNS Add action into the first phone viewport, identify its
  selected policy, and focus newly added records across paging. Compact policy
  publication controls while retaining guidance, review and draft safeguards.
- Separate policy, network, upstream and assertion editors and workbench
  presentation from shared draft/publication handlers.

- Restore keyboard focus to the initiating policy-review button after asynchronous
  candidate loading; use main content after promotion or stopping removes it.
- Make cancellation review guidance accurate for imported and legacy list versions.
- Split engine admission, decisions, forwarding, outcomes and wire handling into
  private modules while preserving public interfaces and query behavior.

- Prevent malformed appliance TOML from dumping configuration values/unknown keys
  in CLI errors; retain a safe path and parse location for diagnosis.

- Add parameter-free HTTPS/SVCB ServiceMode local records and exact/suffix AdGuard
  pattern imports with source TTL, bounded RRsets and whole-pattern exceptions.
- Expose priority/target fields and usage guidance; reject AliasMode, parameters
  and value exceptions rather than discarding unsupported settings.

- Support descendant wildcard TXT/PTR/MX/SRV records and bounded AdGuard suffix
  pattern imports with TTL, same-pattern exceptions and concrete reply owners.
- Clarify independent apex/descendant editing, typed NODATA and address fallback;
  preserve legacy address limits, alias and priority blockers.

- Import exact AdGuard TXT/PTR/MX/SRV rewrite records alongside addresses, retaining
  source TTL and reviewed same-pattern TXT/PTR exception semantics.
- Validate typed response targets before conversion and preserve single-string TXT
  bounds; clarify typed import limits in the migration UI.

- Import supported rewrites from enabled AdGuard block feeds bundled in ZIP
  backups; combine custom/feed exceptions and budgets without fetching publishers.
- Reject ambiguous feed files/identities and retain explicit frozen-refresh guidance.

- Import exact AdGuard address rewrite RRsets and same-pattern whole/value
  exceptions; preserve ordinary blocking and reject partial exception coverage.

- Import disjoint literal exact/suffix AdGuard user-rule `$dnsrewrite` addresses
  with source TTL and explicit activation/priority/layout/expansion limits.
- Fix legacy rewrites surviving global/client filtering disable; block source
  whitespace normalization and unknown active rewrites in paused downloaded feeds.
- Update all five Cargo lockfiles to Rustls 0.23.46 for RUSTSEC-2026-0346–0349.

### Descendant wildcard address rewrites (2026-10-14)

- Compile bounded A/AAAA wildcard local owners with family-aware exact overrides
  and concrete question names on wire replies.
- Import the verified legacy subset, retaining disabled state and blockers for
  ambiguous addresses, unsupported patterns and alias/SafeSearch conflicts.
- Show apex/family limits in the local DNS editor and detect address/TTL/template
  changes in shadow comparison before reviewed promotion.

- Preserve disabled AdGuard exact rewrite entries during import instead of
  activating them. Review per-entry unknown settings, validate enabled types,
  select legacy/DNS rewrite containers independently and block ambiguous input.

- Correct AdGuard rewrite source-layout classification, accept exact family
  passthrough in older DNS-container exports, and honor the verified global rewrite
  activation switch without disabling ordinary filters. Malformed controls,
  ambiguous layouts and pre-31 disabled-state conflicts remain blockers.
  See [source layout and activation](docs/architecture/migration.md).

- Add exact A/AAAA family passthrough directives, typed explanation/shadow decisions,
  legacy AdGuard import and an IPv4/IPv6 editor. Ordinary filtering and response
  inspection remain active; wildcard patterns and ambiguous CNAME owners
  remain blockers. See [rewrite passthrough](docs/architecture/local-dns.md).

- Add explicit `adguard_v6` `$ctag` restrictions, typed/client/domain combinations,
  original rule provenance and explicit binding `filter_tags` separate from
  advisory annotations. Fresh imports preserve supported source tags in V6;
  unsupported values remain blockers. Partition decision caches by relevant tags,
  pin pending/shadow contexts and expose tag choices and explanations in the UI.
  AdGuard `$important` remains unsupported because its block-over-allow precedence
  conflicts with this repository's allow-first contract.

- Add explicit `adguard_v5` per-rule `$client` restrictions for IPs/CIDRs and exact
  binding names, with escaped source syntax and combined type/domain scopes.
  This slice introduced V5 imports, now superseded by V6; old interpreters stay frozen. Partition decisions using
  bounded compiled equivalence classes while retaining raw-cache sharing and
  pinned binding names. Add original/current/assertion UI traces and rename hints.
  Merge CIDR membership off the query path after profiling, and skip response-value
  filtering when every value rule excludes the client. Missing source names block
  named-rule migration. Schema 6 is unchanged; downgrade needs a compatible backup.
  See [client rule scopes](docs/architecture/filtering.md).

- Add explicit `adguard_v4` `$dnstype` selectors, optionally combined with
  `$denyallow`, and bounded reachable CNAME/address/HTTPS hint filtering with
  actual response types. This slice introduced V4 imports, now superseded by V6; older versions stay
  frozen. Partition typed decisions without filtering raw resolver cache entries.
  Add typed assertions, schema 6 response provenance and desktop/mobile traces.
  Unreleased Rust `Rule` literals use `scope` and `response_value`; `Assertion`
  requires `qtype`; event/history literals require optional `matched_type`.
  Legacy unscoped JSON is preserved. Downgrading requires a compatible backup.
  See [supported type rules](docs/architecture/filtering.md) for limits and verification.

- Add explicit `adguard_v3` per-rule `$denyallow` exclusions for exact/suffix/regex
  network rules, bounded scoped indexes, exclusion-aware deduplication and
  historical/current/assertion UI explanations. This slice introduced V3 imports; V4 now supersedes it;
  existing interpreters stay frozen and unsupported combinations block publication.
  Rust `Rule`/`MatchedRule` literals gain optional `denyallow`; it is omitted from
  JSON for unscoped rules. Older binaries require a compatible backup to downgrade.

- Add explicit `adguard_v2` compile-time `$badfilter` cancellation for supported
  masks/regex, retaining Native/legacy parser semantics and historical rule IDs.
  This slice introduced V2 imports, now superseded by V4, with bounded source review and per-policy lazy
  reports. Enforce the existing active-regex budget earlier to reject oversized
  sets promptly. `ListStats` Rust literals require `badfilters`/`disabled`; zero
  serialized counts stay omitted. Downgrade requires a compatible backup.

- Add opt-in per-policy parent-name routing for DS questions, preserving native
  question-name defaults, original filtering/questions and resolver cache identity.
  AdGuard imports use the setting and no longer require a DS incompatibility
  blocker. Add typed query explanations, recorded-type query-log requests and a
  scoped route editor. Verify cache/inflight generations, local overrides, aliases,
  migration and restart/backup/restore. `PolicyConfig` Rust literals require the
  new `ds_routing` field; legacy serialized configurations keep their default.

- Import bounded AdGuard per-client UDP and matching pinned DoT/DoH resolvers,
  independently of filtering inheritance. Preserve custom defaults, conditional
  route precedence and whole-client fallback; share identical profiles within the
  native 32-profile budget. Fix bracketed IPv6 imports and global profile limits.
  Add a pageable client/resolver review table, missing-identity/cache-type checks
  and an explicit DS parent-routing incompatibility for imported suffix routes.
  Verify cache isolation, reviewed promotion and CLI restart/backup/restore.

- Add frozen service catalog v2 with twelve first-party groups, including Netflix,
  Spotify, Twitch, Steam, Roblox, WhatsApp, Telegram and Signal. Preserve v1 defaults,
  coverage and historical IDs; expose explicit API versions and scoped provider
  references. Add searchable/category-filtered editing, reviewed version changes
  preserving weekly windows and guarded downgrade. Import new source selectors as
  drafts with compatibility blockers; verify v2 history, DNS and packaged recovery.

- Add per-policy weekly service schedules with explicit bundled IANA zones,
  block/allow periods, overnight/DST handling and bounded immutable filter variants.
  Recheck cached/in-flight replies, cap private TTLs without changing raw cache/OPT,
  and preserve actual schedule state in schema-5 history and shadow explanations.
  Add desktop/mobile draft editing, conservative AdGuard duration/zone translation,
  missing-window/empty-selection validation and packaged upgrade/restore checks.

- Add versioned first-party YouTube/TikTok/Reddit/Discord domain groups per client
  policy, authenticated coverage metadata and a compact Services editor. Reuse
  assertion-gated filters, CNAME/cache/shadow behavior and recorded rule provenance;
  translate AdGuard selectors with explicit coverage/schedule/inheritance blockers.
  Validate raw filter budgets before expansion and align historical rule limits.

- Add opt-in per-policy Google/Bing/DuckDuckGo SafeSearch and YouTube moderate/
  strict, versioned offline catalogs, shared compiled maps, filter-first CNAME
  routing, historical provenance and a desktop/mobile policy editor. Preserve
  supported AdGuard client/global settings with explicit compatibility blockers.
  Verify local DNS, shadow/caches, packaged persistence and recovery; reject
  structural CNAME loops for ordinary local aliases as well as SafeSearch.

- Keep UDP admission through bounded reply sends, and configuration-sized API
  admission through canceled serializers/shared response buffers. Admit rollback
  before loading/parsing its stored policy; add lifetime regressions.
- Move the console to React Router document routes, current TanStack Query/Table,
  owned shadcn/Radix components, Bun and Oxc. Organize feature folders, preserve
  drafts/bookmarks, abort disconnected requests, fetch configuration by version,
  and improve neutral/blue layouts, table density and keyboard navigation.
- Record [readiness, parity and resource evidence](docs/product/scope.md), and
  add an [optional Unbound guide](docs/operations/integrations.md), distro snippet and isolated
  compatibility fixture. Native-host and long network-soak gates remain pending.

## 0.1.0-alpha.1 — 2026-10-10

- Open the source as a public alpha under MIT OR Apache-2.0. Add maintainer-wide
  code ownership, contributor review/local-verification guidance, a PR template,
  conduct and support documents, private security reporting and explicit alpha
  deployment limits. Update public embedding/release guidance and the README's
  DoT pipelining description. Native deployment and the long network soak remain
  pending; crates.io publication is separate.

- Refresh native bundle documentation for pipelining, serve-stale and runtime
  snapshots, and make the disabled stale default explicit in the install template.
  Packaged non-root smoke now checks TTL-30 stale answers over UDP/TCP during a
  local encrypted-upstream outage, alongside upgrade/WAL recovery and independent
  library consumer checks. See [release verification](docs/engineering/performance.md).

- Split SQLite persistence and scheduled refreshes into focused internal modules,
  preserving SQL, durability and scheduling behavior. Encapsulate upstream,
  telemetry, resolver and history atomics behind plain `snapshot()` values;
  diagnostics and Prometheus names retain their existing contracts. See
  [module and snapshot boundaries](docs/architecture/embedding.md).

- Dev-only proptest models compare CLOCK eviction with a rotating queue and
  cache removal/regrowth with a map, and stress DoT/DoH cancellation across
  admission, connection setup and active requests. They check reply identity,
  per-connection limits, capacity recovery and socket/permit disposal; see
  [test depth](docs/architecture/upstreams.md).

- Opt-in serve-stale returns retained expired answers with TTL 30 only after
  every upstream fails, within a validated maximum age of one day. Default off;
  policy blocks/rewrites, temporary deadlines and upstream partitions remain
  enforced. Adds `rustwalld_stale_answers_total` and `stale` history sources;
  uncacheable refreshes invalidate older answers. See [setting and tests](docs/architecture/upstreams.md).

- DoT pipelines eight pending queries per pooled connection, with unique message
  IDs, out-of-order reply matching, cancellation cleanup, strict connection
  retirement and bounded writer/admission queues. Local failure tests and the
  `dot_concurrent` benchmark cover the shared connection lifecycle; see
  [measurements](docs/engineering/performance.md).

- Explain the encrypted rehearsal's DoH latency gap: its one-stream fixture
  serialized two clients. With only the fixture limit changed to 100, HTTPS
  fresh p99 falls from 22.1 to 11.1 ms with the same daemon; TLS stays at 11.1 ms.
  Add `--https-streams` and an overlap/lifecycle test ([evidence](docs/engineering/performance.md)).

- DNS-over-HTTPS multiplexes up to eight requests per HTTP/2 connection within
  the existing socket cap: 32 concurrent misses against a 10 ms server complete
  in 22 ms instead of 178 ms (~8x throughput, [evidence](docs/architecture/upstreams.md)).
  Refused streams are retried once; timed-out requests retire their connection.
- Query path is 2–16% faster than before this review on every warm wire
  scenario with unchanged allocation counts ([evidence](docs/engineering/performance.md)):
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
  compilation, unchanged decisions and memory ([evidence](docs/engineering/performance.md)).
- `BoundedCache` evicts with CLOCK (second chance) and hashes each key once:
  hot entries survive one-off names, cache hits are 8–25% and insertions ~2x
  faster ([evidence](docs/engineering/performance.md)).
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

### Homelab alpha expansion (2026-10-12–13)

- Add reachable CNAME and bounded regex filtering, typed local DNS/routes/block
  modes, scoped temporary actions and original-generation history explanations.
- Add supported-subset Pi-hole/AdGuard migration with strict compatibility and
  archive/parser bounds; source credentials and unsupported settings stay explicit.
- Add HTTPS/DoT/DoH ingress, local Argon2id/TOTP administration, scoped tokens,
  secure sessions/CSRF, privacy preferences and schema-4 history sequencing.
- Add setup/resolver profiles, advisory DHCP/UniFi/OPNsense inventory and reviewed
  peer policy copying; package non-root native/container recovery fixtures.
- Replace the console stack with React Router, TanStack Query/Table, Tailwind,
  shadcn/Radix, Bun/Oxc and feature folders; verify desktop/mobile/keyboard flows.
- Keep full source parity, additional transports/HA and deployment-host/long-soak
  gates explicit. See docs/readiness-review.md for evidence and limits.

### Migration parity follow-up (2026-10-13)

- Import supported Pi-hole v5 Teleporter JSON tables from bounded tar.gz without
  extracting paths or executing source SQL/settings; preserve group/client rules,
  local hosts/CNAME and supported block modes. Missing feeds/privacy/source gaps
  remain explicit compatibility blockers.
- Translate AdGuard literal domain routes and reuse matching destination DoT/DoH
  endpoint pins/trust. Refuse ambiguous profiles and incompatible mixed fallbacks;
  never use source bootstrap DNS as resolver endpoint IPs.
- Put backup import and its compatibility report first in the migration console;
  keep encrypted resolver help expandable and node copying below the import.


### Service aliases (2026-10-15)

- Add parameter-free HTTPS/SVCB priority 0 AliasMode to native local records and
  supported exact/suffix AdGuard pattern imports, preserving TTL and frozen whole
  exceptions. Reject mixed modes, multiple aliases and obvious self aliases.
- Accept priority 0 in the structured editor and explain client follow-up and
  advisory root-target unavailability. Service parameters and value exceptions
  remain blockers; no service-alias chasing or Additional synthesis is added.


### Service endpoint ports (2026-10-15)

- Add typed optional port parameters to HTTPS/SVCB ServiceMode local records and
  supported AdGuard pattern imports. Preserve explicit port 0 distinctly from no
  override; reject unknown/duplicate parameters and AliasMode parameters.
- Add optional port editing/removal and clarify client-default behavior in the
  console. Parameter-free native configurations remain valid; Rust constructors
  now supply a ServiceParams field. No endpoint networking/listener setup is added.
