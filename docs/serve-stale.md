# Serve-stale contract

Opt-in [RFC 8767](https://www.rfc-editor.org/rfc/rfc8767.html) fallback is a
startup cache setting, independent of revisioned policy. Zero disables it.
`ServeStale` validates a private duration capped at one day; engine/library
callers cannot construct an unchecked enabled window. Runtime/app configuration
uses `serve_stale_max_staleness_secs`, validated before serving.

The normal minimum-RR-TTL expiry remains unchanged. The bounded CLOCK cache
retains expired entries until replacement/eviction; they count towards the same
capacity and no extra stale map exists. Eligible expired answers use TTL 30 for
all records. Each caller checks staleness after the upstream flight fails;
coalesced callers cannot receive a stale result pinned before the retention
boundary. Stale reads do not update insertion/expiry times. Valid positive and
SOA-backed negative entries share this behavior. AD remains clear.

Policy runs before cache lookup, using the pinned immutable generation. After
an upstream wait, the engine rechecks temporary allowances, caps TTLs to their
remaining lifetime, and restores blocking if the exception expired. Stale does
not bypass rewrites/blocks or cross the existing upstream identity/question/DO/CD
cache key. `rustwalld_stale_answers_total` increments only after that final policy
check, and telemetry/history use source `stale`. Console cache filters and traffic
counts include stale answers, while the query path column retains `stale`.

Only `Forwarder::resolve` exhaustion triggers fallback. Flights distinguish
upstream failure from shutdown; logical overload, server shedding and shutdown
return SERVFAIL. No background refresh, per-query control-plane work, extra
connection race or new network deadline is introduced. An uncacheable completed
refresh invalidates the old key, preventing resurrection of known superseded
data. Errors and invalid envelopes leave the old state intact, as required by
[RFC 8767 section 4](https://www.rfc-editor.org/rfc/rfc8767.html#section-4).
BoundedCache removal swaps the last slot into the released position and
updates its index/clock hand; existing CLOCK insertion/hit behavior is preserved.
The default-off path does not introduce a new forwarding-key clone.

Tests use local UDP fixtures for real warming, expiry, SERVFAIL/timeouts,
successful fallback and recovery. They cover default off, coalesced replies,
blocks/rewrites after publication, changed upstream identity, temporary TTL caps
and a prepared query finishing after expiry, overload/shedding/shutdown, and
zero-TTL refresh invalidation. Synthetic-time cache tests cover exact retention
boundaries, immutable stale deadlines, all TTLs, capacity/eviction and DO/CD
partitions. Configuration tests cover omission, zero, the one-day limit and
rejection above it. Evidence lives under `target/review/serve-stale/`.

Local fmt, all-target/all-feature locked Clippy, locked workspace tests and Rust
1.95 all-target checking pass. Audit and deny are clean. The stale-cache target
(including invalid-envelope preservation) and cache removal target each ran for
30 seconds without failure. Console build/format and the desktop/mobile cached
filter/traffic regression pass. All logs/traces remain under the evidence path.
