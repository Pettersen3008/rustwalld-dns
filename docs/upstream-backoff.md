# Bounded upstream failure admission

The measured malformed-response outage spent most sampled DNS-worker user CPU
in cryptographic leaf routines. Reconnecting for every new uncached name repeated
that work without increasing availability. The resolver now limits retries at the
endpoint boundary; filtering, cache hits and immutable snapshot publication do
not enter this gate.

## Contract

Each compiled endpoint owns one fixed-size state and a short mutex. Three
consecutive qualifying completions open a 250 ms cooldown. Requests skip a
cooling or probing endpoint and continue sequential fallback without waiting.
If all endpoints are skipped, DNS returns SERVFAIL, which is never cached.
After cooldown, the next request admits one recovery probe. A qualifying probe
failure backs off to 500 ms, 1 s, then at most 2 s. There are no background probe
tasks, endpoint maps, allocated timers or locks spanning an await/network I/O.
A successful probe restores normal admission and resets delay. Recovery is
traffic driven and can be delayed by the cooldown plus the configured exchange
deadline; generation publication creates fresh state.

Qualifying failures: connection/I/O, TLS authentication/protocol, HTTP protocol,
status/envelope, or rejected DNS replies. Certificate and response validation
remain mandatory, including for probes. SERVFAIL and REFUSED are validated,
query-specific outcomes: they reset a qualifying streak and restore a probing
endpoint but still trigger fallback for that query. Cancellation, local encoding
errors and deadlines do not penalize an endpoint. Deadlines include local pool
waits and cannot currently distinguish remote stalls from local admission delay.
Stall-only outages therefore keep the existing bounded timeout/fallback behavior.

Completions carry an epoch. Attempts already in flight when cooldown begins
cannot reset or extend it; late completions cannot release a newer probe. The
attempt guard releases a cancelled probe for the next query without increasing
its delay. Completed transport failures still contribute to diagnostic counters
regardless of epoch. Existing admitted requests may finish normally, including
on a retired generation. Counters are generation scoped.

## Observability and verification

The upstream API exposes backoff_skips, recovery_probes and admission state
(ready/cooldown/probing plus retry_after_ms). These are separate from attempts
and failures: skipped work was never an endpoint attempt. An elapsed cooldown
still reports cooldown with zero remaining milliseconds until traffic probes it.
Live API reads remain nontransactional; at quiescence attempts equal successes
plus all fixed failure counters. No query identities are stored in admission.

Deterministic clock-injected state tests cover maximum delay, stale completions,
one-probe exclusion, domain-specific outcomes and cancellation. Real local TLS
and HTTP/2 tests exercise bad DNS, fallback, fresh generations, simultaneous
queries, a stalled/cancelled probe and validated recovery. The process rehearsal
reconciles attempts + skips with lookups and keeps setup recovery outside its
latency windows. See upstream-backoff-baseline.md for measured results.

A meaningful alternative was a global retry budget or retrying each request.
A global gate would couple healthy profiles and clients; per-query retries retain
the measured handshake storm. Fixed endpoint state is simpler and isolates
failures without racing queries across public providers. Configurable strategy,
stall-stage classification and proactive health checks are deferred until needed.
