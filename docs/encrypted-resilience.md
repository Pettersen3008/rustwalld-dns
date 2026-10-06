# Encrypted upstream failure rehearsal

Automation note (2026-10-06): GitHub Actions and `.github/` were removed at
the maintainer's request. References to CI below describe historical verification;
run the documented commands locally and retain artifacts under `target/`.

Goal: exercise the real appliance under sustained blocked, cached and fresh DNS
traffic while encrypted upstreams fail and durable policy revisions are promoted.
Done means a repeatable local-only harness, short CI regression run, recorded
longer measurements, bounded resource observations, retirement and recovery
checks, plus the repository quality gates. This is a rehearsal, not a maturity claim.

Add a separate app example rather than enlarging the management-failure harness.
It starts a child appliance with real SQLite/API/runtime separation and reuses the
resolver's local certificate fixtures. Only fixture/dev dependencies change. The
DNS engine, caches and transport APIs remain unchanged unless a defect is found.

Run TLS and HTTPS sequentially. Each has two endpoint pairs with the same explicit
certificate identity and combined private roots. A profile tries a faulty primary
then a healthy fallback, with two connections per address and an 80 ms deadline.
Phases cover healthy forwarding, stalled replies, malformed DNS, reset connections,
HTTPS envelope failure, total upstream failure, recovery and promotion churn.
Separate UDP client lanes keep blocked/cached traffic independent of slow misses.
Queries verify ID, question, response direction, response code and A data. A
synchronized fresh-name burst verifies one logical lookup (one stalled primary
exchange plus one fallback exchange) for 16 duplicate misses.

During churn, promote complete asserted revisions through the authenticated API,
alternating endpoint pairs and fault modes. Wait for the retired pair to close
before reusing it in another generation. A fixture holds a named request at the
old healthy fallback until publication completes, then releases it. Assert it is
still pending after publication and finishes correctly. Verify the recovery
generation/configuration in SQLite after graceful exit, including history and
revision retention bounds. The workload admits at most current + retiring endpoint pairs
(eight configured upstream sockets). Record sampled child-owned upstream socket
FDs through Linux /proc, thread/FD/RSS observations and API inflight/cache counts.
These are sampled bounds for this workload; they cannot prove every instantaneous
resource invariant, and native threads do not count Tokio tasks. Explicit fixture
connection retirement and graceful process exit check eventual driver disposal.

Use bounded per-client latency histograms, not an unbounded sample vector. Report
blocked, cache-probe and fresh-name lanes separately. Cache probes include FIFO
evictions under fresh-name pressure and generation-induced misses; record actual
cache-hit and upstream-lookup counters. No strict network latency gate, allocations or
CPU/query claim. A real-process alternative with separate mock executables would
isolate benchmark scheduling further but adds packaging without improving this
initial correctness/recovery check.

Verification: existing workspace gates; local fixture regression tests for new
failure modes; debug harness smoke then release measurements; CI keeps a short
report. Persist phase results, promotion/retirement timings and sampled resources.
Operator guidance must distinguish expected SERVFAIL on complete outage from
timeouts/wrong answers, and explain revision-safe recovery without TLS bypass.
