# Upstream failure diagnostics

A failed endpoint exchange used to disappear behind the final `Unavailable`
error. Preserve a fixed set of reasons in the resolver and show their counters in
`GET /api/v1/upstreams` and the console. DNS behavior, sequential fallback,
certificate verification and retry limits remain unchanged.

## Ownership and accounting

`resolver::FailureKind` has twelve categories: deadline, connection, TLS
authentication, TLS protocol, HTTP protocol, HTTP status, HTTP envelope, DNS
response, SERVFAIL, REFUSED, cancellation and local error. Each endpoint owns a
fixed atomic array plus attempts, successes, inflight and successful-latency EWMA.
No query names, error strings, unbounded labels or per-query logs are retained.
Serialization and display happen in the control plane.

An attempt starts when an endpoint is selected, including waiting for admission
into its connection pool. Its RAII guard records exactly one success or failure;
dropping an unfinished endpoint future records cancellation. A coalesced lookup
can outlive its original client; client departure alone does not count as an
endpoint cancellation. At quiescence:

    attempts = successes + sum(failures)
    inflight = 0

Individual relaxed atomic reads are live observations, not a transactional
snapshot. A success can follow a failure; historical failures do not mean that an
endpoint is currently down. Success latency excludes failed attempts. A stale
warm-connection retry remains part of the same endpoint attempt.

Deadline includes pool admission, connection, handshake and response time. TLS
certificate errors use rustls typed errors, never message matching. Missing h2
ALPN is TLS protocol; h2 resets/protocol faults are HTTP protocol. Non-2xx status
is HTTP status. Invalid media type, encoding, Age, length or oversized body is
HTTP envelope; malformed/mismatched/truncated DNS is DNS response. UDP still
ignores unsolicited malformed/mismatched packets until its deadline, so those
attempts end as deadline rather than trusting an invalid packet's reason.

Counters belong to immutable-generation resolver profiles. The API includes the
active generation. Promotion/rollback creates fresh counters; requests pinned to
old generations finish and update the old profile. Blocked, rewritten, cached
and single-flight follower queries do not start endpoint attempts.

A dynamic map or structured per-failure log on the DNS path would retain richer
errors but adds allocation, cardinality and persistence pressure. Fixed counters
provide bounded diagnostics without those dependencies. No schema migration or
configuration change is needed; API fields are additive.

## Verification

Exercise local UDP, TLS and HTTP/2 faults, sequential fallback, cancellation,
recovery, cached/blocked traffic and generation replacement. Check the accounting
identity only after work finishes. Real HTTP and desktop/mobile browser tests
verify the public API and display. Run the workspace gates, dependency audit/deny,
targeted DoH fuzzing and the real-process encrypted failure rehearsal.

The quiet paired release run reproduced malformed-outage cache-probe p99 above
150 µs. A repository-local user-only perf recording then attributed most sampled
DNS-worker user CPU to cryptographic leaf routines in the local fixtures. Samply's
permission preflight failed, but the narrower user-only recording needed no host
setting changes. See upstream-diagnostics-baseline.md for sample counts, limits
and reproduction. Rehearsal latency is diagnostic rather than a noisy CI gate;
no performance mitigation was selected without further correctness/measurement
work.
