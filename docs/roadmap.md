# Delivery checklist

Complete and verify slices in order; no placeholder crates or endpoint responses.

- [x] 0: architecture, dependency/RFC review, benchmark method
- [x] 1: bounded UDP/TCP ingress, validated forwarding, protocol tests
- [x] 2: bounded response cache, TTL/negative semantics, baseline benchmarks
- [x] 3: exact/suffix filtering, list compiler, immutable reload
- [x] 4: compiled global/client/subnet policies and generations
- [x] 5: bounded cancellation-safe coalescing and upstream failure/health
- [x] 6: asynchronous SQLite history, local API, metrics/config revisions
- [x] 7: assertion gate, explanations, shadow, rollback
- [x] 8: React management console, revision-safe editing, browser verification

Later individually: regex sets, DoQ, worker-local caches, packed domain structures,
live client discovery, HA, plugins and DNS Guard. DNS Guard belongs in a
separate process/control-plane integration; DoH cannot be perfectly enforced.

MVP delivered with local DNS rewrites, the safety workflow and a management
console. Protocol restrictions and initial performance limitations are documented
in README.md; memory estimates are not RSS claims.

## Deployment and operational hardening

Before expanding DNS transports or optimizing data structures:

- [x] Reproducible release bundle containing the Rust binary and compiled console.
- [x] Non-root systemd service with explicit state/config paths and sandboxing.
- [x] Installation, upgrade, backup/restore and recovery checks in a clean Debian container.
- [x] Sustained DNS load while API clients stall, revisions compile and history
      persistence fails; retain latency, admission and dropped-event evidence.

Delivered with content-addressed packaging, private no-clobber WAL snapshots,
upgrade preservation and a real-process failure benchmark. See operations.md and
resilience-baseline.md for evidence and limits. Native systemd sandbox activation
is a deployment-host check; the container verifies unit syntax and non-root
runtime behavior. No service was installed on the development host.

## DNS-over-TLS upstreams

- [x] Explicit TLS profiles, certificate/hostname validation, bounded inline private
      trust and generation-separated caching; legacy UDP/TCP profiles remain readable.
- [x] Bounded warm connections, deadlines, cancellation and reconnect with local
      TLS mocks; no plaintext downgrade or runtime bootstrap-name resolution.
- [x] Real DNS filtering/cache/coalescing/reload tests, console controls and local
      cold/warm Criterion evidence. See encrypted-upstreams.md and tls-baseline.md.

## DNS-over-HTTPS upstreams

- [x] Define explicit HTTPS endpoint/identity/bootstrap profiles and cache isolation.
- [x] Bound HTTP/2 connections, concurrent streams, headers/body, redirects and
      cancellation; validate DNS media type/status and preserve sequential fallback.
- [x] Verify warm reuse, authentication/failure isolation and cold/warm latency with
      local HTTPS fixtures before promotion. No public resolver traffic in tests.

Delivered with console controls, HTTP Age/negative-cache semantics, driver/socket
retirement, local security fixtures and encrypted backup/upgrade/recovery smoke
tests. See doh-design.md and doh-baseline.md for contracts, evidence and limits.

## Encrypted-upstream failure rehearsals

- [x] Sustain mixed blocked/cached/uncached traffic while local TLS/HTTPS upstreams
      stall, reset connections and return invalid HTTP/DNS responses.
- [x] Combine those failures with concurrent policy promotions and retired pools;
      retain latency/timeout, coalescing and bounded connection/task evidence.
- [x] Document operator recovery and repeatable soak methodology before adding
      DoQ, multiplexing, HA or transport optimizations.

Delivered a real-process local rehearsal and short CI gate with counter
reconciliation, old-generation completion, retired connections, durable recovery,
bounded histograms and sampled socket/inflight/cache evidence. See
encrypted-resilience.md and encrypted-resilience-baseline.md. These short runs
do not replace a production-host soak. Complete malformed-response pressure
exceeded the local cache p99 target and needs diagnosis before optimization.

## Upstream failure diagnostics

- [x] Preserve bounded, typed upstream failure categories and expose aggregate
      reasons through the API/console without query-name logging or persistence
      dependencies in DNS workers.
- [x] Use the new fixtures to reproduce complete-outage handshake pressure and
      profile its effect on local-path latency before choosing a mitigation.
- [x] Verify diagnostic counters/recovery across reloads, old-generation requests,
      cancellation and failure isolation with real DNS/API/browser tests.

Delivered fixed endpoint counters, active generation/inflight API fields and
readable desktop/mobile reasons. The rehearsal reconciles each steady-phase
outcome and requires clean recovery counters after publication. See
upstream-diagnostics.md and upstream-diagnostics-baseline.md. User-only perf
sampling on the real daemon shows cryptographic leaf routines consuming most
sampled DNS-worker user CPU during malformed outages; kernel/caller attribution
and causal tail-latency isolation remain limited. No host permissions changed.

## Bounded upstream admission

- [x] Fixed per-endpoint cooldown, a single traffic-driven recovery probe and
      capped delay; domain errors, cancellation and ambiguous deadlines do not
      penalize endpoint admission. Preserve certificate/reply validation.
- [x] Verify cancellation, stale completions, fresh generations, real TLS/HTTP2
      fallback and all-endpoint unavailability without upstream retry storms.
- [x] Compare saved/current production binaries in quiet local rehearsals and
      retain counter, recovery, promotion, socket/cache and latency evidence.

Malformed-outage cache-probe p99 fell to 21–25 µs in the five-second run and
21 µs in the reverse-order repeat, with 6–8 attempts per endpoint rather than
thousands. See upstream-backoff.md and upstream-backoff-baseline.md for scope,
workload and limits. No zero-allocation or statistical gate claim is made.

## Console redesign

User confirmed release completion before redesign, with Ward.pdf as a reference.
Later feature expansion remains separate. See console-design.md.

- [x] Semantic Tailwind/shadcn-style tokens with light/dark themes and offline assets.
- [x] Compact task-specific layouts across the existing working console.
- [x] Desktop/mobile/keyboard/browser checks, visual review and tested release.

Keep optional firewall integration, public management access, HA and parser/cache
optimizations separate. Native deployment validation and longer operational
rehearsals remain operator/CI work, not a claim of mature production hardening.

## Complete policy-check diagnostics

- [x] Offline `policy test` command with text/JSON, explicit exit codes and all-case
      reports; no database, listeners or upstream requests.
- [x] Shared compiler and bounded provenance reports through the existing test API;
      required assertion gates remain strict for every publication path.
- [x] Paginated console diagnostics, regression tests and a policy-check fuzz target.

See offline-policy-checks.md for the contract, usage and verification evidence.

## Temporary exact-domain allows

- [x] Compile bounded per-policy exceptions with absolute expiry, conservative
      monotonic deadlines and one-way expiry; cache and coalesced work cannot
      carry an allowance past its deadline.
- [x] Preserve permanent assertion gates, local-rewrite precedence and other
      clients' TTLs; expose live state, explanation and recorded provenance.
- [x] Console draft/shadow/promotion/revocation, transactional schema-1 history
      migration, restart/rollback and failed-management expiry verification.

See temporary-exceptions.md for scope, performance evidence and clock/TTL limits.
Reviewed list scheduling and client/network annotations are delivered below.

## Reviewed downloaded lists

- [x] Bounded manual HTTPS fetch into drafts, explicit bootstrap IPs and strict
      public/private trust; reject redirects, oversized/malformed content and
      stale revisions without affecting DNS.
- [x] Persist source identity and content fingerprints with list text through
      existing assertion, shadow, promotion, rollback and recovery gates.
- [x] Console registration/edit/removal/refresh, list statistics, real local
      HTTPS failure tests, fuzzing, performance and packaged recovery evidence.

See downloaded-lists.md. Reviewed timers are delivered below; automatic live
promotion and additional list formats remain deferred. Conditional retrieval was
added in the follow-up slice below.

## Client and network annotations

- [x] Bounded optional group/owner/VLAN-label/tags/note metadata on IP bindings,
      persisted with complete immutable revisions and independent of admission.
- [x] Explanations and assertion reports use the winning binding's annotations;
      source-IP selection and query telemetry stay unchanged.
- [x] Searchable, paginated inventory/editor, durable shadow/promotion/rollback,
      validation/failure tests, benchmark comparisons and packaged recovery.

See client-metadata.md. Labels do not detect VLANs, discover devices or create
group-based policy inheritance. Discovery/import integrations remain separate.

## Scheduled downloaded-list checks

- [x] Optional bounded intervals, one worker, shared download admission and one
      queued check; manual-only defaults and monotonic deadlines.
- [x] Assertion-gated durable shadow staging, generation preconditions, pause for
      review, last-good DNS during publisher/SQLite failures and cancellation.
- [x] Console schedule editing/status/check-now, regression and browser checks,
      parser fuzzing, performance comparison and packaged pending-shadow recovery.

See scheduled-refreshes.md. Attempt status is runtime-only; restart reconstructs
deadlines from retrieval stamps. Live promotion remains an operator action.


## Conditional downloaded-list retrieval

- [x] Bounded runtime ETag/date hints tied to source trust, stored content and
      generations; 304 preserves stored provenance/revisions, full GET on restart.
- [x] Changed bytes retain assertion/durable shadow gates; discarded shadows,
      manual edits, malformed replies and concurrent generations cannot reuse
      hints for different content. Failed checks permit unconditional recovery.
- [x] Console HTTP/body-byte diagnostics, local header/network/browser/fuzz tests,
      transfer and unchanged DNS pipeline measurements, packaged restart recovery.

See conditional-retrieval.md. Source freshness is checked on the configured
schedule; publisher HTTP freshness hints do not choose deadlines. No persistent
validator schema or DNS worker change.


## Repeated control-plane recovery rehearsal

- [x] Share fixed-memory histograms between network harnesses; replace unbounded
      management latency vectors without changing DNS behavior.
- [x] Repeat conditional checks, shadow/promotion, failed persistence and full
      recovery under independent blocked/cache-probe lanes; reconcile counters.
- [x] Observe bounded resources and durable retention/restart; retain longer local
      evidence, a short CI gate and an optional manual soak workflow.

See control-plane-soak.md. Native deployment activation and long production-host
soaks remain separate; sampled RSS is not an instantaneous bound or leak proof.

## Filter storage performance

- [x] Measure fresh-process filter RSS/peak at 100k, 1M, 5M and 10M rules and a
      deterministic broader lookup working set before changing storage.
- [x] Share immutable domain/list-name storage, retain provenance and allow
      precedence, and compile the payload estimate for constant-time status reads.
- [x] Compare memory/lookup and real-daemon reload/failure results; pass full
      checks, compiler fuzzing and packaged recovery before retaining the change.

See filter-memory.md. Process RSS includes allocator-retained compiler memory;
logical payload estimates and warmed DNS paths are not zero-allocation claims.

## Query string ownership performance

- [x] Measure allocator/timing baselines with closed, live empty and full event
      queues, cached decisions/responses, temporary allows and local rewrites.
- [x] Reuse normalized names for telemetry and avoid unused decision keys;
      preserve raw label escapes, question casing, truncation and event counters.
- [x] Verify full checks, matched loopback reload/failure behavior and final
      release packaging before retaining the allocation improvement.

See query-allocations.md. Hickory parsing and cache representations remain intact;
live event buffers may retain formatting spare capacity within the bounded queue.

## Forwarding request ownership performance

- [x] Capture warmed allocator/timing baselines, including maximum-length mixed
      names and DO/CD cache hits, before changing forwarding ownership.
- [x] Derive semantic keys from accepted client requests and construct canonical
      forwards only for admitted misses; preserve per-client replies and flights.
- [x] Verify flag/type/profile/generation partitions, gated mixed-client
      coalescing, full checks, matched failure traffic and packaged recovery.

See cache-forwarding.md. Cache/key/response allocations remain; measurements are
fixture-specific and shared-host network percentiles are diagnostic.

## Borrowed decision-cache lookup performance

- [x] Measure warm wire allocations and shared-cache hit/working-set/FIFO behavior
      before changing the owned decision lookup or map implementation.
- [x] Borrow domain/policy/generation keys on hits, retain explicit randomized
      hashing and FIFO bounds, and test hash/equality, collisions and concurrency.
- [x] Investigate initial timing regressions with the library's inlining feature
      and reversed pinned repeats; pass final checks, fuzzing and release recovery.

See borrowed-decisions.md. Blocked iterations improve in the local repeats;
cached iterations are slightly slower, within 2%. Allocation savings are measured
for the specified warm fixtures and do not establish zero-allocation DNS.

## Local CPU/query measurement

- [x] Share warmed Criterion fixtures with a separate Linux CPU probe, keeping
      proc reads, setup/reporting and allocation instrumentation outside queries.
- [x] Bound work, validate wire replies/counters and reject unexpected upstream
      work; test stat parsing, CLI limits and driver accounting/precision labels.
- [x] Record full/focused quiet pinned runs and investigate timing outliers,
      compare Criterion/allocator results and verify the unchanged release payload.

See cpu-query.md. Tick precision is distinct from machine stability; an unusually
high DO/CD repeat is retained, and CPU results remain diagnostic on this desktop.

## Appliance comparison and release exit gates

- [x] Pinned Pi-hole/AdGuard Home adapters, equivalent exact/suffix/allow rules,
      isolated mock upstream, UDP/TCP protocol preflight and bounded wire driver.
- [x] Counterbalanced paced/burst measurements, CPU/RSS/cgroup/history evidence,
      wrong-answer rejection and retained product failures without fake scores.
- [x] Measure/fix persistent TCP delayed-ACK stalls and SQLite retention scans;
      verify sparse IDs/atomic batches, full checks and packaged recovery.
- [ ] Validate native systemd activation/sandboxing, install/upgrade/restore on
      the actual deployment host.
- [ ] Complete a clean 24–72-hour representative-network soak; investigate
      correctness failures, resource growth or unexplained latency outliers.

See comparison.md. Feature/redesign scope is complete: stop adding v0.1 features.
Unpaced peer failures and burst history drops remain visible. A local benchmark
does not replace native/production observation or establish maximum capacity.

## Reusable libraries and open-source preparation

The proposed behavior-preserving refactor is in open-source-refactor.md. Start
with a recoverable source/performance baseline, then rename packages, organize
modules, define checked embedding APIs and separate durable control services
from HTTP/CLI adapters. Preserve existing tests, workloads and external formats;
accept changes only with appropriate correctness and performance evidence.

This is repository/library preparation, not additional v0.1 DNS features. Native
deployment and the representative-network soak above remain pending release
gates. Rustwalld integration is demonstrated through independent consumer
fixtures in this repository; no changes to the Rustwalld project are planned.
