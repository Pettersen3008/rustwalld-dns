# Release exit gates and appliance comparison

Automation note (2026-10-06): GitHub Actions and `.github/` were removed at
the maintainer's request. References to CI below describe historical verification;
run the documented commands locally and retain artifacts under `target/`.

The v0.1 feature and redesign scope is complete. Stop adding features to this
release. Exit gates are a reproducible common-behavior comparison, native
deployment/upgrade/restore validation and a 24–72-hour representative-network
soak. Fix failures found by those gates; later roadmap features stay separate.
The source and experimental artifacts may be shared as the explicitly scoped
[public alpha](public-alpha.md) while native deployment and soak gates remain
pending for a stable appliance release.
The network soak is elapsed observation, not a coding deadline or proof of
universal reliability.

## Comparison slice

Goal: compare the actual three appliances with correct DNS answers before speed.
Done: pinned images, generated equivalent rules, network-isolated local mocks,
UDP/TCP protocol preflight, bounded warm/cold/coalesced workloads, retained
hardware/config/image identities and results, deliberate wrong-answer rejection.

Own the generic Hickory wire driver/mock in an app example and the Docker
orchestration in scripts. Production DNS libraries and dependencies stay intact.
Run products sequentially in fresh containers with identical CPU/memory limits.
Use one CPU, 512 MiB memory with swap disabled, a 256 MiB shared-memory ceiling
charged within that memory limit, and disabled core dumps. Explicitly configure
Pi-hole's TCP connection admission to 64, matching our configured limit.
A network-none fixture namespace is shared only with the tested appliance and
driver. No published ports, public DNS, host services or privileged networking.
Pin different physical CPUs for appliance, producer and upstream fixture.

Generate one exact-domain dataset, render native product formats, and add one
suffix rule plus an exact allow exception. Test exact children remain allowed,
suffix children blocked and allow precedence. Pi-hole uses gravity for the
dataset; obtain its schema from the pinned image rather than a moving remote
schema. Keep telemetry/history enabled, disable rate limits and optimistic
caching, and explicitly record unequal cache units (entries versus bytes).

The Rust driver uses Hickory to validate IDs, original questions, codes, answer
addresses/CNAME chains and negative SOA. Preflight checks TTL decrement/expiry,
negative caching and truncated UDP recovery, accepting a valid TC response
followed by a client TCP retry as well as upstream TCP fallback. Benchmark warm
blocked/cache/AAAA/CNAME/negative replies, unique misses and concurrent duplicate
misses. Single-flight efficiency is observed, not assumed identical.

Use a fixed-memory histogram (21,001 buckets: exact microseconds to 1 ms, then
100 us upper bounds to 2 s), record the observed maximum, and bound sockets/tasks
and the entire query including one TCP reconnect/retry to two seconds. Pi-hole's
pinned FTL closes each incoming TCP connection after 100 queries; include and
report reconnects rather than requiring an unlimited connection lifetime.
Coordinate READY/GO so warm-up precedes cgroup CPU sampling. Report product
cgroup CPU during the measurement interval, including telemetry/background work;
this is whole-appliance cost per completed query, not isolated engine CPU.
Stop CPU sampling when the result arrives, before Docker tears down the producer.
Retain raw CPU/throttling and memory counters; label cgroup memory separately
from process RSS. Closed-loop throughput includes producer overhead and cannot
claim open-loop capacity or coordinated-omission-free tail guarantees.
The process RSS sample is the main DNS process; Pi-hole's temporary TCP child
processes are included in cgroup memory, which also includes charged file cache.
After timing, collect Rust's history/drop counters, stop writers and count durable
history. History retention, flushing and delivery differ: enabled history does
not mean identical history work. Report these differences with CPU results.

Alternative: dnsperf with live public upstreams. It adds an external tool and
network/provider noise, without proving policy, cache and answer equivalence.
Use the local functional comparison first. Later add a pinned open-loop traffic
generator, dataset scale sweeps and adversarial management/reload comparisons.
Features without equivalents belong in a capability matrix, not fake speed rows.

## Verification

Run native checks, driver/validator and orchestration rejection tests, real
containers for all three products, counterbalanced longer repeats with builds
idle, and retain failed runs. Docker resources are uniquely named and cleaned
in finally blocks. No parser/security/dependency change to production means no
new production fuzz target is needed for the fixture changes. The production
change sets TCP_NODELAY once on accepted DNS TCP streams. Verify it with matched
old/new daemon measurements, persistent-connection regressions and fresh packaged
deployment/recovery smoke tests. No per-query syscall, parser or cache change.
The second production change counts history through SQLite's compact covering
index, then finds the oldest excess rows instead of walking the configured
retention limit for every batch. It remains in the SQLite worker, with unchanged
schema, transaction and newest-row semantics. Test sparse IDs, limit changes,
oversized batches, failed insertion rollback and packaged backup/restore.

## Reproduction

Requires Linux cgroup v2, readable process/cgroup counters, Docker and three
distinct physical cores. Dependencies/images may be downloaded during preparation;
the DNS workload itself has no route to the Internet. Builds and other heavy jobs
must be idle during measurement. From the repository root:

```sh
python3 scripts/compare-appliances.py --iterations 10000 --queries-per-second 1000 --scenarios blocked cache --output target/comparison/paced.json
# Full functional workload matrix (unpaced; failures remain failures):
python3 scripts/compare-appliances.py --iterations 10000 --output target/comparison/matrix.json
# Longer mixed-workload stress test:
python3 scripts/compare-appliances.py --output target/comparison/stress.json
```

Defaults: 100,000 exact rules, 100,000 queries per warm row, four clients and three
counterbalanced rounds. Unique misses use 200 queries with a 5 ms mock delay;
coalescing uses one 64-client burst with a 25 ms mock delay. Both transports run
eight scenarios. The short cold/burst samples are functional diagnostics, not
tail-latency estimates. Warm-up (1,024 queries) is excluded. Blocked exact queries
cycle through 1,024 names; other warm cases use one name. This is a specified
working set, not a claim about a million-domain distribution.
Optional pacing schedules warm queries against a common monotonic start; it
remains closed-loop and can fall behind. It excludes waiting from wire latency
but includes it in elapsed time/achieved rate. Cold and coalescing rows remain
unpaced. A paced run additionally requires zero Rust event drops/write failures,
all received events persisted and correct bounded retention. Native durable
history counts are observations, not assumed equivalent telemetry semantics.

Use `--server-cpu N --driver-cpu N --upstream-cpu N` when the default physical
CPUs 2/4/6 are unavailable. `--rules`, `--iterations`, `--rounds`, `--products`,
`--scenarios` and `--transports` admit bounded subsets. `--skip-build` trusts
already built artifacts; `--binary PATH --skip-build` selects a trusted baseline
daemon. Build examples separately from the shipping binary to avoid dev-feature
unification. `--inject-wrong-answer` must fail before accepting performance rows.
Failed reports/logs are retained too. A failed product/round skips its remaining
rows, continues other fresh products/rounds, and makes the overall command fail.
Never average missing/rejected rows into a successful score. The manual `Appliance comparison` workflow
requires a dedicated self-hosted runner; it does not turn desktop timings into
a strict performance CI gate.

## Local evidence, 2026-10-06

AMD Ryzen 7 9800X3D, Linux x86_64, appliance/producer/mock on physical CPUs 2/4/6.
Pi-hole image 2026.09.0 (FTL 6.7.1), AdGuard Home 0.107.79; exact image digests are
in `scripts/comparison-images.json`. Dataset: 100,000 exact domains, one suffix
and one allow exception. History enabled, no optimistic cache or rate limiting.
Cache ceilings are 4,096 entries (ours/Pi-hole) and 4 MiB (AdGuard Home); these
are unequal units. The cache/blocked working sets fit all three configurations.

`target/comparison/paced-retention-after.json` passed 36 rows and nine independent
39-check preflights: 10,000 queries per row, four clients, requested 1,000/sec,
three counterbalanced rounds. Table values are **medians of per-run values**,
not pooled percentiles. CPU is cgroup runtime cost during the query window,
including background work; setup, warm-up, subsequent flushing and shutdown are
excluded. This is not the total cost of making every event durable.

| Product | Cache UDP p99 (us) | Cache TCP p99 (us) | Cache UDP CPU/query (us) | Cache TCP CPU/query (us) |
| --- | ---: | ---: | ---: | ---: |
| rustwalld-dns | 102 | 95 | 15.70 | 17.49 |
| Pi-hole | 254 | 673 | 77.90 | 82.55 |
| AdGuard Home | 66 | 130 | 20.83 | 24.58 |

All Rust rounds received/persisted/retained 44,136 events, with zero drops/write
failures. AdGuard Home retained 44,136; Pi-hole retained 44,079/43,681/44,137
(its client TCP truncation retry also adds a query). Flushing/delivery differ.
Final sampled cgroup memory medians were 58.6/25.6/111.7 MiB respectively; main
process RSS was 55.6/24.2/93.1 MiB. File cache and temporary forked processes make
these different metrics. They are whole-appliance footprints, not bytes/rule.

The shared workstation is noisy: our per-run UDP cache p99 was 26/102/169 us,
TCP 33/121/95 us. AdGuard Home was faster on UDP in these medians. One Rust UDP
repeat exceeds the initial 150 us cache target; dedicated/native testing remains
necessary. These measurements do not establish a universal ranking or capacity.

Before the retention change, the matched paced report `paced-final.json` used
the identical driver/controller/dataset/config/CPU limits. Our median CPU/query
was 23.38/38.82 us (UDP/TCP) and median p99 191/295 us. After: 15.70/17.49 us and
102/95 us. Other products' latency also varied, so the entire tail improvement
cannot be attributed to SQL alone. The SQL prototype independently measured
about 30–37x less retention-statement CPU at 20k/40k/100,010 rows. It used Python
SQLite 3.53.4, 200 warmed in-memory samples per case, a real-shaped history table
with its created index, CPU 2, rollback outside timing; it excludes insertion,
Rust serialization and fsync. Raw data: `retention-sql-before-after.json`.

The prior release's accepted TCP streams lacked TCP_NODELAY. Identical-driver
1,000-query cache runs (`tcp-matched-before.json`/`tcp-matched-after.json`) changed
p50 from 41,100 to 6 us and p99 from 42,100 to 216 us. Both passed protocol/reply/
upstream gates. The small after-run tail remains visible; longer warmed repeats
were lower. This justified the socket option rather than a new packet parser.

`rustwalld-retention-after-stress.json` passed all 48 rows across three rounds:
3,601,584 measured replies plus warm/preflight traffic, no incorrect replies,
timeouts, clipped latency or unexpected upstream work. Every 64-client duplicate
burst used one upstream lookup; unique misses used exactly 200. Queue pressure
still dropped 90.4–90.6% of 1,212,856 received history events per round, with no
write failures and 100,000 retained rows. That is explicitly best-effort history,
not complete query logging at the burst rate. Normal DNS continued correctly.

The pre-retention three-product mixed stress report `comparison-256m.json`
failed overall: all Rust/AdGuard rows passed, while each Pi-hole round hit the
two-second deadline during cached TCP work. The smaller `matrix-final.json` and
`fastpath-final.json` also retained intermittent Pi-hole TCP failures. All nine
preflights passed. Shared memory was only 17–25% used in the larger-ceiling stress
run, and no Docker OOM flag was recorded; the timeout cause is **not established**.
Do not present failed stress runs as accepted throughput/latency scores or infer
that other hardware/native deployments have the same behavior. Earlier fixture
configuration/connection failures are retained separately in the same directory.

Shipping daemon SHA-256: `47ff93e78391cd327bc280b7c153018b75e836c2a29db77f5717658428fef75a`.
Paced before daemon: `19e0e50ae523d6d2b20ad389813e822f0d853275f226c23c6e348c32123551d5`.
Final reports retain driver/controller/container-recipe SHA-256, image identities,
toolchains, dataset/config hashes, raw counters and failures. Keep raw data with
any published comparison. Native activation and a 24–72-hour network soak remain
release exit gates; this local benchmark does not replace them.

Official configuration references:

- [Pi-hole configuration](https://docs.pi-hole.net/ftldns/configfile/)
- [Pi-hole domain database](https://docs.pi-hole.net/database/gravity/)
- [AdGuard Home configuration](https://github.com/AdguardTeam/AdGuardHome/wiki/Configuration)
- [AdGuard Home filter syntax](https://github.com/AdguardTeam/AdGuardHome/wiki/Hosts-Blocklists)
- [RFC 7766: client TCP retry and framing](https://www.rfc-editor.org/rfc/rfc7766.html)
- [RFC 1035: zero TTL is valid](https://www.rfc-editor.org/rfc/rfc1035.html)
- [Pinned FTL connection limit](https://github.com/pi-hole/FTL/blob/v6.7.1/src/dnsmasq/config.h)
