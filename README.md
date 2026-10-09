# rustwalld-dns

A local-first DNS policy and security engine written in Rust. Policies are compiled
into immutable generations; DNS workers use those snapshots while the management
plane validates, tests, persists and promotes changes.

This repository contains a usable **MVP with a local management console**. UDP/TCP
forwarding, filtering, caching, client/subnet policies, the API and React console
are implemented, including authenticated DNS-over-TLS and HTTP/2 DNS-over-HTTPS
upstreams with bounded persistent connections. DoQ, HA, plugins and firewall
integration remain later phases.
This is an initial implementation with measured baselines, not a claim of mature
production hardening.

An [encrypted-upstream failure rehearsal](docs/encrypted-resilience.md) exercises
the real appliance with local TLS/HTTPS outages and concurrent durable promotions.
It separates blocked queries, cache probes and fresh misses, checks recovery and
connection retirement, and retains latency/resource evidence.

## Use as a Rust library

| Crate | Responsibility |
| --- | --- |
| [rustwalld-dns-filter](crates/filtering/README.md) | Pure immutable matching and provenance |
| [rustwalld-dns-resolver](crates/resolver/README.md) | Bounded forwarding, caching and coalescing |
| [rustwalld-dns-policy](crates/policy/README.md) | Assertion-gated snapshots and client policy selection |
| [rustwalld-dns-core](crates/dns-core/README.md) | Embeddable engine, checked publication and UDP/TCP ingress |
| [rustwalld-dns-runtime](crates/runtime/README.md) | Optional durable revisions, history, downloads and lifecycle |

Core has no dependency on the app, Axum, SQLite or JSON. The optional runtime
owns durable services; the host owns signals, executors and management adapters.
[Embedding guidance](docs/embedding.md) explains integration and cancellation.
Public examples and [independent consumers](tests/consumers) verify these APIs.
These crates are prepared locally; registry publication is a separate step.

```sh
cargo run --locked -p rustwalld-dns-core --example embedded
cargo doc --workspace --no-deps --locked --open
python3 scripts/verify-consumers.py
```

To use the checkout before publication, add a path dependency such as
`rustwalld-dns-core = { path = "../rustwalld-dns/crates/dns-core" }` to your host
project. Rustwalld integration is possible through that API; its actual dependency
graph and application lifecycle require a separate integration change. This
refactor makes no changes in `~/Work/rustwalld`.

Large-list compilation has [an optional bounded Rayon backend](docs/parallel-compilation.md).
Default builds remain sequential. For the standalone appliance, build with
`--features parallel-compilation` to share an owned two-worker pool across startup
and durable reloads. Measurements include compilation, peak RSS and DNS latency;
choose the worker budget based on the deployment workload.

See [CONTRIBUTING](CONTRIBUTING.md), [SECURITY](SECURITY.md),
[CHANGELOG](CHANGELOG.md) and [release preparation](docs/releasing.md).

## Run

Requires Rust 1.95+ and a C/C++ toolchain for bundled SQLite/fuzz builds.
The checked-in toolchain pins 1.99.0 for performance/release reproducibility.

```sh
cargo run -p rustwalld-dns -- --print-default-config > config.toml
cargo run -p rustwalld-dns -- --config config.toml --check-config
export RUSTWALLD_API_TOKEN="$(openssl rand -hex 32)"
cargo run -p rustwalld-dns --release -- --config config.toml
```

Defaults: DNS `127.0.0.1:5353` (UDP and TCP), API `127.0.0.1:8080`, SQLite
`rustwalld.sqlite`. No root privileges are needed. Set `RUST_LOG` for structured
tracing. SIGINT/SIGTERM stop ingress, drain bounded DNS work and attempt to flush the history
queue within the shutdown budget. Query names are not logged to stdout by the DNS engine.

The token protects all management endpoints except `/healthz`, `/metrics` and
`/api/v1/status`; these expose aggregate health information on loopback. The API
must remain on loopback. It bounds connections, idle time, request concurrency
and body size. DNS listeners outside loopback require explicitly configured
`allowed_clients` CIDRs. Client bindings select policies; they do not grant access.
Clients are matched by canonical address, so IPv4-mapped IPv6 networks such as
`::ffff:10.0.0.0/104` are compiled as their IPv4 network (`10.0.0.0/8`; stored
`allowed_clients` are rewritten to that form). Mapped prefixes shorter than /96
are rejected.

Policy content from the configuration file initializes a **new database**.
Subsequent starts restore the last durable active/shadow revision from SQLite.
Listener/cache/retention settings still come from the file. To change existing
policy content, use the API. `--check-config` always validates the supplied file
and its assertions without opening the database or contacting an upstream.

For a complete diagnostic report rather than stopping at the first failed assertion:

```sh
cargo run -p rustwalld-dns --locked -- policy test --config config.toml
cargo run -p rustwalld-dns --locked -- policy test --config config.toml --format json
```

Exit codes: `0` passed, `1` assertion failures, `2` configuration/input errors.
Reports include every case, client admission, policy, matcher, rewrite and bounded
rule provenance. No database, listeners or upstream requests are involved. See
[offline policy checks](docs/offline-policy-checks.md) for report semantics and CI use.

## Deployment and recovery

Build a native Linux release bundle with `python3 scripts/release.py`. It includes
the binary, compiled console, conservative systemd unit, configuration template,
installer and a manifest of file hashes/toolchains. Repacking the same built
inputs is deterministic. Installations preserve configuration, credentials and
state, and require an explicit service start. The daemon runs as a dedicated
non-root account. No host DNS or firewall settings are changed.

Standalone `backup`, `verify-backup` and `restore` commands snapshot SQLite WAL
state, validate integrity/schema and active/shadow assertions, and refuse to
replace an existing target. Future schema versions are rejected at startup.
See [installation, upgrades and recovery](docs/operations.md) for commands,
permissions, sandboxing and the limits of this initial Linux deployment support.

## Management console

Build the console with Node 22.12+ (Node 24 was used for local verification):

```sh
npm --prefix web ci
npm --prefix web run build
```

Set `web_root = "web/dist"` at the top level of `config.toml`, before any policy
sections. The path is relative to the configuration file. Start the appliance
as above, then open <http://127.0.0.1:8080> and enter its management token.
An invalid or missing `web_root/index.html` fails configuration validation.
Omit `web_root` to run a backend-only appliance; Node is not needed at runtime.

The console shows live counters, recent query history and current-policy
explanations with rule provenance, clients/networks, filter statistics, upstream
health and durable revision history. The policy workbench supports rules,
allow exceptions, local rewrites, subnet/device bindings, upstream profiles and
required assertions. Use **validate → shadow → review → promote**, or inspect a
stored revision before rolling back. Advanced JSON import/export covers the
complete policy configuration.
Bindings can carry group, owner, VLAN label, tags and a note. Search those fields
in Clients & networks, or edit them in the workbench's collapsed annotations.
The clients view and binding editor paginate their rows. Annotations describe
the selected source-IP binding and never grant DNS access or enforce a VLAN.
See [client metadata](docs/client-metadata.md) for limits and configuration.
Failed validation shows paginated assertion results and expandable decision
traces; passing results remain collapsed. Editing the draft clears its report.

Drafts and tokens exist only in tab memory. Disconnect clears them; refreshing
requires reconnecting. Unsaved drafts survive navigation and polling. Writes use
revision preconditions, so a conflicting editor receives an error and retains
the draft. Reloading active configuration explicitly discards local edits.
Shadow impact uses a labeled sample of at most 500 retained events; it is not a
complete traffic estimate. Explanations evaluate the current policy, not a
reconstruction of historical policy execution.

For frontend development, run `npm --prefix web run dev` alongside the appliance
on API port 8080. Vite binds loopback and proxies API/metrics requests to that
local endpoint. Production uses bundled same-origin assets, without a CDN.

## Filtering, clients and local DNS

Edit `config.example.toml` or the generated file. Example policy additions:

```toml
[[policy.policies.lists]]
name = "local-deny"
action = "block"
rules = """
=exact.ads.example
telemetry.example
||tracking.example^
0.0.0.0 unwanted.example another.example
"""

[[policy.policies.lists]]
name = "exceptions"
action = "allow"
rules = "=safe.telemetry.example"

[[policy.policies.rewrites]]
domain = "nas.home.arpa"
addresses = ["192.168.10.20", "fd00::20"]
ttl = 60

[[policy.bindings]]
network = "192.168.20.0/24"
policy = "default"
name = "IoT"

[[policy.assertions]]
client = "127.0.0.1"
domain = "telemetry.example"
expected = "block"
```

`=domain` matches only that name. Plain domains, `*.domain`, supported `||domain^`
and hosts-file domains match the apex and all subdomains at label boundaries.
`@@` makes a rule an allow exception. Allow rules override deny rules; a rewrite
runs before filtering. Only this limited Adblock syntax is supported: regex,
modifiers and URL paths are rejected. Invalid rules reject a policy revision.
Unicode names are compiled to lower-case IDNA ASCII; duplicate rules retain source
locations. Same-action subsumption is analyzed and reported. All policies are
already effective configurations; runtime inheritance is not evaluated.

To load a local list file at initial configuration/check time, add a top-level
entry (paths are relative to the configuration file):

```toml
[[filter_files]]
policy = "default"
name = "hosts-list"
action = "block"
path = "lists/hosts.txt"
```

Remove `filter_files = []` from the generated file before adding these tables.
Live list replacement uses a complete policy configuration through the API; file
reading and downloads never run in DNS workers. Manual HTTPS downloads are
available through the policy workbench, with opt-in reviewed scheduling.

## Downloaded lists

In **Policies → Downloaded lists**, register a policy/list target, HTTPS URL and
explicit bootstrap IPs. Add an inline private CA for a self-hosted publisher if
needed. Download into the draft; the server checks the full candidate and returns
list statistics and a SHA-256 content fingerprint. Review in shadow and promote
using the existing workflow. Failed or stalled downloads keep the active list.

Fetches have a 15-second total deadline, an 8 MiB body limit and one concurrent
download slot. Only configured IPs are contacted; TLS authenticates the URL host.
Redirects, proxies, compression, cookies and plaintext fallback are disabled.
Lists must be valid UTF-8 in the supported exact/suffix/hosts/Adblock subset.
Sources are manual-only by default. Enable scheduled refreshes (300 seconds through
30 days) to check periodically and stage changed content as a durable shadow.
Existing shadows pause all scheduled checks; only explicit promotion changes live
DNS. Unchanged content creates no revision. Check-now and status are available in
the console. Scheduled checks use bounded ETag/Last-Modified hints when supported
by the publisher; HTTP 304 retains the stored list without allocating a revision.
Hints are tied to source trust and content, held only in runtime memory, and
relearned with a full GET after restart. Manual previews always fetch full bodies.
See [schedule bounds and recovery](docs/scheduled-refreshes.md) and
[conditional retrieval](docs/conditional-retrieval.md).

Source metadata and exact list contents persist in policy revisions and backups.
Startup and rollback use stored content without contacting the publisher. Manual
text edits clear the download stamp in the console. Removing a source keeps its
list; remove the list too when retiring its filtering. See
[download contracts and evidence](docs/downloaded-lists.md) and
[binary downgrade compatibility](docs/operations.md).

## Temporary exact-domain allows

In **Policies → Temporary exceptions**, choose an existing effective policy,
name one exact domain and select a duration. Add it to the draft, validate,
inspect shadow impact and promote. Its absolute expiry starts when added to the
draft. Removing it from the draft requires promotion to revoke the active allow.

The policy JSON field is `temporary_exceptions`: an array of
`{ "name": "repair", "domain": "service.example", "expires_at": UnixSeconds }`.
Use a numeric Unix-second expiry, at most seven days ahead when the exception is
first submitted (restored revisions are clamped, never rejected). Matching uses IDNA
normalization and is exact; subdomains need separate entries. Limits are 1,024
entries per policy and 4,096 per generation. A policy applies to every admitted
client mapped to it; choose a device-specific policy for a device-only exception.

DNS expiry works with stalled management/history storage and warm caches.
Answers get TTLs capped to remaining allowance, and delayed upstream/coalesced
work rechecks expiry. Permanent policy assertions exclude temporary allows;
current explanations include them. Rollback preserves the original expiry.
Restart/recompilation needs a correct system clock; existing application
connections cannot be withdrawn. See [semantics and verification](docs/temporary-exceptions.md)
and [schema-2 upgrade recovery](docs/operations.md).

## DNS-over-TLS upstreams

In the console, choose **Policies → Upstream profiles → DNS over TLS**, enter the
resolver's certificate name and its explicit IP:port addresses (normally port
853). Addresses in one profile must share that identity. Configure another
profile for a different provider and assign it to the appropriate policy.
A profile tries its addresses sequentially and never downgrades TLS to plaintext.

For example, replace an upstream table with your own resolver's details:

```toml
[[policy.upstreams]]
name = "private-resolver"
addresses = ["192.0.2.53:853", "192.0.2.54:853"] # example addresses; replace
timeout_ms = 1500
[policy.upstreams.transport]
kind = "tls"
server_name = "resolver.your-domain.example" # replace with certificate identity
max_connections = 2 # per address; 1..8
# ca_pem = """-----BEGIN CERTIFICATE----- ...""" # private CA, public certs only
```

Set the policy's `upstream` to the profile name. Leaving `transport` absent keeps
UDP with TCP fallback. TLS verifies chains, validity and hostnames using bundled
public roots. An optional inline CA PEM replaces public roots; certificate files
are never loaded during a DNS query. The deadline includes waiting for a pool
slot and the handshake. Responses use the same validation/cache semantics as
plaintext forwarding. Trust or transport changes publish a new generation.

Validation/shadow mode checks policy decisions and configuration; it does not
probe resolver availability or compare upstream answers. Verify connectivity
before promoting a new upstream. See [design and evidence](docs/encrypted-upstreams.md)
for TLS bounds and cancellation/reconnect behavior.

## DNS-over-HTTPS upstreams

Choose **Policies → Upstream profiles → DNS over HTTPS** in the console. Supply
the certificate DNS name, explicit bootstrap IP:port addresses (normally 443),
and an absolute POST path such as `/dns-query`. For the profile above, replace
the transport table with:

```toml
[policy.upstreams.transport]
kind = "https"
server_name = "resolver.your-domain.example"
path = "/dns-query"
max_connections = 2 # per address; 1..8
# ca_pem = """-----BEGIN CERTIFICATE----- ..."""
```

Change the addresses to the HTTPS listener's ports. Certificate verification and
private-CA behavior match TLS profiles. HTTPS requires authenticated TLS with
HTTP/2 ALPN and POST `application/dns-message` wire bodies. It does not follow
redirects, resolve bootstrap hostnames, use environment proxies, or fall back to
HTTP/1/plaintext. HTTP headers and DNS bodies are bounded. HTTP `Age` reduces DNS
TTLs, including negative-cache lifetimes; expired answers are not cached.

The initial pool allows one outstanding exchange per connection. Cancellation
retires its driver/socket before a physical connection slot can be reused.
Validation and shadow staging do not probe upstream availability. See the
[HTTPS design](docs/doh-design.md) and [local benchmark evidence](docs/doh-baseline.md).

## Management API

```sh
curl -H "Authorization: Bearer $RUSTWALLD_API_TOKEN" \
  http://127.0.0.1:8080/api/v1/config > candidate.json
# Edit candidate.json, then validate its required assertions.
curl -H "Authorization: Bearer $RUSTWALLD_API_TOKEN" \
  -H 'Content-Type: application/json' --data-binary @candidate.json \
  http://127.0.0.1:8080/api/v1/policy/test
# Observe differences on real traffic, then promote the shadow candidate.
curl -H "Authorization: Bearer $RUSTWALLD_API_TOKEN" \
  -H 'Content-Type: application/json' --data-binary @candidate.json \
  http://127.0.0.1:8080/api/v1/shadow
curl -X POST -H "Authorization: Bearer $RUSTWALLD_API_TOKEN" \
  http://127.0.0.1:8080/api/v1/shadow/promote
```

| Endpoint | Behavior |
| --- | --- |
| `GET /api/v1/status` | Version, active/shadow generation, cache and inflight counts |
| `GET /api/v1/queries?limit=100` | Most recent persisted events (maximum 1,000) |
| `GET /api/v1/clients` | Client bindings and allowed networks |
| `GET /api/v1/policies` | Compiled policy summaries |
| `GET /api/v1/temporary-exceptions` | Active generation and configured exceptions with live expiry state; no SQLite read |
| `GET /api/v1/filter-lists` | Deduplication, invalid/subsumed counts, payload estimate |
| `GET /api/v1/filter-sources` | Active source metadata and retrieval fingerprints; no SQLite read |
| `POST /api/v1/filter-sources/preview` | Fetch `{config, source: index}` into a checked draft; requires current `If-Match`, never publishes |
| `GET /api/v1/filter-refreshes` | Runtime schedules, running/queued check, last outcome, successful HTTP status/body bytes and pause state |
| `POST /api/v1/filter-refreshes/check` | Queue `{source: index}` for an active schedule; requires `If-Match`, returns 202, never promotes |
| `GET /api/v1/upstreams` | Profiles, transport/identity, attempts, successes and EWMA latency |
| `GET /api/v1/config` | Current complete `PolicyConfigSet` JSON and revision ETag |
| `GET /api/v1/shadow` | Current shadow generation/configuration or null, with revision ETag |
| `PUT /api/v1/config` | Validate, assert, compile, persist and atomically promote |
| `POST /api/v1/policy/test` | Compile and report all assertions without publication; failures return 422 with a report |
| `GET /api/v1/explain?client=127.0.0.1&domain=ads.example` | Current policy, matcher, rule and source explanation; `permitted: false` means DNS drops the client and the trace is hypothetical |
| `POST /api/v1/shadow` | Compile/persist a non-enforcing candidate |
| `DELETE /api/v1/shadow` | Clear the candidate |
| `POST /api/v1/shadow/promote` | Promote candidate content as a fresh generation |
| `GET /api/v1/revisions` | IDs, timestamps, actor, state and changed top-level fields |
| `GET /api/v1/revisions/{id}` | Inspect complete stored policy content |
| `POST /api/v1/revisions/{id}/rollback` | Recompile revision content into a fresh generation |
| `GET /healthz`, `GET /metrics` | Health and Prometheus counters/latency histogram |

Configuration and shadow reads provide an opaque ETag covering active and shadow
generations. Send that exact value in `If-Match` on mutation requests to reject
stale changes with 412 before compilation or persistence. The console always
uses this safeguard. Existing clients without `If-Match` retain unconditional
writes. Promotion captures the shadow under the same single-permit mutation
admission used for its precondition check; no mutex spans compilation or SQLite
I/O. Responses use `Cache-Control: no-store`; served assets receive a restrictive
CSP, `nosniff` and a no-referrer policy.

API mutations serialize: a concurrent compilation returns 409. Failed validation
returns 422; unavailable persistence returns 503 and leaves the running snapshot
untouched. A durable commit completes publication even if its HTTP client goes
away. Explanations are on demand; events store source/cache decisions, rule IDs,
latency and optional shadow differences. Shadow comparisons currently distinguish
action/rewrite changes; they do not compare upstream answer contents. Required
assertions check permanent allow/block behavior, excluding temporary exceptions,
not the contents of rewritten RRsets. Temporary decisions record a nullable
exception index alongside the policy/generation; old history has null provenance.

SQLite lives on a dedicated thread. Events use bounded `try_send`; dropped events
and failed history writes are counted. History retains the configured row count;
revisions retain the latest 32 plus active/shadow references. Disk files reuse
space after deletion but are not automatically vacuumed. Event timestamps are
persistence timestamps. Revision diffs identify changed configuration fields;
inspect the two full revisions for their detailed contents.

## DNS behavior and limits

- One recursive IN question per query; UDP and persistent client TCP supported.
- A/AAAA/CNAME and other ordinary records are forwarded through Hickory.
- Sequential fallback across up to eight addresses/profile; no racing of providers.
- Random upstream IDs and connected ephemeral UDP sockets; match ID, QR, opcode
  and question. Truncated or oversized UDP upstream replies retry TCP; truncated
  TCP/TLS replies are rejected. Client UDP replies respect 512 bytes without EDNS
  and a capped advertised size of 1,232 with EDNS.
- Separate bounded decision/response caches. Decisions partition by policy
  generation and policy. Responses partition by upstream identity (ordered
  addresses plus transport trust/identity settings, not timeouts or pool sizes),
  name, type, class and DO/CD, so publishing unchanged upstream profiles keeps
  warm answers while any upstream change starts a disjoint partition. Blocking
  and rewrites are decided before the response cache. TTLs age on hits. Whole messages
  expire conservatively at the earliest RR TTL; negative responses require SOA
  and use `min(SOA TTL, SOA MINIMUM)`. SERVFAIL, zero TTL and truncated responses
  are not cached. Final block/rewrite answers never enter the upstream cache.
- Bounded, sharded single-flight entries survive individual waiter cancellation.
  Cache/inflight mutexes never cover awaits or network operations.
- The engine passes DO/CD but performs **no DNSSEC validation** and clears AD.
  EDNS options (including ECS and cookies) are ignored and never forwarded.
  TSIG, transfers, ANY, non-IN, updates and nonrecursive requests are refused.
  Malformed packets are dropped.
- UDP ingress bounds local work (`max_udp_queries`) separately from cache misses
  waiting on upstreams (`max_udp_upstream_waits`, default 1,024). Blocks,
  rewrites and cache hits are answered without waiting, so a slow upstream
  cannot starve them; misses beyond the wait limit get SERVFAIL at once.
  Listener errors (including descriptor exhaustion) pause only that listener.
- Input frames are capped at 4,096 bytes; upstream responses at the DNS wire
  maximum. Cache limits are entry counts, not exact byte budgets; record/message
  and request bounds keep growth finite. Tune limits for available memory.
- Direct self-upstreams are rejected. Operators must prevent indirect forwarding
  loops. No firewall, port redirection or DNS bypass enforcement is installed.

## Verify and measure

Deployment checks (after building the release binary and console):

```sh
python3 scripts/release.py
python3 -m unittest discover -s scripts/tests -v
scripts/deployment-smoke.sh target/releases/RELEASE.tar.gz
cargo run -p rustwalld-dns --release --example resilience --locked -- --binary target/release/rustwalld-dns --output target/resilience.json
```

The Docker smoke test installs into a clean Debian container with no host service
access, privileged capabilities, host ports or writable bind mounts. It verifies
non-root UDP/TCP DNS, unit syntax, upgrade preservation, WAL backup and restore.
Native systemd sandbox activation remains a deployment-host check. The resilience
benchmark runs the real binary with four loopback clients, warmed block/cache
queries, 48 stalled HTTP bodies, a 200,000-rule shadow candidate and an external
SQLite write lock, then a scheduled HTTPS body stalled after authentication.
The scheduled phase caps its sample window at five seconds and verifies that
shutdown closes the download. It checks response correctness, rejected publication, admission
and telemetry drops, and records latency plus hardware/toolchain metadata.
Latency is diagnostic; stable hardware is required for regression thresholds.

The [filter memory comparison](docs/filter-memory.md) records fresh-process
RSS/peak and broader matcher workloads. Retain footprint and Criterion artifacts
locally; logical payload estimates are not exact RSS.

The [Rust 1.99 performance comparison](docs/rust-1.99-performance.md) separates
compiler, LTO and query-name ownership experiments, and explains the decisions
about unsafe code, Rayon and repository artifacts.

The [query allocation comparison](docs/query-allocations.md) covers blocked,
cached, rewritten and temporary-allow replies with closed/empty/full telemetry
queues. It records measured string-copy savings and protocol regression coverage.
The [forwarding allocation comparison](docs/cache-forwarding.md) measures short
and maximum-length cache hits after deferring forwarding work to admitted misses,
including DO/CD partitioning and mixed client size/casing regressions.
The [borrowed decision comparison](docs/borrowed-decisions.md) records one fewer
key allocation on warm hits, randomized map hashing, collision/partition tests
and repeated CPU-pinned timing checks, including slightly slower cache results.

The [CPU/query probe](docs/cpu-query.md) measures warmed local paths in a separate
Linux executable with no allocation-counter hooks. It records process CPU ticks,
quantization limits, hardware and binary identity, and rejects upstream work.
Short local runs verify accounting; longer quiet batches supply CPU estimates.

The [appliance comparison](docs/comparison.md) runs pinned Pi-hole, AdGuard Home
and our daemon against the same generated rules and isolated local upstream.
It checks DNS semantics before measuring UDP/TCP latency, appliance CPU, memory
and upstream request counts. It retains history/drop evidence and failed runs.
Linux cgroup v2, Docker and three distinct physical cores are required:

```sh
python3 scripts/compare-appliances.py --iterations 10000 --queries-per-second 1000 --scenarios blocked cache --output target/comparison/paced.json
```

These are closed-loop workload comparisons, not maximum-capacity claims.
The current release's remaining exit gates are native deployment/upgrade/restore
validation and a clean 24–72-hour representative-network soak; see the
[delivery checklist](docs/roadmap.md). Later features stay outside v0.1.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
cargo bench --workspace
DNS_BENCH_SIZES=100000,1000000,5000000,10000000 cargo bench -p rustwalld-dns-filter --bench matching
cargo run --release --locked -p rustwalld-dns-filter --example footprint -- 1000000
cargo run -p rustwalld-dns-core --release --example load
python3 scripts/measure.py target/release/examples/load
cargo test --locked -p rustwalld-dns-core --example cpu_probe
cargo build --release --locked -p rustwalld-dns-core --example cpu_probe
python3 scripts/cpu-probe.py --output target/cpu-query.json
# Optionally add --cpu N for a CPU in the current process's allowed affinity.
cargo install cargo-audit cargo-deny cargo-fuzz --locked
cargo audit
cargo deny check
rustup toolchain install nightly --profile minimal
mkdir -p fuzz/corpus/dns_message fuzz/corpus/filter_compile fuzz/corpus/tls_config fuzz/corpus/doh_response fuzz/corpus/policy_check
cp fuzz/seeds/dns_message/* fuzz/corpus/dns_message/
cp fuzz/seeds/filter_compile/* fuzz/corpus/filter_compile/
cp fuzz/seeds/tls_config/* fuzz/corpus/tls_config/
cp fuzz/seeds/doh_response/* fuzz/corpus/doh_response/
cp fuzz/seeds/policy_check/* fuzz/corpus/policy_check/
cargo +nightly fuzz run dns_message -- -max_total_time=30 -max_len=4096
# Generate bounded large seeds locally to exercise parallel parsing/indexing.
python3 - <<'PYSEEDS'
from pathlib import Path
corpus = Path("fuzz/corpus/filter_compile")
(corpus / "parallel-index").write_text("# parallel\n" + "".join(f"=d{i}.t\n" for i in range(40000)))
(corpus / "parallel-hosts").write_text("# hosts/IDNA\n" + "0.0.0.0 a.example bücher.example\n@@=safe.example\n" * 1400)
PYSEEDS
cargo +nightly fuzz run filter_compile -- -max_total_time=30 -max_len=524288
cargo +nightly fuzz run tls_config -- -max_total_time=30 -max_len=65536
cargo +nightly fuzz run doh_response -- -max_total_time=30 -max_len=65544
cargo +nightly fuzz run policy_check -- -max_total_time=30 -max_len=4096
mkdir -p fuzz/corpus/cache_lookup
cp fuzz/seeds/cache_lookup/* fuzz/corpus/cache_lookup/
cargo +nightly fuzz run cache_lookup -- -max_total_time=30 -max_len=4096
mkdir -p fuzz/corpus/download_config
cp fuzz/seeds/download_config/* fuzz/corpus/download_config/
cargo +nightly fuzz run download_config -- -max_total_time=30 -max_len=4096
```

The console adds reproducible real-browser verification:

On shared hosts with a busy tmpfs `/tmp`, use a disk-backed `TMPDIR` for browser
profiles/shared files. For example, from the repository root:
`mkdir -p target/tool-tmp && TMPDIR="$PWD/target/tool-tmp" npm --prefix web test`.
Keep native crash and failed-run evidence when diagnosing the test environment.

```sh
cargo build -p rustwalld-dns --locked
npm --prefix web ci
npm --prefix web run format:check
npm --prefix web run build
npm --prefix web exec -- playwright install chromium
npm --prefix web test
npm --prefix web audit
```

Playwright starts the real Rust binary with an isolated SQLite database, loopback
DNS mock resolvers and production UI assets. It uses local ports 18081 (HTTP),
15353 (DNS), 15354/15355 (mock upstreams), and fails rather than reusing an existing
server. Desktop/mobile tests verify authentication, memory-only credentials,
provenance, failed assertions, shadow/promotion/rollback against real DNS,
conflicting editors, preserved drafts, telemetry errors and multiline editing.
Screenshots and failure traces go to ignored `web/test-results/`.

Tests use local mock upstreams and real DNS/HTTP requests. They cover spoofed replies,
TCP fallback, TTL/negative semantics, cache partitioning, 1,000 coalesced waiters,
initiator cancellation, overload, reload, shadow/rollback, idle connections and
SQLite locking. Run fuzzing separately from other local checks and retain Criterion
artifacts under target/. There is no CI/CD or .github/ directory.

See [architecture](docs/architecture.md), [benchmark method](docs/benchmarks.md),
[measured baseline](docs/baseline.md), [console decisions](docs/management-ui.md),
[upstream diagnostics](docs/upstream-diagnostics.md),
and [delivery checklist](docs/roadmap.md).

Licensed under MIT OR Apache-2.0.

Endpoint outage admission and recovery are documented in [upstream backoff](docs/upstream-backoff.md) with [local before/after measurements](docs/upstream-backoff-baseline.md). The console uses a [semantic light/dark design system](docs/console-design.md) and task-specific layouts.


## Repeated control-plane recovery rehearsal

Run the real daemon under repeated conditional list checks, reviewed promotions
and SQLite writer failures. The harness uses bounded latency histograms and
records response correctness, counter reconciliation, resource observations,
retention and restart recovery. All network fixtures stay on loopback.

```sh
cargo build --release --locked -p rustwalld-dns --example control_soak
cargo build --release --locked -p rustwalld-dns
TMPDIR="$PWD/target/tool-tmp" target/release/examples/control_soak --binary target/release/rustwalld-dns --phase-ms 8000 --cycles 10 --rules 100000 --output target/control-soak.json
```

Build first, then measure with other build/test/browser/container jobs idle.
Use short cycles for local smoke verification and longer durations for measurement.
No network latency or RSS threshold is claimed across machines.
See [workload, bounds and evidence](docs/control-plane-soak.md).
