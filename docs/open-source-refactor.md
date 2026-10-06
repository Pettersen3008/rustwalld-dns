# Reusable libraries and open-source preparation

Status: proposed implementation plan, 2026-10-06. This document authorizes no
publication or deployment. Implementation proceeds in independently verified
slices. Native deployment and the 24–72-hour network soak remain pending release
gates; this refactor does not satisfy or remove them.

## Goal and completion criteria

Make the existing DNS engine straightforward to embed, its component libraries
useful independently, and the standalone application maintainable by external
contributors. Preserve observable DNS, management, console, persistence and CLI
behavior. Performance is the primary design criterion among implementations
that preserve DNS correctness, security and resource bounds.

The refactor is complete when:

- An independent Rust consumer can construct the engine, serve local DNS,
  consume bounded events, change validated policy and shut down through public
  APIs without importing the standalone app, SQLite or Axum.
- Another consumer can use filtering or forwarding independently.
- An optional reusable runtime supplies the current persistence, revision and
  reviewed-list workflows without owning process signals or an HTTP server.
- The standalone binary, console, configuration format, API, SQLite schema,
  service name and recovery behavior remain compatible.
- Existing tests, fuzz targets, benchmarks and deployment fixtures retain their
  cases and semantics; new tests cover the actual library boundaries.
- Matched measurements show no reproducible performance regression beyond
  baseline variability. Ambiguous results require further measurement, not a
  claim that the refactor is free.
- Public APIs have useful documentation and runnable examples; crate archives
  can be consumed without the repository checkout.

No work in `~/Work/rustwalld` is part of this plan. Integration is demonstrated
by an independent consumer fixture in this repository. Compatibility with that
project's actual dependency graph and lifecycle remains unverified.

## Repository findings

These observations come from source inspection, not a fresh verification run.

| Current package | Existing responsibility | Main preparation issue |
| --- | --- | --- |
| `filtering` | Normalization, list compilation, exact/suffix rules, provenance | Generic name; public API documentation and consumer examples |
| `resolver` | UDP/TCP/TLS/HTTPS forwarding, bounded caches, coalescing, endpoint admission | Generic name; exposed cache/metrics implementation details |
| `policy` | Configuration, assertion-gated compilation, client selection, rewrites, exceptions | Generic name; public mutable compiled fields; large root module |
| `dns-core` | Wire query processing, UDP/TCP serving, telemetry | Public ArcSwap handles and resolver; processing and server code share root module |
| `rustwalld-dns` in `crates/app` | CLI, lifecycle, SQLite, HTTP, console serving, downloads and schedules | Reusable lifecycle and revision workflows are coupled to application adapters |

The four DNS libraries already have no dependency on the application. Preserve
that direction. Policy snapshots already construct resolver forwarders; removing
that dependency is not necessary for embedding and would add risk without a
demonstrated benefit.

Specific change points:

- `Engine` exposes `active`, `shadow`, `resolver` and `telemetry`. Consumers can
  bypass the application's publication rules through raw handles.
- `PolicySnapshot` exposes its generation, configuration, policies and upstreams;
  `CompiledPolicy` also has public fields. Assertion-gated constructors alone do
  not protect the result from external mutation before sharing it.
- `app::run` waits for operating-system signals. Library users need explicit
  lifecycle control instead.
- `api::stage` owns mutation admission, revision preconditions, compilation,
  persistence and publication. `refreshes::check` calls `api::stage_refresh`,
  constructing an HTTP precondition to perform a non-HTTP operation.
- `Store::call` returns `serde_json::Value`, requiring callers to interpret field
  names and types. Its commit mode is a string. These are control-plane concerns;
  JSON currently stays off the DNS query path.
- The large files include substantial tests: `control_plane.rs` is about 2,250
  lines and `protocol.rs` about 1,523. Production files top out around 771 lines.
  Line count alone is not evidence that code needs abstraction or deletion.
- No `beta_` or `alpha_` identifiers were found in the searched source. Naming
  cleanup should target actual ambiguous names, not historical evidence or
  descriptions of release maturity.
- Git currently has no commits and project files are untracked. Establish a
  reviewed recoverable baseline before implementation; do not mix an initial
  repository import with behavior-sensitive refactoring.

## Recommended package boundaries

Use a consistent project prefix. These names are proposals; registry availability
has not been checked. Keep short, responsibility-based module and type names
inside each package.

| Proposed package | Location | Public role |
| --- | --- | --- |
| `rustwalld-dns-filter` | `crates/filtering` | Standalone immutable filter compiler and matcher |
| `rustwalld-dns-resolver` | `crates/resolver` | Standalone bounded upstream resolver |
| `rustwalld-dns-policy` | `crates/policy` | Policy configuration, compilation and diagnostics |
| `rustwalld-dns-core` | `crates/dns-core` | Primary embedding entry point: engine, server, policy control and events |
| `rustwalld-dns-runtime` | `crates/runtime` | Optional durable lifecycle, revision service, history and reviewed list management |
| `rustwalld-dns` | `crates/app` | Existing executable and standalone HTTP/CLI adapters |

Keep the current directories during the package rename to reduce tooling churn.
Keep the binary `rustwalld-dns`, its environment variables, installed paths,
systemd unit and browser product identity unchanged. Update Cargo selectors,
Rust imports, fuzz manifests, CI, scripts, examples and documentation together.

Dependency direction, where an arrow means "depends on":

```text
app      -> runtime, core, policy as required by its adapters
runtime  -> core, policy, SQLite and control-plane download dependencies
core     -> policy, resolver, filter
policy   -> resolver, filter
resolver -> protocol and transport dependencies
filter   -> normalization and compilation dependencies
```

Core re-exports a small selection of configuration and event types so most
consumers do not need to coordinate imports from every component crate. It is
the real engine crate, not an additional facade that forwards every method.
Implementation modules remain private unless independent use demonstrates a
reason to expose them. Avoid a generic `common`, `utils` or `types` crate.

**Alternative:** retain the existing five packages and improve their APIs without
extracting runtime. This is lower effort and sufficient for DNS-only embedding.
The runtime extraction is recommended because revision/publication and scheduled
refreshes have an existing non-HTTP reuse case. Complete core embedding first;
do not make it depend on runtime extraction. A monolithic facade with feature
flags would complicate dependency isolation and feature combinations.

## Embedding and lifecycle contracts

There are two useful integration levels:

1. **DNS-only embedding:** depend on core, compile an initial policy off the DNS
   executor, construct bounded telemetry, bind a server on a host-selected DNS
   runtime, and supply explicit cancellation. The host owns its configuration,
   persistence and management interface.
2. **Full appliance runtime:** use the optional runtime for the existing durable
   revisions/history and list workflows, then choose whether to mount the
   standalone HTTP adapter. Runtime must not require that adapter.

An external process using the existing local management API is also viable and
retains process isolation. Embedding is an option, not a requirement for using
this project alongside Rustwalld.

Proposed API responsibilities (names and signatures finalized in the API slice):

- `EngineConfig` names cache/inflight bounds instead of positional size arguments.
  Defaults and standalone validation preserve current behavior.
- `Engine::answer` retains its current wire-processing semantics. Keep per-query
  types and dispatch concrete; configuration and lifecycle convenience must not
  introduce boxed futures, virtual callbacks, new queues or extra state loads.
- `Server::bind` / `Server::run` retain UDP/TCP admission, deadlines and explicit
  cancellation. The embedding example documents placement on a dedicated DNS
  executor to preserve control-plane scheduling isolation.
- `PolicyController` supplies read-only snapshots and checked active/shadow
  updates instead of exporting raw ArcSwap stores. Compilation must pass required
  assertions; reject stale preconditions and reuse of a live/retired generation
  identifier for different content. Track generation high-water state rather
  than an unbounded set of all previous generations. Failed allocations may leave
  gaps, as they do now. Rollback and shadow promotion create fresh generations.
  Runtime restoration initializes allocation/high-water state from durable
  revision history, not just the active snapshot. A volatile consumer starts
  with empty caches and declares its initial generation ownership.
- In-memory policy control and durable revision service have different contracts.
  Core cannot prove that a host persisted a revision. Document that responsibility
  explicitly; runtime preserves durable commit before live publication, including
  startup restoration and HTTP-client cancellation. Do not add an unchecked
  public "publish anything" escape hatch to simplify adapters.
- Events remain bounded, best-effort, nonblocking channel messages. Provide
  read-only metric access without rebuilding reports in the query path. Preserve
  existing closed/full queue behavior and counter meanings.
- Runtime accepts caller configuration, runtime handles and cancellation. The
  executable owns environment reads, signal registration, global tracing setup
  and process exit. Retain separate DNS/control executors and blocking limits.
- Shutdown must stop admissions and background work, retire pools and preserve
  current bounded drain ordering. An embedding wrapper must supervise tasks;
  dropping a join handle must not silently abandon a running appliance.

Existing local dependency use is technically possible today:

```toml
[dependencies]
dns-core = { path = "../rustwalld-dns/crates/dns-core" }
```

After the planned package rename, the equivalent consumer declaration is:

```toml
[dependencies]
rustwalld-dns-core = { path = "../rustwalld-dns/crates/dns-core" }
```

These are illustrative declarations, not changes to Rustwalld. A published
version or a Git dependency pinned to a reviewed commit can later replace the
local path. The host controls the final dependency resolution and build profile;
this workspace's release settings cannot guarantee another application's
performance.

## Ordered implementation slices

Every slice gets a focused diff, review, appropriate checks and its own retained
evidence. Do not combine algorithm changes, dependency upgrades and structural
refactoring.

### 0. Preserve the baseline and inventory contracts

- Establish a reviewed Git baseline, retain the current shipping binary/bundle
  and hashes, and record compiler, lockfile, build profile and machine identity.
- Run the existing verification suite. Build benchmark fixtures and the shipping
  binary separately to avoid dev-dependency feature unification.
- Capture quiet sequential Criterion, allocator, CPU/query and loopback baselines.
  Reuse existing historical reports as context, not as a substitute for matched
  current measurements.
- Inventory DNS restrictions, management status/error bodies and ETags,
  serialized config, SQL schema, history counter meanings and shutdown behavior.
  Retain original test case identifiers to reconcile later moves.

Acceptance: a recoverable source/artifact baseline and a documented test and
performance comparison method. Do not claim current checks passed until run.

### 1. Rename packages without restructuring behavior

- Apply the names above to the four libraries and all references.
- Add accurate crate descriptions and initial module-level docs. Do not fabricate
  a repository URL, maintainer contact, MSRV or portability claim.
- Keep binary and external configuration/API names stable; retain historical
  measurements with their original artifact identities.
- Map old benchmark package names to new ones while retaining benchmark cases,
  input data, warm-up and instrumentation semantics.

Acceptance: workspace, fuzz and tooling references resolve; required checks and
benchmark compilation pass. Confirm changed binary identity where relevant,
including package/module names appearing in diagnostics or tracing targets.

### 2. Split modules and organize tests mechanically

- Core: `engine`, `server`, `response`, `decision_cache`, existing `telemetry`.
- Policy: `config`, `compile`, `selection`, `rewrite`, existing assertions,
  exceptions, metadata and sources.
- App: group HTTP routes by read-only status/history, diagnostics, downloads and
  revisions; isolate HTTP admission/authentication from business operations.
- Resolver: retain its useful existing transport/cache/admission modules; avoid
  restructuring them merely for symmetry.
- Group integration tests by protocol/cache/reload/expiry and
  revisions/downloads/schedules/recovery. Extract shared fixtures with explicit
  cleanup; keep imports and public visibility as narrow as possible.

Acceptance: unchanged case inventory and assertions, green checks, matched
performance evidence for moved hot code. Keep public re-exports during mechanical
moves; changes to supported Rust APIs are isolated in the next slice. Do not set
an arbitrary source-line reduction target or weaken tests to make files smaller.

### 3. Define and verify the core library API

- Encapsulate compiled snapshots and engine mutation; add read-only accessors,
  named limits and checked publication APIs.
- Document valid input normalization, generation ownership, cancellation,
  executor placement, overload responses and event delivery guarantees.
- Add useful `Debug` and standard traits where appropriate; redact secrets and
  avoid expensive snapshot dumps. Use typed errors for decisions callers need
  to handle, without changing standalone HTTP or CLI messages.
- Add an independent Cargo consumer fixture that imports only public APIs.
  Demonstrate local mock resolution, blocking, allow precedence, policy reload,
  shadow state, cancellation and two independently managed engine lifecycles.
- Add small examples for core, filtering and resolver. No public DNS in tests or
  verification; examples state when they require a configured upstream.

Acceptance: external consumer tests pass; stale/reused generations and
post-compilation mutation cannot bypass invariants; the core dependency tree
contains no app, Axum, rusqlite, TOML loader or serde_json. HTTP/HTTP2 transport
dependencies remain legitimate for DNS-over-HTTPS. No new per-query allocation,
dispatch or synchronization cost without measured justification.

### 4. Extract revision operations from HTTP

- Introduce a concrete control service for test, stage, promote, clear shadow,
  rollback and scheduled refresh staging.
- Replace internal string commit modes, JSON-indexed store replies and HTTP
  headers/status values with typed requests/results/errors. Keep serialized SQL
  policy content and API responses compatible at their adapters.
- Both HTTP and the scheduler call this service. Preserve bounded mutation
  admission, candidate capture and revision checks, blocking compilation,
  durable commit, publication order and cancellation-safe task ownership.
- Keep the SQLite worker concrete. A generic persistence trait is deferred until
  a real second implementation needs it.

Acceptance: API/browser/process tests preserve bodies/statuses/ETags and durable
active/shadow state. Local tests cover cancellation during commit, SQLite locks,
stale refresh completion, rollback and post-commit recovery. This is the highest
risk slice and requires targeted failure rehearsals, not just unit tests.

### 5. Extract optional runtime and thin application adapters

- Move the control service, SQLite/history, maintenance, downloads and scheduler
  into runtime with configuration supplied as values.
- Extract explicit start/run/stop ownership; move signals and global setup to the
  executable. Separate file loading and CLI formatting from reusable operations.
- Keep HTTP/console serving in app. Preserve limits, deadlines, startup
  restoration, telemetry delivery, list trust and pending-shadow recovery.
- Reconcile fuzz targets and all process/script/packaging entry points.

Acceptance: runtime consumer operates without Axum or process signal ownership;
standalone browser/process and packaged upgrade/backup/restore checks pass;
matched DNS failure/reload measurements retain behavior and bounds.

### 6. Prepare distribution and contributor workflows

- Rework README around "run the appliance", "embed the engine" and "use a
  component". Keep operational contracts and measured limitations accessible.
- Add crate READMEs, checked doctests, CONTRIBUTING, security reporting guidance,
  a changelog and a documented API/versioning/support policy. Use a confirmed
  reporting channel and actual project URL rather than placeholders.
- Select and test an honest MSRV from code and dependency requirements; keep it
  separate from the pinned performance/release toolchain. Add appropriate stable,
  MSRV, documentation and external-consumer CI checks.
- Define minimal package contents with licenses, READMEs and examples. Audit
  package contents for missing assets and unintended generated evidence.
- Verify packages in dependency order. Before the new dependencies exist in a
  registry, use an isolated local registry/source replacement to validate archives
  and their consumer graph; do not waive verification with `--no-verify` and
  describe that as publication readiness. Registry dry runs follow when registry
  dependency versions are available.
- Check proposed registry names and stage a release checklist. Publishing remains
  a separate explicitly requested action.

Acceptance: documented public APIs build, archives are independently consumable,
dependency/version metadata is coherent and new contributors can reproduce
checks. Do not claim Windows/macOS support without testing it; current appliance
deployment is Linux/systemd and several probes use Linux `/proc`.

### 7. Run final matched comparisons and close the refactor

- Run the full original and new checks; reconcile cases moved between modules.
- Repeat baseline performance workloads with before/after binaries in alternating
  order on the same machine, with other builds/tests/containers idle.
- Record unfavorable results, investigate confirmed regressions and simplify or
  revert abstractions that add cost. Correctness failures always block acceptance.
- Verify release packaging, upgrade and recovery again. Update architecture and
  roadmap to describe the actual final structure, not just this proposed shape.

Acceptance: completion criteria above satisfied with reviewable artifacts. Native
activation and representative-network soaking remain separate pending gates.

## Verification and benchmark contract

Required commands before shipping meaningful slices:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
cargo bench --workspace --no-run --locked
```

Add public documentation and independent-consumer checks as those artifacts are
introduced. Preserve the existing browser, Python orchestration, fuzz and
deployment checks; run relevant failure rehearsals after publication/lifecycle
changes and the complete suite at final acceptance. Run audit/deny and targeted
fuzzing for dependency, security and parser-sensitive work.

| Concern | Evidence |
| --- | --- |
| DNS correctness | Existing protocol tests: flags, questions, EDNS, truncation, negative TTL, transport validation and refused requests |
| Policy isolation | Generation/cache partitions, allow precedence, provenance, assertion failures, expiry and pinned old-generation work |
| Admission and lifecycle | Coalescing, cancellation, overload, retirement, full/closed event queues and shutdown regressions |
| Durable workflows | API/browser tests, locked/failed SQLite, stale edits/refreshes, restart, rollback and packaged backup/restore |
| Reuse | Independent core/component/runtime consumers and checked documentation examples |
| Timing and allocations | Existing matching/cache/TLS/HTTPS/engine Criterion cases and separate allocator probes |
| CPU and memory | CPU/query probe, fresh-process filter footprint, sampled daemon resources and bounded structure inspection |
| Whole appliance | Matched local mock loopback, reload/failure/control-plane rehearsals; equivalent appliance comparison when relevant |

Follow the existing method in [benchmarks.md](benchmarks.md). Expand rule sizes
using `DNS_BENCH_SIZES` (100k, 1M, 5M and 10M for final filter storage evidence);
keep large fixtures generated. Preserve cold/warm distinctions, long-name and
DO/CD cases, broader working sets and enabled history/telemetry conditions.

The agentic iteration loop is: retain an unchanged baseline, state a hypothesis,
make one bounded change, verify answers and invariants, measure sequentially,
review complexity, then keep or revert. Never change benchmark inputs, disable
caching in cache-specific workloads, remove history or relax security to reach a
score. Extra workloads are additive and clearly labeled. Build flags, toolchains,
affinity and features must match both sides. No blanket inlining, custom parser,
tries, lock-free structures or SIMD without profiling evidence.

A structural refactor may be performance-neutral. Do not force a 20% speedup or
line-count reduction. Preserve improvements only with evidence; stop when
remaining ideas add complexity without demonstrable value. Additional tests must
exercise contracts and failure modes, not mirror implementation or target an
arbitrary test count.

## Rust design guidance and research

The public [Let's Get Rusty anti-patterns video](https://www.youtube.com/watch?v=SWwTD2neodE)
lists error handling, standard traits, excessive cloning, pattern matching and
glob imports as its topics. The public description/chapter list was inspected;
this plan does not claim access to its course or a full video transcript. Apply
those concerns through explicit ownership, useful errors, standard conversions,
focused imports and narrow module visibility; an Arc clone can be intentional
for snapshot lifetime and is not automatically waste.

Use the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/checklist.html)
to review naming, interoperability, documentation, predictability and API
evolution. These are review aids, not reasons to add speculative traits/builders.
Use [Cargo's MSRV guidance](https://doc.rust-lang.org/cargo/reference/rust-version.html)
to declare and verify supported compiler versions, and
[Cargo's publishing guidance](https://doc.rust-lang.org/cargo/reference/publishing.html)
for metadata, package verification, versioning and release preparation.

[Max Woolf's iteration article](https://minimaxir.com/2026/09/agentic-iteration/)
motivates unchanged baselines, constrained iteration and scrutiny of misleading
speedups. Its numerical targets and source-line goals are not requirements for
this DNS project. The project's existing correctness/security/performance
contract remains authoritative.

## Immediate next implementation task

Start with slice 0, then complete the package-only rename in slice 1. This produces
a recoverable measured starting point and meaningful names before exposing new
APIs. Leave algorithms, storage layout, transports, product behavior and Rustwalld
integration unchanged during those slices.
