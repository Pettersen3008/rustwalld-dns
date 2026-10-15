# rustwalld-dns engineering contract

Build a local-first DNS policy/security engine in complete tested slices.
Correctness, security, predictable latency, maintainable structure and usable UI
are acceptance criteria. Throughput follows those priorities.

## Start and resume

Use `ponytail-loop` in personal context and `ponytail-mode` for engineering slices.
Repository planning is canonical; do not use Jira. Resume from the current sprint
and backlog within the user's requested scope. Keep mutable session checkpoints
under ignored `target/ponytail-loop/`, not in a second tracker.

1. Read [docs/README.md](docs/README.md), [architecture](docs/architecture.md),
   [workflow](docs/engineering/workflow.md) and [standards](docs/engineering/standards.md).
2. Read the [current sprint](docs/planning/sprints/sprint-05.md), then select the
   highest-priority ready story in [backlog](docs/planning/backlog.md). Follow a
   direct user request first; create/update its story as part of the work.
3. Inspect the affected code, tests and linked contracts. Repository facts beat
   stale plans. Keep existing uncommitted work intact; never reset it.
4. Write or update a short spec for behavior, architecture, security, performance
   or significant UI changes. Review it against code before implementation.
   Routine reversible choices are delegated to the agent. Resolve routine
   questions yourself, record assumptions, and continue through verification.

## Work autonomously

Own planning, task breakdown, implementation, review, verification, documentation,
backlog updates and retrospective. “Run the sprint” authorizes the selected sprint's
ready stories in dependency order; finish complete slices while scope permits.
A single-story request authorizes that story, not the rest of the backlog.
Keep one story in progress per agent. Multi-agent work requires authorization in
this session; give workers disjoint ownership and review their results.

Ask only when missing information blocks safe progress or a change needs new
user authority: product direction outside the request, breaking public/persistent
contracts, changing these safety boundaries, publishing, merging or activating
host/network services. Prepare the concrete proposal and safe verification first.
Existing authorization persists. Do not require approval for every spec or task.
Contributor merges still require maintainer review per CONTRIBUTING.md.
Never invent acceptance, approvals, test results or deployment evidence.

## Invariants

- This repository intentionally has no CI/CD or `.github/` folder. Verify locally;
  generated evidence belongs under ignored `target/`. No hosted workflows unless
  the maintainer explicitly changes this preference.
- Use Hickory for DNS protocol handling. Profile before replacing the parser or
  introducing custom tries, lock-free containers, io_uring or zero-copy machinery.
- DNS libraries must not depend on app or runtime. Query processing performs no
  filesystem, database, HTTP management, filter/config parsing or JSON operations.
  Never execute plugins on the query path.
- Bound networking, caches, inflight work, connections, queues, retries and telemetry.
  No lock spans an await or network I/O.
- Compile complete immutable generations off DNS executors. Validate assertions
  and durable revisions before ArcSwap publication. Keep provenance and generation
  identifiers. Rollback creates a new generation; changed content never reuses a
  live cache key. Keep HTTP and SQLite failures away from DNS.
- Production forbids unsafe, unwrap and expect. Test/benchmark fixtures may
  explicitly allow unwrap. Use typed errors and ownership-based modules.
- Matchers accept normalized ASCII names without a trailing root dot; allow rules
  take precedence over block rules. Keep stored interpreter versions frozen.
- Refuse transfers, ANY, non-IN, signed queries and nonrecursive requests. EDNS
  options are ignored (RFC 6891), never forwarded; upstream requests use a fresh
  envelope. Extend protocol/cache semantics and regressions together to lift limits.
- No zero-allocation or absolute performance claims without allocator, hardware
  and workload evidence. No fabricated UI counters or misleading health badges.

## Verify and finish

Before shipping meaningful changes run:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
python3 scripts/check-docs.py
```

Run relevant Criterion/loopback benchmarks for performance work; use
DNS_BENCH_SIZES for larger filters. Network tests use local mocks, never public DNS.
Run cargo audit/deny and targeted fuzzing for security/dependency/parser changes.
See [verification](docs/engineering/verification.md) and [design](docs/engineering/design.md)
for additional checks. Review your diff for defects and unnecessary complexity.

Update the story, acceptance evidence, current contracts and changelog when
behavior changes. Capture durable tradeoffs in a short ADR; finish sprints with a
review and retrospective. Report failures and unverified gates explicitly.
Do not commit, push, publish, merge or activate host services unless requested.

Keep docs lean: no session transcripts, per-task verification essays, pasted logs,
binary hashes or append-only delivery ledgers. Use existing contracts and sprint
records; scratch material and measurements stay under target/. Preserve licenses,
security policy and operator recovery guidance. [Cleanup map](docs/archive.md).
