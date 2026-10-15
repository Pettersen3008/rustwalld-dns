# Independent security review scope

Prepared for DNS-010; self-reviewed against repository source and contracts,
2026-10-15. This is a review brief and reproducible source packet, not an independent
review or approval to expose/deploy the service. No reviewer is identified yet.
DNS-024 owns the actual independent review and finding disposition.

## Review target and trust boundaries

The subject is the six-crate workspace, console, fixture/build/install paths and
locked dependencies. Start with [architecture](../architecture.md),
[security contracts](../architecture/security.md), [API limits](../architecture/api.md),
[filtering](../architecture/filtering.md), [recovery](../operations/install.md) and
[SECURITY.md](../../SECURITY.md). The latter conservatively advises loopback
administration; opt-in HTTPS/LAN capability is not a production-hardening claim.

Threat actors include malformed/high-rate DNS clients, malicious upstream replies,
untrusted imported/filter/publisher content, unauthenticated HTTP clients and
authenticated users exceeding their role. Compromised management credentials,
local root, trusted release origins and the operator's network/storage choice are
separate trust assumptions; identify what each compromise permits. Multi-tenant
isolation, DNS bypass prevention, recursive DNSSEC validation, automatic HA and
Windows/macOS appliance hardening are not implemented claims.

| Surface and source entry points | Review invariant and failure case | Existing test/fuzz footholds |
| --- | --- | --- |
| [DNS ingress](../../crates/dns-core/src/server.rs), [admission/wire](../../crates/dns-core/src/engine/admission.rs), [encrypted ingress](../../crates/app/src/secure_dns.rs) | Protocol refusal, frame/deadline/connection limits; malformed/truncated/signed/nonrecursive/non-IN/ANY/transfer traffic cannot bypass policy or exhaust unbounded work | core protocol/stale tests, app secure_ingress; dns_message, engine_prepare, server_tls |
| [Resolver](../../crates/resolver/src/lib.rs), [TLS](../../crates/resolver/src/tls.rs), [HTTPS](../../crates/resolver/src/https.rs), [cache](../../crates/resolver/src/response_cache.rs) | Validate complete response identity/envelope; TLS identity and no downgrade; cache namespace/TTL/DO/CD/stale semantics; hostile CNAME/additional records and inflight cancellation | resolver UDP/TLS/HTTPS/diagnostics; cache_lookup, dot_response, doh_response, serve_stale |
| [Filtering](../../crates/filtering/src/parsing.rs), [indexes](../../crates/filtering/src/index.rs), [policy/local records](../../crates/policy/src/local_dns.rs) | Normalization, frozen interpreters, allow precedence, bounded regex/record work, qtype/client/tag partitioning, expiry/schedule transitions and original provenance | filter/policy/core suites; filter_compile, policy_check, service_records, schedules, services, safe_search |
| [HTTP/auth middleware](../../crates/app/src/api.rs), [login](../../crates/app/src/api/authentication.rs), [listener](../../crates/app/src/listener.rs) | Trace actual middleware order: auth/roles, Host/Origin/CSRF, body/deadline/admission ownership and cancellation. Inspect public status/metrics/auth-info/health/assets separately | app control_plane/security, secure_ingress, process; real HTTPS web permission flows |
| [Identity store](../../crates/app/src/auth/store.rs), [private file](../../crates/app/src/auth/file.rs), [crypto](../../crates/app/src/auth/crypto.rs) | Fixed Argon2 costs, bounded sessions/hash jobs/tokens, durable TOTP replay and revocation, time rollback, private file modes, failed writes/recovery and secret redaction | app auth tests and auth_resilience; identity |
| [Publication](../../crates/runtime/src/control.rs), [core controller](../../crates/dns-core/src/control.rs), [store worker](../../crates/runtime/src/store/worker.rs) | Assert/compile/persist before immutable publication; durable revision high-water marks, stale ETags, cancellation, rollback as new generation and pinned inflight state | app control_plane/revisions, runtime store/control tests; engine_prepare, policy_check |
| [Downloads](../../crates/runtime/src/downloads.rs), [refresh worker](../../crates/runtime/src/refreshes/worker.rs), [remote adapters](../../crates/app/src/integrations/remote.rs) | Privileged pinned HTTPS egress, URL/trust/body/header bounds, conditional 304 semantics, queue/cancellation and failed refresh isolation; advisory discovery cannot grant DNS identity | app downloads/integrations, runtime refresh/download tests; download_config, lease_inventory |
| [Migration](../../crates/app/src/migration/mod.rs), [TOML/TLS files](../../crates/app/src/config.rs) | Bounded archive/scalar expansion, duplicate/ambiguous layout refusal, unsupported source semantics, path/permission/error redaction; imports create reviewed drafts | migration/import suites, process/policy_check; migration, tls_config |
| [History/privacy](../../crates/runtime/src/store/history.rs), [schema](../../crates/runtime/src/store/schema.rs), [maintenance](../../crates/runtime/src/maintenance.rs) | Bounded best-effort telemetry, separate durable policy writes, privacy retention, corrupt/future schema refusal, live WAL backup and absent restore destination | app maintenance, runtime store/privacy tests, isolated package/native recovery |
| [Remote rehearsal intake](../../crates/app/examples/support/soak_record.rs), [driver](../../crates/app/examples/remote_soak.rs) | Strict bounded records, private numeric endpoints, oracle/counter/output caps, cancellation ownership; collector and operational authority are external trust assumptions | remote_soak example tests; seeded soak_record sanitizer target |
| [Installer](../../scripts/install.py), [unit](../../packaging/rustwalld-dns.service), [container](../../packaging/Dockerfile), [console](../../web/README.md) | Trusted bundle/member/path validation, credentials/state ownership, native/container least privilege, UI token/CSRF handling and dependency/license provenance | Python deployment tests, package/native fixture, web browser suites, audit/deny/Bun audit |

Review cancellation, malformed/huge/concurrent input and failed persistence across
these boundaries. DNS processing must perform no config/file/SQLite/HTTP/JSON or
plugin work, and no lock may span await/network I/O. Library dependency direction,
resource bounds and public/persistent compatibility are acceptance constraints.

## Bounds and known limits to challenge

- `api.rs` defines 16-MiB bodies, 32 management slots and two heavy permits. Login
  separately admits two hash jobs before its 4-KiB/5-second upload. Verify permits
  survive cancelled bodies/blocking work; do not assume JSON parsing alone bounds
  all concurrent allocations. Library configuration can exceed HTTP intake limits.
- Migration input is 16 MiB and aggregate expanded content 64 MiB. File, parser and
  compile bounds differ: review the complete intake path, not one length check.
- Source retrieval deliberately allows pinned unicast private/loopback endpoints
  for operator-controlled local services. Pins/trust are not a blanket SSRF denial
  policy. Review what operator/admin roles may reach and whether credentials can
  cross destinations. URL query tokens can be secrets in policy exports/backups.
- `/healthz` intentionally bypasses management-slot saturation. Status, metrics,
  auth info/login and console assets are outside protected policy routes. Review
  actual data exposure/admission; do not describe the whole HTTP router as private.
- The engine clears AD and delegates DNSSEC validation to the selected upstream;
  no plugin or firewall enforces client DNS use. Indirect/self-interface forwarding
  loops remain an operator responsibility. Peer copying is reviewed content, not HA.
- Schema 6 alone does not make older binaries compatible with V6 rules, tags,
  schedules, records or encrypted profiles. Identity/TLS/master credentials are
  outside policy SQLite backup. Review upgrade/recovery with that separation.
- Native sandbox probes passed only in the Sprint 04 Debian/KVM guest, with a
  temporary non-weakening probe drop-in. Actual older-binary downgrade, ARM,
  representative-network soak and independent review remain open gates.

These are review inputs/known limitations, not claims that every listed attack
works or has been ruled out. Distinguish source facts, observed reproductions and
unverified concerns in the findings.

## Local packet and reproduction

Sprint 05 prepares `target/review/sprint-05/security-packet/` locally:

- `source.tar.gz` contains the exact nonignored working source, including new docs;
  it excludes `.git`, generated target data and local credentials/state.
- `source-manifest.json` records base revision, each file hash/mode and archive
  hash. `working.diff` and `git-status.txt` distinguish the snapshot from its base.
- `scope.md` freezes this brief. `checks.json` and `security-scans.json` record
  actual commands/exits; raw test/scan logs remain in the parent evidence directory.

Subsequent work adds the remote driver, target-local HTTP/verified HTTPS collector,
offline report consistency checks and failure/cancellation coverage. Sprint 08 also
repairs production truncated-response encoding, plus example oracle/file/phase
boundaries. Include every later diff and the current locked dependencies in the
actual review target; the historical Sprint 05 packet does not represent them.
Current verification evidence is under target/review/sprint-08/ and sprint-09/.
For the actual review, prepare a fresh local packet from an explicitly selected
clean commit, retain exact file hashes/modes and command records, and verify the
extracted source before running checks. The later lease corpus is synthetic parser
coverage; it does not represent an operational device inventory. Neither engineering
peer review nor the offline checker satisfies independent security acceptance.

Verify every extracted file against the manifest before review/build, and compare
the changed files to the base revision. A checksum detects mismatch, not source
authenticity; obtain the expected identity from the maintainer. Never substitute
the base commit alone for a later dirty source snapshot. Test certificates/keys
in source are public fixtures; production keys, query histories, auth files,
policy exports and VM disks must not enter the packet. No upload/contact is
authorized by packet preparation.

Run [required checks](verification.md) in an isolated checkout. Focused entry points:

```sh
cargo test -p rustwalld-dns --lib auth --locked
cargo test -p rustwalld-dns --test control_plane --test secure_ingress --test maintenance --locked
cargo test -p rustwalld-dns-resolver --locked
cargo test -p rustwalld-dns-core --locked
cargo audit
cargo deny check
(cd fuzz && cargo audit && cargo deny check)
```

Use the seeded sanitizer procedure in verification.md for affected parsers, plus
the appropriate table targets. `identity` and `server_tls`
currently have no checked-in seed directory: prepare bounded public valid/invalid
fixtures before claiming seeded mutation coverage. Target presence alone is not
fuzz evidence. Build a cold fuzz target separately; timeout means incomplete.
`lease_inventory` now has ten synthetic valid/invalid seeds and five actual-parser
replay/boundary tests; see [DNS-036](../specs/DNS-036-lease-parser-seeds.md).
Console changes need Bun audit and real-daemon HTTP/HTTPS browser/role checks.
Native destructive fixtures require their explicitly authorized fresh VM; ordinary
test permission does not authorize production activation or live-data fault tests.

Sprint 05 refreshed root/fuzz audit and deny, plus required workspace/example
checks. Deny emits duplicate-version/license-exception warnings retained in logs;
zero exit is not a warning-free result. No parser/auth/dependency implementation
changed here, so new fuzz campaigns/UI/native runs were not claimed or required.

## Reviewer result and closure

The maintainer must identify an independent reviewer, source identity, agreed
surfaces/exclusions and review method/access before DNS-024 is Ready. Preparing
this packet or a self-review does not meet that requirement. Refine large review
work with the reviewer; no reviewer tasks or messages are sent automatically.

Return the reviewed source identity, reviewer/date/method/coverage and each finding's
path/line, threat precondition, minimal private reproduction, impact and confidence.
Classify confirmed defect, likely defect, concern or dismissed with evidence.
Triage severity with the maintainer; high-impact unresolved integrity/auth/bounds
findings prevent the corresponding release/security claim. Fix confirmed defects
with regressions and affected verification; give unresolved gaps an owner and next
action. New relevant code requires review of that new diff. Follow SECURITY.md for
private vulnerability reporting; do not put exploit/private data in public issues.
