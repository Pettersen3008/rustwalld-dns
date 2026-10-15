# Administration privacy and encrypted ingress

## Local administration implementation contract

Local administration includes password sessions, optional TOTP, scoped automation
tokens and privacy choices. Preserve the existing environment bearer token as an explicit emergency
administrator credential; TOTP protects password sessions, not automation tokens.
Authentication never enters DNS workers or the published policy configuration.

Use the maintained RustCrypto Argon2id implementation, Ring for secure randomness,
SHA-256 token digests and RFC 6238 HMAC-SHA1 TOTP. Avoid a custom password KDF,
JWT parser or backtracking password validation. Pin supported hash parameters on
intake: memory 32768 KiB, three passes, one lane, 32-byte output, 16-byte random
salt; do not honor arbitrary cost parameters from a modified credential file.
Verify on at most two bounded blocking workers. Login traffic has a separate
global rate budget and at most 256 per-source budgets, never a DNS query lock.

Process configuration may select a separate private credential file and must
require HTTPS administration when it does. Read it with size and permissions
bounds before binding. Keep passwords out of argv, policy imports, query history
and log errors. CLI initialization takes a password through stdin and creates an
absent 0600 file. Password hashes, TOTP provisioning secret, replay counter and
token digests are local security state. Configuration/database backup alone does
not back up the credential or certificate files; document and test recovery.

TOTP uses six digits and 30-second steps with a one-step clock window. Verify
using constant-time comparison, then durably advance the last accepted step
before issuing a session. Concurrent/restarted requests cannot reuse that step.
Failed persistence yields no authenticated session and never affects DNS.
Clock rollback must not reset replay protection.

Sessions use a fresh 256-bit opaque value, with only its SHA-256 digest retained.
Bound sessions to 64, an eight-hour absolute lifetime and thirty-minute idle
expiry. Cookies use `__Host-`, Secure, HttpOnly, SameSite=Strict and Path=/ without
Domain. Mutations authenticated by a cookie need a separate unpredictable CSRF
header tied to that session. Bearer auth cannot fall back to cookies when invalid.
Never trust X-Real-IP/proxy headers for rate admission or identity.

Automation roles: read-only (existing read APIs), operator (DNS policy actions),
administrator (credential/token management as well). Token creation/revocation
requires an administrator and a durable private-file update before publication.
Bound tokens to 64, names to 128 bytes and explicit expiries. Return a minted
token only once; listing returns metadata, never token values or digests.
Read-only users should see disabled mutation controls and the API must still
reject writes. Public status/health behavior is reviewed independently from
secret-bearing configuration/query endpoints.

Credential changes compile immutable identity state off async/DNS executors,
write an atomic durable private file and publish only after success. A dedicated
blocking mutation guard may span private file I/O; no lock spans await/network
I/O, and request authentication never waits on that writer. Cancellation must
retain hashing/mutation admission while blocking work survives. Repeated slow
logins/failed auth-file writes must not degrade UDP/TCP/DoT/DoH correctness.

Console sign-in supports password/TOTP over HTTPS and the legacy bearer mode.
Cookies and CSRF state stay local; no credentials in localStorage/URLs. Logout
revokes the server session and clears browser cookies. Refresh/resume semantics
must be explicit and tested. Show one-time token values only in a review dialog,
with clear expiration/scope and intentional clipboard copying.

Verification: RFC TOTP vectors/replay/clock boundaries; Argon2 configuration and
correct/incorrect credentials; real HTTPS cookie flags, CSRF, expiry, logout and
role enforcement; cancelled/over-budget logins; durable revoke/restart and failed
private-file writes; source credentials never appear in import reports. Desktop
and mobile sign-in/token flows run against the real TLS daemon with local trust.
Measure concurrent logins during loopback DNS traffic and steady/transient RSS.
Run required Cargo checks, root/fuzz audits/deny and parser fuzzing after changes.

An external identity proxy was considered. Keep it an optional deployment choice:
it cannot provide per-client DNS identity or a local offline recovery path by
itself. Native authentication is isolated from DNS and remains deliberately
small; external identity/SSO is a later adapter, not a query-path plugin.

### Implemented administration slice

The fixed-cost Argon2id password, RFC TOTP/replay, durable private identity file,
bounded sessions, scoped tokens, HTTPS-only password/cookie authentication and
CSRF/origin checks are implemented. `auth init --password-stdin` creates an absent
0600 file and prints its authenticator provisioning URI once. `auth_file` is a
process setting requiring `api_tls`; credentials never enter a policy revision.
The console supports password/TOTP and bearer sign-in, token creation/review/
revocation and read-only controls. Password/code fields clear after each attempt.
It does not automatically resume cookies on refresh; sign in explicitly again.

For the native package, place writable identity state under
`/var/lib/rustwalld-dns/auth.json`, owned by the `rustwalld-dns` service account.
Run initialization as that account, configure the top-level `auth_file` path and
HTTPS, then restart explicitly. `/etc` is read-only inside the native systemd
sandbox; putting the mutable identity file there breaks TOTP replay commits and
token administration. The StateDirectory remains writable under ProtectSystem.
Keep certificate/key files in the reviewed read-only configuration location.

Global login allowance is 30 attempts/minute, 10/source/minute, with at most 256
source windows. Hash admission is acquired before reading the 4-KiB/5-second
upload. Every surviving blocking job retains its permit through cancellation.
Directory-sync/write errors fail identity authentication closed; the environment
administrator token remains the emergency path. `POST /api/v1/auth/recover`
reloads verified private state, durably rewrites it as a new identity revision and
clears sessions. Never reset the TOTP replay counter during normal recovery.
Restoring a credential backup requires reviewing old token digests/expiries and
revoking obsolete credentials independently of restoring DNS policy.

Token expiry combines the absolute time with a monotonic deadline (clamped to
30 days on load). An expired token cannot revive after a clock rollback or an
unrelated mutation in the running process. Restart still requires a correct
system clock for absolute expiries, certificate validity and TOTP. Credential
changes are isolated from DNS and no query awaits private-file writes/hashing.

Local checks: `cargo test -p rustwalld-dns --lib auth`, the real binary
`secure_ingress` test and `bun run test:auth`. Browser fixtures use public test
credentials and deliberately trust a self-signed fixture for UX only; Rust
tests separately assert certificate trust/hostname/plaintext rejection. Native
long-duration operation and independent authentication review remain release
gates. Password change, authenticator re-enrollment and multi-user administration
are not represented as implemented by the single-administrator/token slice.

## Query-history privacy implementation contract

Provide three explicit persisted modes: full query history, history without client
identity, and disabled new query logging. Aggregate DNS counters/latency and policy
assertions continue in every mode. Disabling logging must not enqueue new query
events or touch SQLite from DNS workers. Client identity is still needed in memory
for admission/policy selection; masking applies to retained history, not networking.

Keep these operational preferences outside policy generations and credentials.
Schema 4 adds one bounded privacy-preference row with a monotonic revision, mode
and row-retention bound, plus a persistent next-query-ID counter. History inserts
advance that counter in their transaction; clearing rows never resets it. A new
database seeds preferences from process settings;
existing durable preferences win at restart. Every change requires its own current
ETag and administrator access. Validate on the control side, commit durably on the
SQLite worker, update that worker's batching/retention state, then publish the DNS
telemetry flag. Failed storage yields no preference publication and does not
change DNS behavior. Cancellation cannot drop an admitted preference mutation.

The worker skips writes when logging is disabled, including events queued before
the flag changed. The query path reads one atomic logging flag and retains all
aggregate counters, including shadow differences. Masked history writes
`anonymous` instead of the source IP; the API marks that value so the UI disables
client-specific repair/current-IP explanation. Historical generation/rule
provenance still works. Configured client bindings remain configuration data.

Retention is bounded to at most one million rows. Setting a lower bound trims
oldest rows in the same durable update. Logging off preserves existing history
unless the operator explicitly selects clear-history in the review dialog.
Clearing rows cannot promise erasure from WAL, backups, snapshots or filesystem
blocks. Do not expose an irreversible erase checkbox as a reversible draft edit.
The operator may separately remove private backups/volumes when required.

Update schema checks, backup verification, SQLite migrations and packaging smoke
fixtures together. Existing v1/v2/v3 databases retain revisions/history and get
default privacy settings on first open. A disabled-history startup must not create
query rows. Backup/restart restores the chosen mode and retention revision.
The UI labels traffic graphs as retained samples, explains disabled/masked history
and keeps live resolver health available. Preference controls show the actual
persisted revision and require an explicit review before changing or clearing it.

Verify mode changes while UDP/TCP and encrypted DNS continue, masks in history,
retention boundaries, stale ETags, role/CSRF enforcement, cancellation and SQLite
lock failure. Test restart and older-schema migrations with retained rule
provenance. Run required local Cargo/UI checks and record evidence under target.

## Encrypted client DNS and HTTPS administration

DoT and DoH are optional listeners using the same engine, generations, local
records, CNAME filtering, caches and source-IP policy. Encryption does not enable
DNSSEC validation, malware intelligence or hostname discovery by itself.

Use a certificate valid for the hostname/IP clients use, with a trust chain they
accept. Supply the leaf followed by intermediate certificates. Keep its private
key 0600, or 0640 with the dedicated service group. Files are read at startup on
the control worker; restart after a successful renewal. Relative paths resolve
against the daemon configuration directory. No automatic ACME client is included.

```toml
[api_tls]
cert_file = "/etc/rustwalld-dns/tls/fullchain.pem"
key_file = "/etc/rustwalld-dns/tls/key.pem"
hostnames = ["dns.home.arpa"]

[dot]
listen = "192.168.1.2:853"
max_connections = 64
[dot.certificate]
cert_file = "/etc/rustwalld-dns/tls/fullchain.pem"
key_file = "/etc/rustwalld-dns/tls/key.pem"

[doh]
listen = "192.168.1.2:443"
max_connections = 64
[doh.certificate]
cert_file = "/etc/rustwalld-dns/tls/fullchain.pem"
key_file = "/etc/rustwalld-dns/tls/key.pem"
hostnames = ["dns.home.arpa"]
```

Top-level `api_listen` still defaults to loopback. A LAN bind requires `api_tls`;
there is no plaintext fallback. All listener ports must be distinct. The bearer
token remains required on management routes. Restrict firewall/VPN access to the
operator network. Source-IP admission in `policy.allowed_clients` must explicitly
cover clients of LAN DNS listeners. Bindings select policy; they never grant access.
For container deployments mount the private key read-only and publish the chosen
TCP ports explicitly. Never publish a plaintext management listener to a LAN.

DoH uses `https://dns.home.arpa/dns-query`. POST carries an
`application/dns-message` body; GET carries unpadded base64url in the `dns`
parameter. HTTP/2 and HTTP/1.1 are supported. Responses use wire DNS and
`Cache-Control: no-store`. DNS failures such as SERVFAIL remain DNS responses;
invalid HTTP bodies, media types, admission and hostnames produce HTTP failures.
POST bodies are limited to 65535 bytes, GET query strings to 8192 bytes.
`X-Real-IP` and forwarding headers are ignored; a TLS proxy's TCP source identity
selects its policy, so direct encrypted ingress preserves per-client policies.

At most `min(max_inflight, 512)` secure queries share work across DoT/DoH.
Connection limits include incomplete TLS handshakes. Handshakes and frame/body
completion have five-second deadlines; connections have a ten-minute lifetime
and thirty-second idle window. DoT handles sequential frames on each connection.
HTTP upload handling and TLS handshakes stay off the dedicated DNS executor;
wire requests run on it with admission held through cancellation and response
ownership. Existing UDP/TCP service budgets remain independent.

Self-forwarding checks include all configured DNS transports on startup,
validation, staging, scheduled updates and restore. Indirect loops through a
separate resolver and wildcard-bound local interface addresses still require
correct network configuration; upstream/inflight/time limits remain bounded.

Local evidence: `cargo test -p rustwalld-dns --test secure_ingress --locked`
starts the actual binary with local certificates. It exercises trusted and
untrusted HTTPS, plaintext refusal, DoT multiple frames, a stalled handshake,
DoH GET/POST over HTTP/2, invalid media/body/hostname inputs, admission changes,
forged proxy identities and self-forwarding rejection. It uses no public DNS.
