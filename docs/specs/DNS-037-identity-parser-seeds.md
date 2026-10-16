# DNS-037 Prepare public identity-document parser fixtures

Status: Implemented. Story: DNS-037 in the [backlog](../planning/backlog.md).
Author: Codex coordinator, 2026-10-15; coordinator self-review against file.rs/
crypto.rs 2026-10-16. Separate read-only agent review accepted 2026-10-16, AFTER
implementation (deviation from the Ready gate below; recorded, not hidden).

## Grounding and proposed boundary

fuzz_targets/identity.rs accepts raw bytes and calls auth::validate_document, then
file::decode/IdentityFile::validate. This is pure parsing and validation: no password
hashing/verification, authentication, file load/save, user provisioning or network.
The review brief identifies its missing checked-in seed corpus.

Add small explicitly public synthetic JSON fixtures and public-API replay tests,
with no existing credential files, real accounts/tokens/TOTP secrets or operational
state. A valid fixture must pass validate_document; do not assume a plausible PHC
string reaches the successful branch. Construct dummy fixed salt/output bytes in
the supported Argon2id v19 PHC shape (m=32768,t=3,p=1), without deriving a password.
Use exactly 16 decoded salt bytes and 32 output bytes.
All bytes are public test data and must never initialize a running identity store.
Ownership: new fuzz/seeds/identity/ inputs (each <=4 KiB, aggregate <=32 KiB) and
crates/app/tests/identity_seeds.rs (<=200 lines); no existing auth code changes.

Cover schema/revision, user/token names of 1..128 UTF-8 bytes without controls,
optional TOTP/replay consistency, each role, unique lowercase token IDs, lowercase
digests, expiry bounds, unknown fields and malformed JSON/PHC. Digests need not be
unique; expiry validation accepts 1..253402300799 without comparing current time.
Generate 64/65-token and 64 KiB/+1 boundaries in replay tests; keep checked-in seeds
small. Pad otherwise valid JSON with whitespace for the 65536/65537-byte cases;
use max_len=65537. TOTP uses unpadded base32 with 20..64 decoded bytes; verify encoded/decoded
boundary cases through the installed library and actual public API using dummy bytes.

No auth behavior, crypto parameters, dependencies, file permissions or fuzz-target
changes. This does not test password verification, sessions, TOTP replay storage or
operational credential security. Reject using generated live auth.json as a seed.

## Readiness and verification

Before Ready, separately review exact public fixture construction and acceptance
mapping against file.rs/crypto.rs, including the proposed ownership/corpus bounds.
One worker can own only the new corpus and
cohesive replay test; coordinator owns contracts/integration. Rebuild identity ASAN,
seed a fresh ignored corpus, bound input/RSS/runtime/output and preserve failures.
Run actual replay plus required local/security/compatibility checks. No independent
security approval or deployment claim follows. Stop at the session limit rather
than beginning an unverifiable fixture packet.

Implemented 2026-10-16: fifteen dummy seeds (5,791 bytes) and six actual-API replay
tests. Both valid seeds pass validate_document; every invalid seed asserts its exact
guard message; label 128/129, tokens 64/65, TOTP 64/65 decoded bytes, decoded
salt/output lengths and 65536/65537-byte bounds are exact. Fresh rebuilt seeded
ASAN: 56,335,827 runs/601 s, exit 0, no artifact (coverage 826 at init, 2,112
final). Required gates, audit/deny pass. Separate review accepted with doc wording
fixes and two added checks (empty name, uppercase digest), now included.
