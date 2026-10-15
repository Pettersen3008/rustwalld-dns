# DNS-037 Prepare public identity-document parser fixtures

Status: Draft; not selected for implementation in the remaining window.
Story: DNS-037 in the [backlog](../planning/backlog.md).
Author: Codex coordinator, 2026-10-15; design review pending.

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
Proposed worker ownership: new fuzz/seeds/identity/ inputs (each <=4 KiB,
aggregate <=32 KiB) and crates/app/tests/identity_seeds.rs (<=200 lines).
Coordinator owns this spec and shared records; no existing auth code is worker-owned.

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
