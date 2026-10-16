# DNS-038 Prepare public paired TLS parser fixtures

Status: Implemented. Story: DNS-038 in the [backlog](../planning/backlog.md).
Author: Codex coordinator, 2026-10-15; grounded against tls.rs and implemented by
Claude coordinator, 2026-10-16. Separate read-only agent review accepted with fixes
2026-10-16, AFTER implementation (deviation from the Ready gate; recorded).

## Grounding and proposed boundary

fuzz_targets/server_tls.rs expects one mode byte, certificate PEM, the first double
NUL separator, then private-key PEM. Odd mode selects HTTP ALPN, even selects DoT.
It invokes tls::from_pem: bounded PEM decoding, ring key/certificate compatibility
and rustls configuration, without filesystem access, handshakes or network.
Missing separator skips the target before parsing; it is not parser refusal.
The existing certificate-only tls_config
fixture has no matching checked-in key and cannot prove successful server setup.

Create one explicitly public, disposable matching certificate/key pair solely for
synthetic test input; use a reserved test identity and no operational credentials,
VM keys or runtime configuration. Record generation method and public-fixture
status beside the corpus documentation; no real service may use this key.
Prefer reusing an existing complete public source fixture if inspection finds one.
Do not publish an operator certificate/key pair or introduce a trust bypass.
Ownership: new fuzz/seeds/server_tls/ packed inputs (each <=8 KiB, aggregate
<=64 KiB) and crates/app/tests/server_tls_seeds.rs (<=200 lines); existing TLS
implementation, credentials and operational files stay unchanged.

Seed both mode bits, missing separator, malformed certificate/key, mismatch and
chain/bound failures. Replay the actual packed-input split and from_pem API to prove
successful and rejected branches, plus the 256 KiB certificate,16 KiB key and1–8
certificate limits. Keep large boundaries generated in tests; checked-in seeds
remain small. Assert ALPN directly through TlsAcceptor::config().alpn_protocols;
never infer handshake/trust/hostname acceptance from configuration. The largest
in-bounds packed input is 278531 bytes; max_len=278532 allows its plus-one boundary.
The existing unrelated public tls_config certificate can exercise mismatch with
the new public key without creating a second fixture key.
Malformed cases must alter the selected PEM object; arbitrary trailing text may be
ignored. Keep fixture documentation outside the packed mutation corpus.

No TLS implementation/dependency, ingress, trust, credential-file or target-format
changes. Reject a network handshake harness for this pure corpus-preparation leaf.

## Readiness and verification

Before Ready, separately review public fixture policy, exact encoded corpus shape,
valid pair acceptance, intended error categories, exact owned paths and aggregate
corpus bounds proposed above. One isolated worker owns new
seed/replay files only. Rebuild server_tls ASAN and run fresh bounded seeded
mutations with explicit input/RSS/timeout/output limits; retain every failure.
Run required local/security/compatibility checks. This remains parser preparation,
not independent security review, certificate trust validation or operational TLS
acceptance. No private material from the existing VM evidence enters the corpus.

## Public fixture provenance

The pair embedded in fuzz/seeds/server_tls/ is DELIBERATELY PUBLIC test data.
Generated 2026-10-16 with OpenSSL 3.6.4 (default PKCS#8 `PRIVATE KEY` output):

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 36500 -subj "/CN=server-tls.fixture.test/O=Rustwall public test fixture - not a secret" -addext "subjectAltName=DNS:server-tls.fixture.test" -keyout public-fixture.key -out public-fixture.crt
```

Each seed is mode byte + certificate PEM + `\0\0` + key PEM. The two corruption
seeds replace byte 10 of the first base64 line with `!`. The mismatch seed reuses
the public tls_config resolver.test certificate with this key. The key must never
configure a listener or be trusted; secret-scanner alerts on it (as on
web/e2e/fixtures/download-key.pem) are expected false positives.

## Acceptance

Ten packed seeds (10,706 bytes) and five actual-API replay tests: both mode bits
and a two-certificate chain succeed with ALPN asserted; every invalid seed asserts
its error category; empty input, 1..8 certificates and 256-KiB/16-KiB bounds are
exact. Review confirmed byte-identical regeneration and single-character corruption.
Fresh rebuilt seeded ASAN: 27,397,431 runs/601 s, exit 0, no artifact (coverage 837
at init, 1,590 final). LibFuzzer's length control reached 173,991 bytes, below
max_len; the largest-size boundaries are covered by deterministic tests, not mutation.
Required gates pass. No handshake, trust or independent security review follows.
