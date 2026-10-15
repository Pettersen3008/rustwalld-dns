# DNS-038 Prepare public paired TLS parser fixtures

Status: Draft; not selected for implementation in the remaining window.
Story: DNS-038 in the [backlog](../planning/backlog.md).
Author: Codex coordinator, 2026-10-15; design review pending.

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
Proposed worker ownership: new fuzz/seeds/server_tls/ packed inputs (each <=8 KiB,
aggregate <=64 KiB) and crates/app/tests/server_tls_seeds.rs (<=200 lines).
Coordinator owns fixture provenance in this spec and shared records; existing TLS
implementation, credentials and operational files are outside worker ownership.

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
