# DNS-027 Verify HTTPS in the target-local collector

Status: Implemented. Story: DNS-027 in the [backlog](../planning/backlog.md).
Author: Codex coordinator, 2026-10-15; separate design review: /root/review_sprint06, 2026-10-15.
Authority: user's two-hour M2 engineering goal and existing disposable-VM scope.

## Outcome and grounding

Production API defaults to HTTPS; `scripts/soak-collect.py` currently accepts only
plain numeric loopback HTTP, preventing that deployment mode from qualification.
App TLS supports HTTP/1.1 and public status/metrics, including password mode.
Keep collection read-only and preserve its schema, PID/start/netns/exclusive socket,
generation, explicit Content-Length, size and whole-observation deadline checks.

## Design

Add optional CLI `--tls-ca-file ABSOLUTE_PEM --tls-server-name IDENTITY`, both
required for HTTPS and rejected for HTTP. URL host remains explicit numeric loopback
with a port; the TLS identity never performs DNS resolution. Accept a bounded
ASCII DNS identity or numeric IP SAN, without wildcard/URL/control characters.
Read only the explicitly named CA through existing no-follow directory/file
helpers, at most 64 KiB, inside the watchdog. No system/environment trust fallback.

Use a directly constructed `ssl.SSLContext(PROTOCOL_TLS_CLIENT)`, required chain
and SAN-only identity verification (`hostname_checks_common_name=False`), TLS>=1.2 and ALPN http/1.1. Do not use
`create_default_context`: installed Python honors SSLKEYLOGFILE there, violating
read-only collection. No environment key logging, insecure mode, redirects, proxy,
plaintext downgrade or credential input. Connect directly to the numeric address,
then wrap with the explicit TLS identity; close on any failure. Reuse strict HTTP
framing over TLS. Socket timeouts and the external controller deadline still apply.
Collector and focused tests are worker-owned; root owns contracts and integration.
Keep source modules below 500 lines or split only at a cohesive boundary.

Rejected: disable certificate verification or resolve the certificate hostname.
Both weaken identity or bypass numeric-loopback/socket ownership requirements.
No production DNS/API/schema/dependency or UI change is needed.

## Acceptance and verification

Trusted DNS and IP SAN certificates collect; wrong CA/name, CN-only identity, missing/mixed options,
invalid/oversized/symlink CA, plaintext peers and stalled handshakes fail without
stdout. Reject invalid framing over TLS. Hostile SSLKEYLOGFILE/proxy/trust
environment creates no files or alternate connection. Existing HTTP regressions
remain. Test real TLS handshakes, not only mocks; confirm collection and atomic
handoff against an actual TLS appliance. Use controlled local fixtures only.
Separate code review, Python tests, required Rust/docs checks, audit/deny and
focused malformed-input mutation checks complete acceptance. HTTPS proves server
identity, not per-query provenance or representative-network acceptance.

## Outcome

Accepted with separate source and actual-evidence review; required local, security
and compatibility gates pass. [Sprint 08 review](../reviews/sprint-08.md) records
results and limitations. Current behavior is in the [driver contract](../operations/soak-runner.md),
[lab qualification](../operations/soak-lab.md) and [DNS limits](../architecture/api.md).
Raw successful/failed evidence remains under ignored target/review/sprint-08/.
