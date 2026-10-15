# DNS-028 Qualify large replies and live CLI cancellation

Status: Implemented. Story: DNS-028 in the [backlog](../planning/backlog.md).
Author: Codex coordinator, 2026-10-15; separate design review: /root/review_sprint06, 2026-10-15.
Authority: user's bounded two-hour M2 goal; no long soak or physical-network action.

## Outcome and grounding

`wire_compare` truncation currently affects upstream UDP and recovers to one small
A record. It does not prove downstream UDP truncation/client TCP fallback. The
latest VM SIGINT arrived with no pending exchanges. Existing driver unit cancellation
uses a token and a fixed delay. Close these acceptance gaps without changing the
production DNS path or the frozen run schema.

## Design

Extend existing Hickory fixture/oracle with `large.bench.test`, exactly 64 distinct
192.0.2.x A records, complete encoded size >512 and <1232 bytes. Export a complete
untruncated reference. Honor legacy UDP's 512-byte bound and return the complete
RRset over TCP. Upstream fresh requests advertise 1232, allowing the actual appliance
to receive full data and truncate its separate non-EDNS client's UDP response.
Validate exact address set, owner, TTL bounds and no extra records. Keep existing
upstream-truncation fixture semantics and private-only listener limits intact.
A narrow `probe-large --endpoint PRIVATE_IPV4:PORT --bind PRIVATE_IPV4` CLI
uses the same Hickory query/oracle to report raw legacy UDP length/TC and full
framed TCP 64-record validation across the actual lab path. Both exchanges have <=2s
deadlines and bounded buffers; invalid/public/wildcard bind/endpoint fails before
sockets. This avoids writing a second DNS parser in the runtime controller.
One worker owns wire_compare and its fixture module; root owns driver tests and
runtime acceptance orchestration, avoiding concurrent test-file edits.

Root synchronizes the existing live-cancellation test on observed admitted work.
For actual CLI acceptance, an owned stalled TCP fixture must observe a complete
request before SIGINT; require positive cancellation count, reconciled evidence,
peer EOF and bounded child exit. This generic transport fixture does not parse DNS;
Hickory generates/validates DNS packets. Keep all sockets/queues/output/deadlines
bounded and retain failure artifacts. No service or persistent schema changes.

Rejected: inflate the existing small truncation fixture or infer downstream
fallback from upstream retry counters. Separate named lanes keep the two behaviors
observable and preserve existing users.

## Acceptance and verification

Unit tests assert encoded size, full 64-record oracle, legacy UDP TC/bound and rejection of
missing/extra/corrupt data. Real appliance acceptance separately proves raw UDP
<=512+TC, complete TCP response and successful driver fallback. CLI SIGINT must
occur during an observed live exchange; target survives and owned sockets close.
Run focused example tests, required fmt/Clippy/workspace/docs gates and relevant
security/malformed-input checks. No throughput or representative-path claim follows.

## Outcome

Actual coverage found the separate production DNS-031 encoder defect; that reviewed
fix was required before acceptance, rather than weakening the complete-wire oracle.

Accepted with separate source and actual-evidence review; required local, security
and compatibility gates pass. [Sprint 08 review](../reviews/sprint-08.md) records
results and limitations. Current behavior is in the [driver contract](../operations/soak-runner.md),
[lab qualification](../operations/soak-lab.md) and [DNS limits](../architecture/api.md).
Raw successful/failed evidence remains under ignored target/review/sprint-08/.
