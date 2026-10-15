# DNS-029 Preserve the frozen CD request envelope

Status: Implemented. Story: DNS-029 in the [backlog](../planning/backlog.md).
Author: Codex coordinator, 2026-10-15; separate reviewer reproduced the defect and accepted the design.

The remote driver accepts a response reference with checking_disabled=true, but
`soak_probe::probe` constructs a fresh query and copies only question/RD/EDNS.
A correctly echoing local responder receives CD=false and the driver rejects its
correct response against the frozen CD=true reference. Reproducer is retained
under ignored target/review/m2-adversarial/; no production appliance defect is claimed.

Copy the reference's CD bit into the fresh request. A lane has one immutable
request shape, so require all its transition references to agree on CD, just as
they already agree on the question. Keep RD mandatory and never copy response
QR/AA/RA/AD/rcode/answers into requests. Preserve the run schema and fresh IDs,
names, whole-exchange timeout and UDP-to-TCP fallback behavior.

Root owns soak_probe.rs, soak_record.rs and driver regression tests. Add a real
local responder regression that observes CD=true and CD=false for UDP/TCP and
fallback; correctly echoed replies pass, wrong CD fails. Mixed-CD lane references
must fail validation before sockets/output. Existing records with uniform CD=false
remain unchanged. Required example/workspace/fmt/Clippy/docs checks and focused
malformed-record smoke complete acceptance; no query-path performance change.

Rejected: reject every CD=true record. CD is supported by the engine and accepted
by the existing record contract; preserving the requested flag fixes the tool.

## Outcome

Accepted with separate source and actual-evidence review; required local, security
and compatibility gates pass. [Sprint 08 review](../reviews/sprint-08.md) records
results and limitations. Current behavior is in the [driver contract](../operations/soak-runner.md),
[lab qualification](../operations/soak-lab.md) and [DNS limits](../architecture/api.md).
Raw successful/failed evidence remains under ignored target/review/sprint-08/.
