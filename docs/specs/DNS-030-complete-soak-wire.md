# DNS-030 Enforce complete frozen DNS oracle boundaries

Status: Implemented. Story: DNS-030 in the [backlog](../planning/backlog.md).
Author: Codex coordinator, 2026-10-15; separate reviewer reproduced the defect and accepted the design.

The driver accepts a valid reference/reply followed by unparsed trailing bytes,
because Hickory Message::from_vec reads a prefix. A local responder reproduces
wrong:false for the modified wire. This is a tool-oracle defect; no production
appliance defect or DNS-library replacement is claimed.

Use one small shared example-only complete-message helper in soak_record.rs.
Decode with Hickory Message::read(BinDecoder), then require decoder.is_empty(),
as existing resolver TLS/HTTPS transports do. Reference hex retains its 4096-byte
cap; network messages retain UDP/TCP framing and the 65535-byte bound.
Also enforce the request-advertised UDP payload bound (512-byte legacy floor);
a matching full RRset must not hide an oversized untruncated UDP response. Both paths
must reject incomplete wire encodings and unexplained suffix bytes. No run schema changes.

The helper also enforces a zero spare DNS header Z bit for this strict frozen
oracle profile, because Hickory discards it and cannot compare it to the reference.
This is a test-tool profile choice, not a requirement to change production receivers:
[RFC 6895 section 2.1](https://www.rfc-editor.org/rfc/rfc6895.html#section-2.1)
records historical spare-bit tolerance. All actual DNS parsing stays with Hickory;
the only raw check is the known header bit after a minimum-length guard. EDNS
reserved bits/options retain existing behavior; no custom DNS parser is introduced.

Root owns soak_record/probe and focused envelope regressions. Prove pre-fix false
acceptance, then reject suffix/Z in references before networking and real UDP/TCP
replies while preserving exact valid/compressed packets. An oversized non-EDNS
UDP reply must fail; the same full reference remains valid over TCP. Wrong replies stop with
preserved evidence. Run focused/default/all-feature example tests, required local
checks, audit/deny and bounded seeded parser fuzzing. No production query path,
dependency, persistent format or performance change follows.

## Outcome

Accepted with separate source and actual-evidence review; required local, security
and compatibility gates pass. [Sprint 08 review](../reviews/sprint-08.md) records
results and limitations. Current behavior is in the [driver contract](../operations/soak-runner.md),
[lab qualification](../operations/soak-lab.md) and [DNS limits](../architecture/api.md).
Raw successful/failed evidence remains under ignored target/review/sprint-08/.
