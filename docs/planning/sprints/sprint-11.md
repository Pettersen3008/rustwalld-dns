# Sprint 11 Close encrypted ingress pre-admission

Window: 2026-10-16 onward; dates do not schedule execution. Status: Closed.
Goal: non-admitted sources cannot consume encrypted DNS connection slots or TLS work.
Capacity: one S story plus rework reserve; agent cost unknown. Personal context.

## Selected stories

DNS-041 ([spec](../../specs/DNS-041-encrypted-preadmission.md)) follows the
DNS-040 defect found in Sprint 10 acceptance. Defects outrank elective work, and
external M2 gates are unchanged.

## Tasks

- [x] Ground in tls.rs/lib.rs/secure_dns; record the DoH contract decision in the spec.
- [x] Add the admission predicate; regression fails before (exit 101), passes after.
- [x] fmt, strict Clippy, 510 workspace tests and all-feature tests.
- [x] Separate read-only security review: ship both; two findings applied.

## Closeout

2026-10-16. Accepted DNS-041. All DNS ingress transports now refuse non-admitted
sources before spending connection slots or TLS work.

Retrospective: the review caught a test gap the coordinator missed. The listener
unit test could not detect missing wiring in lib.rs.
Improvement: every security fix includes one actual-binary assertion of its wiring.
Success: the next security story's review finds no unwired-path gap.
Next: no runnable M2 story remains. DNS-021/022/024 need external facts. Candidate
in-repo work: the optional admission-drop counter, or M3 DNS-012/013 once their
contract questions are resolved.
