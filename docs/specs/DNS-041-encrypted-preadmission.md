# DNS-041 Admit encrypted DNS peers before the TLS handshake

Status: Implemented. Story: DNS-041 in the [backlog](../planning/backlog.md).
Author: Claude coordinator, 2026-10-16. Separate read-only code review: see outcome.
Authority: delegated autonomous scope (2026-10-16). Public DoH behaviour changes
only for clients that are refused either way; the choice is recorded below.

## Outcome and grounding

DNS-040 closed non-admitted plain TCP peers at accept. SecureListener (tls.rs)
still took a connection slot and ran a TLS handshake (up to 5 s) for every peer.
DoT checked admission only after the handshake (secure_dns run_dot); DoH checked it per
HTTP request (403). A non-admitted peer could therefore hold handshake slots and
spend server TLS CPU, starving admitted encrypted clients.

## Design

SecureListener gains an optional `Admission` predicate (`with_admission`). It is
evaluated right after TCP accept, before a slot or handshake; a rejected peer's
socket is dropped. app/lib.rs wires one predicate, reading the active policy
snapshot's `permits` without locks or I/O, into the DoT and DoH listeners only.
The management API listener is unchanged: it is not DNS ingress and has its own
authentication. Existing per-frame (DoT) and per-request (DoH 403) checks remain,
so policy changes on already-open connections are still enforced.

Contract decision: a NEW DoH connection from a non-admitted source is closed before
TLS instead of receiving HTTP 403. Those clients are refused either way, and an HTTP
answer would require the handshake this change exists to avoid.
Rejected alternative: a separate pre-handshake slot pool. It still spends accept
and handshake work on refused sources.

## Acceptance and verification

- crates/app/tests/secure_admission.rs: with one slot, a stalled peer from 127.0.0.2
  is closed within 2 s, and an admitted 127.0.0.1 client then completes TLS in the
  free slot. Without the check it fails (exit 101).
- secure_ingress (actual binary): DoH 403 on the reused connection after a policy
  change still passes. A fresh DoH request fails and a fresh DoT peer is closed, while
  the management API still answers 200. Without the lib.rs wiring this fails (exit 101).
- fmt, strict Clippy, 510 workspace tests and all-feature tests pass.
Performance: one ArcSwap load and CIDR scan per accepted connection. This is not
on the per-query hot path, and no benchmark is needed.

## Decisions and outcome

Separate read-only security review (2026-10-16) said to ship DNS-040 and DNS-041.
It confirmed IPv4-mapped canonicalization, lock-free accept checks, that the
management API is unfiltered and that the accept loop does not spin. Its two findings
were applied: end-to-end wiring assertions, and an explicit pooled-connection comment
on the 403 check. An optional admission-drop counter remains a possible follow-up.
