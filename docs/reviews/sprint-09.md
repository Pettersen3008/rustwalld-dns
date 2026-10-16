# Sprint 09 Review and remaining acceptance

2026-10-15 (bounded two-hour session) and 2026-10-16 (resumed session). Personal
context; repository planning, no Jira. Scope: defensive owned-code parser fixtures.
Review identity: coordinator self-review plus separate read-only agent reviews per
story. Agent review is not DNS-024 independent security acceptance.

## Outcomes and evidence

Delivered DNS-036, DNS-037 and DNS-038: every parser-corpus gap named by the
[security review brief](../engineering/security-review.md) now has checked-in
public seeds and replay tests through the actual public API. No production code,
dependency, fuzz-target or runtime behavior changed.

| Story | Corpus | Replay tests | Fresh seeded ASAN (local) |
| --- | --- | --- | --- |
| DNS-036 lease_inventory | 10 synthetic DHCPv4 | 5 field/error/1-MiB/4096-line | 51,323,664 runs/901 s, exit 0 |
| DNS-037 identity | 15 dummy JSON, 5.8 KiB | 6 error-category and exact label/token/TOTP/PHC/64-KiB | 56,335,827 runs/601 s, exit 0 |
| DNS-038 server_tls | 10 packed, public P-256 pair | 5 ALPN/error/1..8 chain/256-KiB/16-KiB | 27,397,431 runs/601 s, exit 0 |

Final gates on 531092d: fmt, strict all-target/all-feature Clippy, 508 workspace
tests, docs (93 files, 0 broken links) and root/fuzz audit/deny pass. MSRV, rustdoc
and benchmark compilation were not rerun for the test-only DNS-037/038 change.
No crash artifacts. For server_tls, LibFuzzer's length control reached 173,991
bytes, so the largest boundaries rely on deterministic tests, not mutation.
Raw evidence: target/review/sprint-09/ (dns-037/, dns-038/ and earlier DNS-036).

Carried: DNS-021 preparation tasks. Actual target hardware/storage, a named routed
path and an observed workload basis do not exist in the repository, so qualification
cannot become Ready. DNS-022/023 depend on it; DNS-024 needs an identified reviewer.

## Quality and AI effectiveness

Three seed sets and 16 replay tests added; largest test file 153 lines. Separate
reviews found no fixture or branch-targeting defects. They did find six doc/claim
issues: a premature "review recorded" status, stale "no seed directory" contracts,
an understated coverage figure, non-reproducible provenance, an over-strong
"each guard" claim and missing ordering disclosure. All were fixed, along with three
added checks (empty name, uppercase digest, empty certificate). Rework: one round
per story. Escaped defects: none known. Agent cost and velocity remain unknown.

Spec deviation: DNS-037/038 required a separate review before Ready; in this
session both reviews ran after implementation, because multi-agent authorization
arrived mid-session. It is recorded in both specs.

## Retrospective and planning

Helped: grounding specs in actual source beforehand made both slices first-pass
green; the experiment from the previous session (prove a valid input reaches the
real API before mutation) held for both new corpora.
Rework cause: docs edited in parallel with a running review went stale quickly.

Improvement (owner: coordinator; next fixture or lab story): run the separate review
against the spec before implementation and update shared contracts in one final
reconciliation pass. Success: zero stale-contract findings in the next review.

Next scope proposal: no runnable M2 story remains without external input. Options:
(a) a bounded synthetic routed-mechanics slice on disposable VMs. It is permitted by
the [DNS-021 spec](../specs/DNS-021-representative-lab.md), but cannot close DNS-021;
(b) M3 DNS-012 source-compatibility priorities. Supplying the target hardware,
routed path, workload and reviewer facts unblocks DNS-021 and DNS-024 directly.
