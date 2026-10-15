# DNS-035 Keep failed phase-entry evidence internally consistent

Status: Implemented. Story: DNS-035 in the [backlog](../planning/backlog.md).
Author: Codex coordinator, 2026-10-15; separate design review accepted by /root/review_sprint06, 2026-10-15.
Authority: bounded M2 defensive reliability work; owned deterministic fixtures.

## Outcome and grounding

After a phase flushes with outstanding work, offer_phase validates the next
phase's first sample before begin_phase. drive already set last_phase to the new
phase. If that sample fails, finish flushes old work/cancellations under the new
phase label but the old planned offer interval. Native deterministic 2-QPS/2-second
deadline fixtures reproduce both cancellation and late-completion variants;
accounting reconciles but metadata contradicts run.json. No production DNS defect
or successful qualification is claimed. Evidence: ignored
target/review/sprint-08/phase-sample-repro-02/; an earlier less realistic fixture
is retained separately and is not operational evidence.

## Design

Move begin_phase before the fallible entry sample in offer_phase. Compute the same
absolute planned interval first; publish that phase metadata together before any
failure can reach finish. No requests occur before sampling; dispatch, deadlines,
query/oracle origin, sample validation and cancellation behavior stay unchanged.
No schema change, new state or duplicated recorder phase field is needed.
A failed entry can retain the last known generation from the previous phase,
with zero new window resource samples; it does not prove the rejected generation
was accepted. The offline verifier must preserve that valid failed-run distinction.

One isolated worker owns remote_soak.rs ordering and a cohesive deterministic
phase-failure regression with minimal include in soak_tests.rs. Coordinator owns
integration/contracts/checks. Test cancellation and late completion from the prior
origin after a rejected next-phase sample. Use an empty JoinSet and deterministic
recorder/pending state to ensure no sockets/dispatch; no timing hook or live fault.

Rejected: relabel final work as the previous phase or fabricate a passing sample.
The failure occurred entering the new phase, and completed_phase_counts already
preserves old outcome origins. Updating metadata before fallible validation keeps
those facts distinct without hiding failure or changing resource evidence.

## Acceptance and verification

Before the fix, reproduce contradictory new phase/old interval. After it, assert
new phase and correct [1000,2000] planned interval, no new sent work, preserved old
origin or positive cancellation, reconciled totals and explicit failed disposition.
Run both native fixtures through the offline verifier: consistent failed exit 2,
never pass. Keep wrong-generation failure and last known observation unchanged.
Focused example tests plus fmt, strict Clippy, workspace/Python/docs and relevant
MSRV compatibility complete acceptance. Parser code/dependencies are unchanged
from DNS-034; its refreshed audit/deny/soak_record ASAN remains separate evidence.
Separate review before Done; no query-path performance or UI impact.

## Outcome

Accepted after separate source/evidence review and required local, compatibility
and security checks. [Sprint 08 review](../reviews/sprint-08.md) records results,
review corrections and limits; current behavior is in the
[driver contract](../operations/soak-runner.md). Raw successful/failed fixtures and
identities stay under ignored target/review/sprint-08/.
