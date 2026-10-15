# DNS-031 Return only committed Hickory wire bytes

Status: Implemented. Story: DNS-031 in the [backlog](../planning/backlog.md).
Author: Codex coordinator, 2026-10-15; separate design review accepted by /root/review_sprint06.

## Reproduced outcome and grounding

DNS-028's real two-VM large-reply probe fails complete decoding against the current
release appliance. The captured legacy UDP reply is 511 bytes with TC and 29 answers,
but bytes remain after the declared message. Under a 512-byte encoder cap, Hickory
rolls its cursor back when a record cannot finish; its Vec retains partial bytes.
`engine/wire.rs::encode` returns the whole Vec rather than the committed cursor.
Earlier Message::from_vec tests ignored that suffix. This is a confirmed production
wire correctness defect, not evidence to relax the new tool oracle.

## Design

Keep Hickory serialization and existing transport limits. After successful emit,
return only the byte prefix ending at BinEncoder::offset(). Use a lexical scope
for the encoder borrow and Vec::truncate, avoiding a new parser, record-copying
fallback or extra traversal on the query path. No configuration, generation, cache,
policy or public/persistent API changes. If emit fails, retain existing None error.
The fixture's bounded encoder should also use its committed cursor before decoding.

One isolated worker owns crates/dns-core/src/engine/wire.rs and meaningful raw-wire
regressions there or in existing protocol tests; fixture change is coordinated only
after its separate pending handoff. Root owns packaging/release/runtime acceptance.

## Acceptance and verification

First demonstrate a failing raw regression with >=64 A records or equivalent data.
For legacy/EDNS UDP caps and TCP, parse with Hickory BinDecoder and require complete
consumption, correct counts/TC and bounded size. TCP/full-fitting UDP retain all
records. Include varying sizes/record types if needed to expose partial writes. Existing engine_prepare fuzzing
adds a 32-address rewrite plus legacy/EDNS seeds and asserts complete output
consumption; the tool fuzz target also exercises raw complete-message decoding.
Verify actual repaired release/container across the independent VM path, separately
observing <=512+TC and full 64-record TCP plus driver fallback. Retain the old failed
packet/report and image identity; never overwrite it with passing evidence.

Run DNS-core/protocol tests, required fmt/Clippy/workspace/docs, relevant security
scans/fuzz and a matched relevant local hot-path measurement before/after. This is
a correctness fix, not a throughput claim. Review the actual small production diff
and tests with a separate agent; update the behavior contract and changelog.

## Outcome

Accepted with separate source and actual-evidence review; required local, security
and compatibility gates pass. [Sprint 08 review](../reviews/sprint-08.md) records
results and limitations. Current behavior is in the [driver contract](../operations/soak-runner.md),
[lab qualification](../operations/soak-lab.md) and [DNS limits](../architecture/api.md).
Raw successful/failed evidence remains under ignored target/review/sprint-08/.
