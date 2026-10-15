# DNS-036 Seed bounded lease-parser review coverage

Status: Implemented. Story: DNS-036 in the [backlog](../planning/backlog.md).
Author: Codex coordinator, 2026-10-15; separate design review accepted by /root/review_sprint06, 2026-10-15.
Authority: remaining bounded M2 engineering window; offline synthetic fixtures only.

## Outcome and grounding

The independent-review brief identifies missing checked-in seeds for identity,
server_tls and lease_inventory. Close one complete corpus gap: lease_inventory
calls the existing pure parse_leases(text,100), with no filesystem/network/crypto.
The parser accepts raw DHCPv4 five-field UTF-8 lines, <=1 MiB/4096 lines; it parses
expiry and IPv4 before dropping expired records, and bounds names/MAC labels to
256 UTF-8 bytes without controls. MAC syntax is not validated; inventory is advisory,
not DNS identity/admission. No parser behavior or dependencies change.

## Design

One worker owns only new fuzz/seeds/lease_inventory/ tiny public synthetic inputs
and crates/app/tests/lease_inventory_seeds.rs. Use documentation IPv4/MAC examples,
no real lease inventories, credentials, external requests or generated private keys.
Cover expired 99/equal 100, unlimited 0 and live 101; whitespace/wildcard/256-byte labels;
field-count, overflow, IPv6, overlong/control-label and expired-invalid-address
refusal. Optional non-UTF-8 seed is target guard coverage, not parser rejection.
Keep each checked-in seed <=4 KiB; generate large boundary inputs inside the test.

Replay through the actual public parser, asserting retained address/name/expiry
values and meaningful error categories, then exact 1 MiB/1 MiB+1 and 4096/4097 line
bounds. Keep fixture tests cohesive below 200 lines; locally allow test unwrap only.
No production refactor, new parser, fuzz target changes, listener or file intake.
Identity/TLS corpora remain explicit later work with their own fixture policy.

## Acceptance and verification

Reviewed corpus/replay tests prove valid seeds actually reach successful parsing
and invalid cases exercise intended guards. Run focused tests, required fmt/
strict all-target/all-feature Clippy/workspace/Python/docs gates and current audit/
deny. Rebuild lease_inventory ASAN separately; copy seeds to a fresh ignored corpus
and run a bounded mutation smoke with max_len 1048577, RSS<=1GiB, per-input timeout 5s
and a separate whole-process deadline. Preserve failures; timeout is incomplete.
The smoke establishes local supplementary coverage, not independent review or a
security claim. No performance/UI/deployment check is needed for fixture-only work.

Accepted: ten synthetic seeds and five actual-parser regressions, separately
reviewed without production changes. Fresh rebuilt seeded ASAN completed 51,323,664
iterations in 901 seconds, exit 0, with source/seed identities unchanged. Required
and compatibility checks pass; [Sprint 09](../planning/sprints/sprint-09.md) records
acceptance and remaining gates. Optional non-UTF-8 target-guard seed was not needed.
