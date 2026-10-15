# Sprint 08 Review and remaining acceptance

2026-10-15, within the user's bounded two-hour M2 session. Personal context;
repository planning, no Jira. Scope is defensive owned-code/fixture testing.
DNS-027–031 are accepted; DNS-032 offline analysis remains in progress before
sprint closeout.

## Delivered and demonstrated

Two isolated implementation workers delivered verified HTTPS collection and large
reply coverage; one then fixed the production encoder defect found by actual
acceptance. Coordinator implemented two reproduced driver bugs, integrated exact
worker files and owned builds, VM acceptance and shared records. A separate
read-only agent reviewed designs, source, controller, actual reports, image/layer
identity and measurements. Peer review is not DNS-024 independent acceptance.

The collector retains PID/start/netns/exclusive listener, generation, framing and
whole-observation bounds. Explicit bounded CA/SAN TLS trust works against a real
password-mode appliance; wrong identity/PID and hostile environment checks fail
safely. No environment trust/key logging, credentials or plaintext downgrade.
The image still contains no collector or additional tooling.

Driver requests preserve CD and reject mixed-CD transitions. Hickory decoding must
consume every reference/reply byte; the strict tool profile rejects spare header Z
and enforces advertised UDP limits. Before/after reproductions retain the former
false acceptance. Neither bug justified changing production receive semantics.

Large-reply acceptance exposed a production defect: Hickory rolls back its encoder
cursor but leaves partial Vec bytes. Returning only the committed prefix fixes it
without another traversal/allocation/parser. Eighteen raw A/AAAA transport cases
cover complete consumption, counts, TC, caps and byte-identical fitting messages.
The original failing 511-byte response and original image remain available.

Two new restricted Debian 13/KVM guests exercised the repaired release image:

- Raw legacy UDP: complete 498-byte TC reply with 29 answers. TCP: 1058 bytes,
  all 64 expected records.
- Five seconds at 20 QPS: 100 correct logical probes, UDP80/TCP20 and two large
  lanes. Eighty UDP fallbacks explain 180 actual wire requests; bins/accounting
  reconcile. This is not a repeat of Sprint 07's entire 20-lane qualification.
- OS SIGINT followed an observed request and actual upstream reply held by a
  bounded frame proxy. One cancellation, zero replies, peer EOF, expected failed
  driver disposition and preserved artifacts; post-drain target PID unchanged.
- Per-run source/plan identities, four deployed artifacts and actual image
  config/layers match. Containers/services stopped, restart disabled, both guests
  and owned listeners absent. Original absolute VM watchdogs were not extended.

Matched 30-sample local warm-path means changed by +1.27% blocked, -1.23% cache
and -1.34% rewrite; measured fixture allocation counts/bytes are unchanged. This
is a short before/after observation, not a general no-regression, improvement,
large-reply capacity or latency SLO claim. Raw results stay under target/.

## Verification and retrospective

Required fmt, strict all-target/all-feature Clippy, 486 default workspace tests,
499 all-feature tests, 36 focused example tests and 41 Python tests pass. Root/fuzz
audit and deny pass with existing duplicate/license warnings retained. MSRV check/
tests, benchmark compilation, strict rustdoc, five library archives and three
independent consumers pass. Fresh seeded ASAN runs completed 5,020,499 engine and
6,570,124 record/wire iterations, each 181 seconds; 90,000 deterministic collector
parser mutations completed without unexpected exceptions. Short mutation/sanitizer
runs supplement regressions and do not establish parser safety or security audit. Evidence lives under ignored
target/review/sprint-08/, including unsuccessful attempts and teardown.

Two driver defects were reproduced during exploration. New complete-wire tests
then found a real escaped production bug that prefix-only parsing had hidden.
The oracle remained strict; the encoder was repaired. Initial live probe attempted
before its fixture was ready, then an expired disposable fixture interrupted
candidate installation. Both attempts were retained; the same owned VMs resumed
only within their remaining original deadline and ended off. No other VM changed.

Process experiments: require complete-consumption checks in raw-message tests
(owner DNS-031; enforced in regression and engine fuzz invariants), and explicitly
separate logical probes from wire requests when reconciling fallback (owner
DNS-028; demonstrated 100 versus 180). Track future false-oracle/encoding escapes
and unexplained accounting differences. No speed/cost/velocity claim: agent usage
and attribution are unknown. No new durable architectural choice required an ADR;
ADR 0005 already owns the controller boundary.

## Carryforward

DNS-021 still needs a representative routed path, intended hardware/storage and
observed workload. User delegated the reference-profile choice: Docker Linux VM,
independent isolated routed client and initially synthetic 20/100 QPS UDP80/TCP20.
Current actual lab remains private L2; the choice is not measured acceptance.
DNS-022 needs the actual separately authorized long interval; DNS-024 needs an
independent reviewer. No long run, scheduler, physical network change, release or
external reviewer contact occurred. DNS-032 prepares offline mechanical evidence
analysis; aggregate provenance and window-bin limitations must stay explicit.
