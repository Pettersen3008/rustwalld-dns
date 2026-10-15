# Sprint 07 Preparation review and handoff

2026-10-15. Personal context; repository planning, no Jira. User requested commit/
push and agent-assisted continuation. Sprint 06 snapshot reviewed and pushed as
`bf9043b`. New preparation remains uncommitted. DNS-025 is Done; actual DNS-021
qualification and the sprint's full goal remain open, not carried as accepted.

## Delivered preparation

Split the concrete collector prerequisite from unready lab qualification. A separate
implementation agent owned only the collector/test files in an isolated worktree;
a second read-only agent reviewed design/code. Coordinator integrated exact bytes,
owned canonical planning and independently verified actual sample-to-driver behavior.
This is engineering peer review, not DNS-024 independent security acceptance.

The 372-line one-shot Linux collector reads actual PID/start/namespace/owned-listener,
RSS/FD/thread/storage and API status/counter values. Inputs, enumeration, HTTP,
deadlines and stdout are bounded. No target mutation, remote execution, production
endpoint/dependency change or file publishing. The existing driver schema is intact.
The controller owns trusted transport, sequence, complete-success validation and
atomic private installation. [ADR 0005](../decisions/0005-soak-controller-boundary.md)
already records that ownership; no additional architectural decision was needed.

The [two-VM Docker/client proposal](../operations/soak-lab.md) names disposable
resources, separate state storage, private path, synthetic 20-QPS steady/100-QPS
burst, collection/teardown and real qualification gaps. It is not activation
authority or evidence that this represents the operator's intended network.

## Evidence and rework

- All 34 Python tests pass, including 18 collector regressions with owned IPv4/IPv6
  HTTP fixtures, PID/namespace/listener refusal, storage symlink swaps/limits,
  malformed/deep JSON, counters/framing and deadline/error behavior.
- Actual CLI collection against the same separately started appliance passes valid
  observation, wrong start ticks and another PID's listener refusal. Atomic complete
  sample handoff drives 30 correct UDP/TCP replies. Deliberately wrong answers fail;
  stopped/failed collection preserves prior evidence and fails freshness. The driver
  reconciles all attempts; target stays alive until its owner stops it cleanly.
  Sampled counter intervals are reported as observed, never forced to equal traffic
  totals; final counter coverage still needs the external lab analysis boundary.
- Required fmt, strict all-target/all-feature Clippy, 473 workspace tests, docs and
  whitespace pass. Release binary/console rebuilt before full deployment-script
  tests. Root/fuzz audit/deny pass with retained duplicate/license-exception warnings.
- Seeded bounded byte mutation exercises proc/resources/endpoint/status/metrics/TCP
  and real stdlib HTTP framing: 70000 cases complete without unexpected exceptions.
  This is robustness evidence, not coverage-guided fuzzing, sanitizer or security
  audit evidence. Raw sources, command exits, outputs and identities stay under
  ignored target/review/sprint-07/.

Review caught HTTPResponse.read accepting a short EOF despite a longer declared
body, plus ambiguous/negative lengths and unsupported transfer framing. Fixed with
single explicit Content-Length-only framing and exact completion, with regressions.
Coordinator added deep parser-error sanitization; a direct mocked RecursionError
regression isolates the handler. No assertions were weakened. Source/test modules
stay below 500 lines. No unresolved code objection. Agent cost/time unknown; no
claim that delegation improved speed or replaced maintainer/security review.

## Remaining scope and retrospective

DNS-021 remains Backlog: real representative workload/path/storage, frozen budgets
and named setup/fault/reversal authority are not established. HTTP-only/explicit-
length collection and conservative FD-change failures are declared limits, not
proof of HTTPS/password or high-churn target qualification. No new VM/system
service, router/DNS/DHCP/firewall action, long run, persistent scheduler or reviewer
contact occurred. The previous native guest remains off.

One process follow-up: before DNS-021 activation, verify collector identity and
framing with the actual deployed mode, and capture final metric coverage after
traffic drains. Success means real transport/clock/process/source identity and
complete counter denominators, rather than accepting a healthy HTTP response.
Next work is the concrete plan's readiness/activation decision; DNS-022 still
requires its own actual 24–72-hour window. Do not invent a later sprint to hide
this outstanding qualification.
