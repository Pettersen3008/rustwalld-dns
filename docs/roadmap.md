# Delivery roadmap

Milestones use exit criteria, not predicted release dates. The working tree is a
homelab alpha; historical “all checks passed” ledgers do not establish acceptance
for the current dirty tree. [Scope](product/scope.md) defines release boundaries.

| Milestone | Outcome and exit criteria | State |
| --- | --- | --- |
| M0 — Reset | Lean contracts, shared agent instructions, story/spec/sprint/decision/review templates, recoverable cleanup and locally verified documentation tools | Complete; see Sprint 00 review |
| M1 — Trustworthy development baseline | Repeatable local Rust/UI/consumer checks; matched benchmark baseline; reviewed large-module boundaries; actionable UX audit; no false acceptance claims | Complete; Sprint 01 baseline and Sprint 02 engine/focus/copy accepted |
| M2 — Reliable appliance | Native deployment-host recovery and sandbox tests plus representative soak; failure/resource limits and compatibility documented; independent security findings triaged | DNS-008 proposed in Sprint 04; needs authorized host/lab access |
| M3 — Focused product improvement | Highest-value migration/local DNS/UI gaps delivered in complete measured slices; each selected feature meets spec, review and UX acceptance | Sprint 02 focus/copy and Sprint 03 phone/editor slices accepted; compatibility candidates remain |
| M4 — Release readiness | Target hardware evidence, security review disposition, verified supported formats, clean local package checks and explicit release authorization | Later |

Before adding features, remove duplication or structural debt that obstructs their
implementation. Preserve the reusable libraries and keep management out of DNS.
Do not copy router-project CI, kernel lab requirements or feature plans here.

The [backlog](planning/backlog.md) owns story priority/status and acceptance;
[Sprint 04](planning/sprints/sprint-04.md) proposes the next tasks and goal;
[Sprint 03 review](reviews/sprint-03.md) records the accepted slice.
At closeout, update milestones using delivered evidence and the retrospective.
