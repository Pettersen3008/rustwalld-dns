# Delivery roadmap

Milestones use exit criteria, not predicted release dates. The working tree is a
homelab alpha; historical “all checks passed” ledgers do not establish acceptance
for the current dirty tree. [Scope](product/scope.md) defines release boundaries.

| Milestone | Outcome and exit criteria | State |
| --- | --- | --- |
| M0 — Reset | Lean contracts, shared agent instructions, story/spec/sprint/decision/review templates, recoverable cleanup and locally verified documentation tools | Complete; see Sprint 00 review |
| M1 — Trustworthy development baseline | Repeatable local Rust/UI/consumer checks; matched benchmark baseline; reviewed large-module boundaries; actionable UX audit; no false acceptance claims | Complete; Sprint 01 baseline and Sprint 02 engine/focus/copy accepted |
| M2 — Reliable appliance | Native deployment-host recovery and sandbox tests plus representative soak; failure/resource limits and compatibility documented; independent security findings triaged | Native Debian 13/KVM accepted; isolated Docker VM mechanics/recovery accepted; representative qualification/run and independent review remain open |
| M3 — Focused product improvement | Highest-value migration/local DNS/UI gaps delivered in complete measured slices; each selected feature meets spec, review and UX acceptance | Sprint 02 focus/copy and Sprint 03 phone/editor slices accepted; compatibility candidates remain |
| M4 — Release readiness | Target hardware evidence, security review disposition, verified supported formats, clean local package checks and explicit release authorization | Later |

Before adding features, remove duplication or structural debt that obstructs their
implementation. Preserve the reusable libraries and keep management out of DNS.
Do not copy router-project CI, kernel lab requirements or feature plans here.

The [backlog](planning/backlog.md) owns story priority/status and acceptance;
[Sprint 08](planning/sprints/sprint-08.md) repairs truncated wire output, strengthens
secure collection and qualifies large-reply/live-cancellation coverage. Its
[review](reviews/sprint-08.md) retains the remaining representative qualification;
offline evidence reconciliation is the current executable prerequisite.
At closeout, update milestones using delivered evidence and the retrospective.
