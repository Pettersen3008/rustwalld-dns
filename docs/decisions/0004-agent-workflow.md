# ADR 0004 Agent ownership of sprint delivery

Status: accepted for the documentation/workflow reset, 2026-10-15.
Authority: maintainer request in this session for an agentic sprint/story/spec/
acceptance/decision/retrospective setup and removal of documentation bloat.

## Context

The previous flat docs mixed current contracts with dated evidence and repeated
completion ledgers. The project needs agents to make sound routine choices and
complete authorized work while preserving DNS correctness, latency, structure and UI.
The router project's workflow is a useful reference; its hosted CI and per-spec
human gates do not match this repository's local verification/autonomy contract.

## Decision

Use one ranked backlog, one active weekly sprint, short grounded specs, current
behavior contracts, immutable ADRs and one review/retrospective per sprint. Agents
own refinement, task breakdown, implementation, adversarial review, local checks,
documentation and closeout within the user's scope. Self-review is permitted and
labeled. Independent/human review is never fabricated. Contributor merge approval
remains mandatory per CONTRIBUTING.md.

Routine reversible design choices do not wait for human approval. Missing authority
for product scope, breaking public/persistent contracts, publishing or host/network
activation still needs a concrete maintainer decision. Preserve earlier explicit
authorizations. No hosted CI/CD, scheduler or new always-running agent is introduced.
Raw evidence belongs in ignored target/; preserve uncommitted docs before cleanup.

## Consequences

Agents can deliver complete slices without a manual gate at every task. Honest
acceptance and scoped execution matter more: unavailable required checks prevent
Done. The source remains authoritative and metrics do not substitute for behavior.
There is no claim of unattended execution after a session ends. Revisit the process
using observed rework/defects and at most two retrospective actions per sprint.

Rejected: copying the router backlog/CI; requiring approval for every spec; replacing
short contracts with generated per-task evidence documents. These add ceremony or
violate this repo's existing boundaries.
