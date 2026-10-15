# Working on rustwalld-dns

A local-first DNS policy engine, reusable libraries and an optional managed
appliance. Agents own delivery from story to verified slice. Maintainers own
product direction, external releases, deployment and contributor merge approval.

## Find the right context

| Need | Source |
| --- | --- |
| Agent entry and non-negotiable rules | [AGENTS.md](../AGENTS.md) |
| Product scope and remaining release gates | [Product scope](product/scope.md) |
| Dependency direction and publication | [Architecture](architecture.md) |
| Planning, execution, review and retrospective | [Workflow](engineering/workflow.md) |
| Code quality and folder ownership | [Standards](engineering/standards.md) |
| Local acceptance commands | [Verification](engineering/verification.md) |
| Performance experiments | [Performance](engineering/performance.md) |
| UI and interaction acceptance | [Design](engineering/design.md) |
| Milestones and next work | [Roadmap](roadmap.md), [backlog](planning/backlog.md), [Sprint 08](planning/sprints/sprint-08.md) |
| Short implementation design | [Filter ownership](specs/DNS-005-filter-ownership.md), [templates](templates/story.md) |
| Durable decisions | [ADR 0004](decisions/0004-agent-workflow.md) |
| Review and learning | [Latest completed review](reviews/sprint-07.md) |
| Documentation recovery and old paths | [Cleanup map](archive.md) |

## Behavior contracts

[Filtering](architecture/filtering.md) · [Local DNS and routing](architecture/local-dns.md)
· [Policy/client controls](architecture/policy.md) · [Migration](architecture/migration.md)
· [Downloaded lists](architecture/feeds.md) · [Upstreams and caches](architecture/upstreams.md)
· [Administration and privacy](architecture/security.md) · [Offline checks](architecture/policy-checks.md)
· [API and DNS limits](architecture/api.md) · [Embedding](architecture/embedding.md)
· [Optional parallel compiler](engineering/parallel-compilation.md)

External acceptance: [representative soak protocol](engineering/soak.md) ·
[bounded remote driver](operations/soak-runner.md) ·
[disposable lab qualification](operations/soak-lab.md) ·
[independent security review scope](engineering/security-review.md).

## Operator guides

[Install, upgrade and recover](operations/install.md) · [Containers](operations/container.md)
· [Optional integrations and Unbound](operations/integrations.md) · [Release preparation](operations/releasing.md)

Living contracts describe current behavior. Specs describe an intended slice;
completed specs record deviations and point back to contracts. Sprint records
summarize acceptance and learning. Raw evidence stays under ignored `target/`.
