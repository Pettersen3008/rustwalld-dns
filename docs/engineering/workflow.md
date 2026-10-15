# Agent delivery workflow

Agents maintain the plan and carry authorized work from idea to tested delivery.
Use short artifacts that help the next agent decide and verify. The maintainer
sets direction and reviews merges/releases; routine specs do not need a manual
approval round. This workflow creates no background scheduler or always-running
agent. A new session resumes from the backlog and sprint.

## One source for each fact

| Fact | Source |
| --- | --- |
| Why the product exists, exclusions | [Scope](../product/scope.md) |
| Milestone exit criteria | [Roadmap](../roadmap.md) |
| Priority, story status, acceptance criteria, dependencies | [Backlog](../planning/backlog.md) |
| Selected scope, goal, task checkboxes, capacity | [Sprint](../planning/sprints/sprint-07.md) |
| Grounded design, alternatives, budgets, test plan | docs/specs/DNS-NNN-slug.md |
| Current behavior | Architecture and operator guides |
| Durable tradeoff | docs/decisions/NNNN-slug.md |
| Delivery, defects and process improvements | docs/reviews/sprint-NN.md |
| Logs, screenshots, raw metrics and benchmark executables | ignored target/review/ |

Templates: [story](../templates/story.md), [spec](../templates/spec.md),
[decision](../templates/decision.md), [sprint](../templates/sprint.md),
[review and retrospective](../templates/review.md). Use stable DNS-NNN story IDs;
never reuse an ID. Tasks are small checkboxes under a story, not another tracker.
No duplicate status column in the sprint: backlog status is authoritative.

## Start or resume

1. Read AGENTS.md and the current sprint. Inspect git status and preserve unrelated
   edits. Read the affected code, callers, tests and living contract.
2. Select the highest-priority Ready story whose dependencies are Done. A direct
   request takes priority; add a story and scope it before substantial work.
3. If none are Ready, refine the highest-priority eligible Backlog story: define
   acceptance, inspect code, split oversized scope, draft and review its spec.
   Routine unknowns are the agent's responsibility. Mark Ready when the readiness
   criteria hold; do not fabricate missing authority or external evidence.
4. Mark In progress, write tasks and complete one vertical slice at a time. If a
   story is blocked, record the concrete dependency and continue independent work
   only within the authorized scope. Stop when all remaining work depends on input.
5. Review the actual diff and failure paths, fix confirmed defects, run acceptance,
   and update current docs, story evidence and any durable decision.
6. Mark Done only with acceptance evidence and completed review. If a required
   check fails, retain In progress/Review/Blocked as appropriate; report it.

“Run Sprint 01” covers its selected ready work, specification/refinement of that
work, safe verification, story updates and closeout. It does not authorize release,
host activation or later milestones. A task cannot run after the session ends
unless separately scheduled by the user.

## Story states and readiness

Backlog → Ready → In progress → Review → Done. Blocked records a reason and
unblocking condition; Dropped records why. Return blocked stories to Ready after
resolving their dependency. Reopened defects get a linked story or explicit reopen.

Ready means: concrete user/engineering outcome; testable acceptance and exclusions;
size S/M (L must split before starting); dependency order; affected contracts;
and a reviewed spec when behavior, security, persistence, performance or significant
UI design changes. Record the spec reviewer and date honestly. Self-review is
allowed and labeled; do not invent an independent review. Human approval is needed
only for choices outside delegated authority, including changing public/persistent
contracts or release/deployment scope. Preserve existing session authorization.

Size is relative complexity: S=1, M=3, L=5 planning points. These are not time
promises. Recalibrate after measured delivery; never use generated LOC as velocity.

## Implementation and acceptance

- Inspect → spec → implementation → adversarial review → verify → update records.
  A typo/link repair can skip a standalone spec with a reason.
- Specs stay around 1–3 pages. State ownership/interfaces, rejected alternative,
  observable error behavior, compatibility, resource/performance budget and tests.
  When the design changes, record the outcome and update the living contract.
- Mandatory local checks are in [verification](verification.md). Match checks to
  changed behavior: parser/security needs audits and fuzzing; UI needs real-daemon
  desktop/mobile/keyboard flows and visual inspection; hot paths need saved baseline
  and candidate measurements. Correctness and bounds take priority over speed.
- Review cancellation, concurrent edits, stale revisions, malformed/huge inputs,
  failure isolation, downgrade/recovery and provenance. Prefer fewer abstractions.
- Done requires acceptance criteria, relevant checks, resolved review findings,
  truthful evidence, docs/changelog as appropriate and story status. A check's
  old result is never evidence for a new diff. Required unavailable checks prevent
  Done; record the limitation and the command needed to finish.
- Contributor merge approval remains with the maintainer; local Done means a
  reviewable accepted slice, not a claim that a PR merged or software deployed.

## Sprint planning

Use one-week sprints, normally Monday–Sunday. Dates are planning windows, not
scheduled execution. Choose one outcome and a small ordered set of stories;
reserve roughly 20% for defects/rework. The first sprint has no reliable velocity.
Split work until a story can be demonstrated without shipping an unfinished mode.

The agent prepares the next sprint at closeout using unfinished dependencies,
defects, product priorities and metric trends. It may start that sprint only
within the user's execution scope. Do not silently expand “finish this story”
into the rest of the roadmap. Maintain the current-sprint link in AGENTS.md and
the index when rolling over; keep completed plans as historical records.

## Review and retrospective

At closeout use one short record for demo results, delivered/carried work,
acceptance evidence, performance/structure trends, escaped defects, spec deviations
and AI effectiveness. Record review identity (self/independent/human), rework rounds,
user interventions and unknowns. A missing measurement is unknown, never zero.

Choose at most two process improvements with an owner, linked story and a way to
measure whether they helped. Carry incomplete stories with reasons and remaining
acceptance; do not inflate velocity or mark calendar-expired stories Done.
Completed reviews and accepted ADRs are historical; correct mistakes explicitly.

## Keep planning small

One backlog, one active sprint, specs for meaningful choices, ADRs for durable
tradeoffs. No per-task design/review/evidence trilogy. Update existing contracts
instead of appending “follow-up delivered” sections. Store generated artifacts
under target/ with a concise command/result summary in the story or review.
