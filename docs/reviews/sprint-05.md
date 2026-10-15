# Sprint 05 Review and retrospective

2026-10-15. Personal context; repository planning, no Jira. Goal: make the remaining
soak/security gates executable. Source starts at `727cb87`, committed/pushed at the
user's request before this sprint. Subsequent changes are uncommitted. Review:
Codex self-review; no independent security review claim. Closed: DNS-018, DNS-010
and reserve defect DNS-019 Done; three relative points, no carryover.

## Outcomes and evidence

- DNS-018: accepted protocol covers independent clients/routed/storage path,
  controlled private upstreams, proposed workload/oracle, fixed numeric-budget
  prerequisites, fault/undo windows, 24–72-hour duration, bounded recorder and stop
  criteria. DNS-020–023 split runner, qualification, measurement and analysis.
  Representative target/rates/budgets/authority remain missing; no long run started.
- DNS-010: review brief maps real source/tests/fuzz targets to trust surfaces,
  admission/publication/auth/egress/storage boundaries and known limitations.
  Complete nonignored source snapshot, base/diff/status, file hashes/modes and
  actual check records are prepared locally. Extraction matches source and passes
  fmt/docs. DNS-024 tracks actual independent review; no reviewer/upload/contact.
- DNS-019: freshly built before reports incorrectly described 1-second histograms.
  Changed exactly two description strings to the unchanged 2-second/21,001-bin
  implementation. Both after reports match. All nine example regressions passed,
  including eight shared histogram tests for slow, clipped, merged/empty samples.
  Sampling/quantiles/helper and daemon binary remain byte-identical.
- Required fmt, strict all-target/all-feature Clippy and 458 workspace tests pass;
  documentation and whitespace checks pass. Root/fuzz audit and deny pass;
  duplicate-version/license-exception warnings remain in retained logs.

Raw before/after JSON, completed command exit records, scans, source comparisons
and verified review packet are under ignored target/review/sprint-05/. Packet
manifest identifies the exact dirty source; the base commit alone does not.
Short 100-ms/one-client local rehearsals prove report/correctness paths only;
no speed/capacity/representative performance claim. Parser/auth/dependency/UI and
native behavior are unchanged, so no new fuzz campaign/browser/VM run was claimed.
The prior VM remains off. No background service/scheduler or delegated agent.

## Quality, rework and limitations

Only two Rust metadata strings changed; no API/schema/dependency, new abstraction
or module growth. Kept the existing histogram behavior and tests; no assertions
were weakened. Planning required no separate behavior spec: the protocol/brief
are the reviewable deliverables, and the metadata correction is a tiny fixture edit.

Self-review corrected recorder cardinality: 32 lane/transport series cover seven
lanes across four transports; client counters cap at 16, with compatible artifact
ceilings. Clarified transition oracles (client send time cannot prove server-pinned
generation), collection outside storage-fault volumes, public HTTP endpoints,
privileged private egress and missing seeded targets. No unresolved source findings.
One metadata correction round; patch-context ordering failures made no partial
changes. No user intervention after scope start. Cost/iteration timing and
independent-review effectiveness remain unknown.

Actual representative 24–72-hour workload, target hardware, older-binary downgrade
and independent security disposition remain open. A prepared protocol/packet or
passing scans cannot close them.

## Retrospective and next scope

Reading real examples before planning exposed stale report metadata and the lack
of a remote long-run driver. Fresh before/after output and existing boundary tests
made the narrow correction concrete. Verifying the extracted packet catches
missing source/docs without pretending to perform an independent review.

Two actions:
1. Agent/DNS-020: validate layout/cardinality, numeric budgets, evidence caps and
   wrong-answer/cleanup sentinels before lab qualification. Success: invalid or
   incomplete runs fail explicitly without silent load reduction or unbounded output.
2. Maintainer/DNS-024: identify reviewer and exact source/method before review
   execution. Success: reviewer findings name the packet/diff and record real
   coverage/exclusions; a self-review is never presented as independent acceptance.

[Sprint 06](../planning/sprints/sprint-06.md) proposes DNS-020 with rework reserve.
It has not started. DNS-021 onward depend on real target/authority; no deployment,
long-run scheduling, release or reviewer action is inferred from this closeout.
