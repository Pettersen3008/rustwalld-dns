# DNS-034 Open native driver inputs without a leaf replacement gap

Status: Implemented. Story: DNS-034 in the [backlog](../planning/backlog.md).
Author: Codex coordinator, 2026-10-15; separate design review accepted by /root/review_sprint06, 2026-10-15.
Authority: user's bounded M2 engineering/security work, owned local fixtures only.

## Outcome and grounding

DNS-033 inspected soak_record::bounded_file: symlink_metadata then File::open
checks the path twice, so replacing its leaf can follow a symlink or wait for a
FIFO writer before descriptor validation. No exploit or operational failure was
demonstrated. Prepared::load and recurring Sample::read share this helper.
Keep its existing regular-file/byte-limit contract and legitimate atomic sample
replacement; no production DNS/runtime, persistent schema or API change.

## Design

Use the safe existing locked rustix 1.1.5 fs interface to open with RDONLY,
NOFOLLOW, NONBLOCK and CLOEXEC; convert OwnedFd to std File, validate descriptor
metadata.is_file(), then retain the cap+1 bounded read. No unsafe or numeric ABI
constants. Reject missing files, directories, leaf symlinks, FIFOs and other
special descriptors without reading their contents. A valid atomic replacement
may yield either complete regular-file snapshot; do not enforce pathname inode
identity or reread the pathname after open. Existing JSON identity, sequence,
freshness and generation checks remain authoritative.

This deliberately retains the trusted local parent-directory contract: final
NOFOLLOW does not reject symlink ancestors. Document that local filesystem/private
parents and an external process watchdog are prerequisites. Synchronous filesystem
operations cannot promise a hard wall-clock bound, even with NONBLOCK (regular
files/NFS/FUSE). No untrusted path or network filesystem acceptance is added.

Coordinator owns app unix dev-dependency, fuzz unix dependency and both lockfiles;
add only an explicit edge to existing rustix with fs feature, no version upgrades.
Fuzz source-includes the whole helper, so it needs that direct edge despite never
calling the filesystem. One isolated worker owns only bounded_file changes in
soak_record.rs plus cohesive example regressions; no concurrent shared-file edits.
The app's shipped dependency surface and query path remain unchanged.

Rejected: canonicalize/re-stat (another race), literal platform flags (opaque ABI),
and openat2/per-component ancestor traversal (new path/kernel policy beyond the
existing trusted-parent boundary). Revisit ancestor policy only with its own
compatibility decision; do not imply this leaf fix covers it.

## Acceptance and verification

Test empty/exact-cap/over-cap regular files; missing/directory/leaf-symlink refusal;
writerless FIFO refusal inside a subprocess watchdog; normal atomic replacement
and existing sample identity/freshness regressions. Use owned temporary files only,
no probabilistic exploit race or timing hooks in production/example code. Preserve
local regressions for all prior CD/wire fixes. Test the actual CLI validate-only
path and a controlled sample handoff, including bounded FIFO/symlink refusal.

Run fmt, strict all-target/all-feature Clippy, workspace/example/Python/docs checks,
MSRV compatibility, root/fuzz audit/deny and bounded seeded soak_record ASAN. Verify
only intended lockfile edge changes. No query-path benchmark or UI check is needed:
only the operator example's file admission changes. Separate review before Done.

## Outcome

Accepted after separate source/evidence review and required local, compatibility
and security checks. [Sprint 08 review](../reviews/sprint-08.md) records results,
review corrections and limits; current behavior is in the
[driver contract](../operations/soak-runner.md). Raw successful/failed fixtures and
identities stay under ignored target/review/sprint-08/.
