# Downloaded lists and scheduled retrieval

## Reviewed downloaded lists

Goal: fetch named lists into reviewable policy drafts, preserve provenance and
durable history, and leave live DNS unchanged on download/compilation/persistence
failure. Done: real local HTTPS/API/browser workflows, malformed/stalled/cancelled
downloads under DNS traffic, shadow/promotion/rollback and restart, bounded
resources, security checks, quiet benchmark and packaged smoke evidence.

Observed: policies already store complete ListInput text in durable revisions.
The compiler gates assertions before ArcSwap publication. Console drafts use
revision ETags and a separate shadow/promotion review. Filtering lists already
retain source name/line and deduplication/subsumption statistics. App owns HTTP,
SQLite and the blocking compiler executor; DNS libraries must not fetch lists.

Design: optional `filter_sources` metadata in PolicyConfigSet references an
existing policy/list. Each source defines HTTPS URL, 1–8 explicit bootstrap IPs
and optional inline private CA. Successful retrieval stamps SHA-256, byte count
and Unix time in that source. Source/list contents travel together through the
existing durable revision workflow. No new SQLite tables/schema or DNS-path
code. Empty source arrays are omitted for old configurations.

App uses URL parsing, rustls and Hyper HTTP/1, already present in the locked
dependency graph. Only configured IPs are contacted, with URL-host certificate
verification and Host identity. No runtime hostname lookup, environment proxy,
redirect, cookies, compression or plaintext fallback. Explicit pins may identify
private/self-hosted HTTPS endpoints; authenticated administrators nominate those
destinations. URLs forbid user info/fragments; literal-IP URLs must match pins.
URL/CA/source counts, HTTP headers/body, deadline and concurrent fetches are
bounded. A driver guard aborts connection tasks on every exit/cancellation.

`POST /api/v1/filter-sources/preview` accepts a complete draft and source index,
requires current If-Match and one download permit. Recheck the captured revision
after the fetch, then acquire compiler admission and validate the complete
candidate off the control executor. Reject invalid/empty payloads, failed
assertions and candidates that exceed the configuration API size. Return a
candidate/report and the captured ETag. No revision allocation, DB operation or
publication occurs. A fetch does not hold mutation admission across network I/O;
policy changes remain available and invalidate a stale download. GET source
summaries reads the active snapshot. Console source editing/download occurs in
the policy workbench and follows existing shadow/promotion/revocation.

Alternative: a persisted feed registry plus timer that automatically promotes
new content. Deferred: it adds independent revision/rollback semantics and can
apply third-party policy changes without review. Manual refresh completes the
first useful slice; scheduling can later stage a candidate using this boundary.

Compatibility: existing schema-2 stores need no migration. Binaries predating
`filter_sources` cannot load revisions containing that field; rollback to such a
binary requires a compatible pre-feature backup. Manual changes to list text
invalidate its download stamp in the console; app verifies stamped content hashes
before accepting candidates. A correct wall clock is required for retrieval
timestamps, not for matching downloaded rules. Private CA material is trust data;
URL query tokens, if used, are secrets in configuration/backups.

The SHA-256 stamp checks that the saved text matches the retrieved bytes. It is
not a publisher signature. Bootstrap IPs need maintenance when a publisher moves.
At delivery of this manual-download slice, scheduled checks and automatic
promotion were excluded. Opt-in schedules and conditional retrieval were added
later; automatic live promotion remains excluded.

Use the Sources tab in the policy workbench to register a policy/list, HTTPS URL
and bootstrap IPs. Download produces a checked draft. Inspect its rule statistics
and assertion report, start shadow evaluation, and promote through the normal
revision workflow. Existing list text stays available when its source is removed.
The Filters view shows the active source and fingerprint. A failed download keeps
both the previous draft and live generation.

The preview API returns 428 for missing If-Match, 412 for stale revisions, 409
for occupied admission, 422 for invalid configuration/rules/assertions and 502
for publisher, TLS, HTTP or deadline failures. Download limits are one concurrent
fetch, 15 seconds total, 3 seconds per connection attempt, 8 MiB of body,
32 HTTP headers and a 64 KiB header buffer. There are at most 64 configured
sources, with 1–8 pinned IPs each. Candidate JSON must fit the 16 MiB policy API.

Primary API references: [Hyper HTTP/1](https://docs.rs/hyper/1.11.1/hyper/client/conn/http1/struct.Builder.html)
and [HTTP semantics](https://www.rfc-editor.org/rfc/rfc9110.html). Downloads accept
only complete 200 responses. Scheduled checks now accept validated conditional
304 replies; see [conditional retrieval](feeds.md).

## Scheduled list refreshes

Opt-in periodic list checks yield a durable shadow candidate for review. Timers
never promote live policy. This slice includes schedule editing/status/check-now,
failure/conflict isolation, candidate persistence, restart/shutdown and validation
through real DNS queries, browser workflows and performance measurements.

Observed: HTTPS preview already bounds pinned destinations, trust, HTTP input,
body size, cancellation and deadlines. Configuration embeds source/list content.
The shared mutation gate serializes assertion-gated durable publication. Shadow
is already persisted, restored and backed up. A new queue would duplicate those
revision, retention and recovery contracts.

Design: optional refresh_interval_secs on FilterSource, 300 seconds through
30 days; omitted means manual-only. One app-owned worker checks one source at
a time, sharing download admission with manual previews. A one-slot check-now
request wakes the worker; concurrent/busy requests are refused. At most 64
schedule entries and one running check are retained. No new DB tables or schema.

Unchanged bytes update runtime status without allocating a revision. Changed
bytes are compiled off the executor, checked for nonempty rules, assertions,
fingerprint integrity and 16 MiB candidate size, durably committed as shadow,
then atomically published to shadow evaluation. Captured active/shadow revision
preconditions prevent overwrite of a concurrent edit or operator shadow. Existing
shadows pause every check, including after restart. Only explicit review/promotion
changes production. Shadow evaluation uses the existing DNS mechanism and has
its usual evaluation cost; scheduling adds no code or locks to DNS workers.

Runtime status records last result, failure, next monotonic deadline and running
source. Failed checks wait the configured interval; occupied admissions retry
after 30 seconds, never in a tight loop. Entries survive unrelated generations
when source identity/interval are unchanged, preventing reload retry storms.
Restart reconstructs deadlines from active retrieval stamps; runtime failure/
unchanged status is intentionally not a durable attempt ledger. Wall-clock changes
do not move an established in-process deadline. There is no catch-up burst.

Shutdown cancels in-progress network fetches and waits for compilation/commit
already in progress before stopping SQLite. Socket/task cancellation and slot
ownership must remain bounded. Locks protect only short runtime-state operations
and never span await or network I/O. Queued requests from retired generations
are discarded, as are queued checks paused by a new operator shadow. Failure
details are bounded and omit publisher URL/credentials.

Alternative: persistent independent drafts plus automatic scheduling/attempt
ledger. Deferred: it adds another queue, schema and promotion lifecycle. Reusing
the single durable shadow is adequate for a first reviewed-refresh slice, with
the explicit tradeoff that review pauses other scheduled sources.

Compatibility: old configurations remain manual-only. Existing schema-2 stores
need no migration. Older binaries cannot read sources with refresh_interval_secs;
use a compatible pre-feature backup when downgrading.

Review found and resolved JSON amplification before compilation, queued-check
retirement on shadow review, stale status/begin snapshots, and retired-job deadline
shortening after a new download stamp. Regression checks cover these cases.
DNS matching, cache keys, upstream selection and telemetry are unchanged.

Usage: Policies → Downloaded lists → Enable scheduled refresh. Set the interval
in seconds, validate the configuration, then review and promote it. A source
without a download stamp is due immediately after activation; a current stamp
waits one interval. Changing the publisher, target or interval creates a new
schedule. Editing the source in the console clears its retrieval stamp.
Check active schedule now runs the active configuration, not unsaved draft text.
GET /api/v1/filter-refreshes reports runtime state; POST /api/v1/filter-refreshes/check
accepts {source: index} with the current If-Match tag and returns 202 on admission.
Busy/review conflicts return 409; stale tags 412, absent tags 428 and a missing or
disabled schedule 422. Both endpoints require the management token.

The entire JSON-encoded configuration must fit 16 MiB when scheduling is enabled.
A counting serializer rejects amplification/oversized file configurations before
compilation without allocating another complete JSON buffer. Download body and
transport limits remain those documented in the downloaded-list contract above. Timers use conditional validators when available, otherwise full GETs. A durable
attempt ledger, fleet jitter and automatic live promotion remain outside scope.

## Conditional downloaded-list retrieval

Goal: reduce scheduled-check transfers and control-plane work without changing
DNS policy evaluation. Complete when validator/content isolation, HTTP 304,
changed-content shadow gates, failures, console evidence, restart recovery and
performance have been verified.

Observed: downloads are pinned/authenticated HTTP/1.1 with one admission slot,
15-second deadline, bounded headers/body and no redirect/persistent connection.
Scheduled unchanged bodies already avoid revision allocation but download/hash
all bytes and clone the configuration before fetching. Manual previews are full
GETs and must remain able to recover independently of automatic checks.

Design: a bounded runtime cache per scheduled source stores a content fingerprint,
validated generation, ETag (at most 512 ASCII bytes) and/or normalized HTTP date.
No persistent format or database migration. Source identity includes target,
URL, bootstrap IPs, private trust and interval. A cache from a staged body cannot
validate the old live body; after promotion it is eligible only for matching
stored bytes/hash. Generation changes with manually edited text are checked off
executor before validators are reused. Restart deliberately performs a full GET.

ETag takes precedence over Last-Modified. Reject unsolicited 304, malformed or
contradictory 304 validators; a 304 has no body, even if Content-Length describes
the selected representation. Weak ETags compare by opaque tag. Invalid/duplicate/
oversized optional 200 validators are ignored. A 200 replaces hints; a missing
validator cannot inherit an old one. Failed checks clear hints to permit full
recovery on the next check. A completion retired by runtime synchronization
cannot install validator state;
content fingerprints also protect the race before synchronization.
HTTP remains authenticated/pinned; validators never bypass candidate assertions.

304 preserves content, retrieval stamp and revision counter; only bounded
runtime check/transfer status changes. Changed 200 content clones configuration
in blocking work, compiles/asserts and persists shadow through the existing gate.
No timer promotion. Manual preview continues unconditional, including when the
publisher sends bad conditional responses. No new DNS lock, field or call path.

Alternative: durable validators in DownloadStamp. Deferred: source/trust/content
binding and metadata-only revisions add persistence/rollback complexity. Runtime
hints save steady-state transfers while preserving offline boot/backup semantics.

Verification: pure header/date/weak-tag tests and fuzzing; local HTTPS fixtures for
ETag/date/200/304/malformed/changed/stalled cases; generation edits and dismissed
shadows; restart with offline publisher and one full re-learning GET; browser
200/304 status; quiet pipeline baseline/comparison plus timed full/conditional
transfers with byte counts. Run formatting, strict Clippy, workspace/browser
checks, audits, release manifest verification and no-network deployment smoke.

Semantics follow RFC 9110 sections 8.8, 13.1.2, 13.1.3 and 15.4.5:
https://www.rfc-editor.org/rfc/rfc9110.html

The source is an explicitly configured policy mirror, not a general-purpose HTTP
cache. The operator's schedule sets deadlines; Cache-Control/max-age/Vary do not
change DNS policy or storage. A successful 304 is the authenticated publisher's
validation of the stored representation (weak ETags permit semantic equivalence),
not a fresh download/hash proof of byte-for-byte publisher equality. Stored
provenance always describes the bytes actually retrieved and reviewed.
