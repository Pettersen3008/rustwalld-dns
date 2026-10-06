# Reviewed downloaded lists

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

Review found and corrected a revision-tag race, mapped-IP validation inconsistency
and missing source validation during offline backup verification. Compilation
returns list statistics in the assertion report instead of compiling twice.
No downloaded candidate is published by the preview handler.

Verification: formatting and strict Clippy pass; 83 Rust tests and 32 browser
checks pass. Tests exercise real local HTTPS and DNS, invalid certificates,
redirects, malformed/truncated/oversized bodies, stalled downloads, cancellation,
concurrent policy changes, SQLite failure, assertion failure and durable rollback.
Root and fuzz dependency audits, cargo-deny and npm audit pass. Download-config
fuzzing completed 768,300 cases and filter compilation completed 227,926 cases
without a failure. Logs are in `target/downloads-*.log` locally.

Quiet before/after Criterion measurements used AMD Ryzen 7 9800X3D, Linux
7.2.5-3-omarchy, rustc 1.98.1, 20 samples, one second warm-up and two seconds
measurement per scenario. These are single-thread local pipeline measurements
including parsing, policy evaluation, response serialization and telemetry drops;
all upstream lookup counts remained zero. The shared desktop was not CPU-pinned.

| Warm path | Before estimate | After estimate | Allocations / bytes |
| --- | ---: | ---: | ---: |
| Blocked decision cache | 613.41 ns | 603.97 ns | 10 / 1,151 |
| DNS response cache | 981.35 ns | 982.51 ns | 13 / 1,259 |
| Active temporary allow, DNS cache | 1,014.7 ns | 1,064.2 ns | 13 / 1,259 |
| Blocked, unmatched temporary exception | 613.09 ns | 632.28 ns | 10 / 1,151 |
| Blocked, expired temporary exception | 612.11 ns | 632.07 ns | 10 / 1,151 |

Allocation counts/bytes are unchanged. All timing differences are below 5%; this
does not establish zero overhead, wire latency percentiles or absolute throughput.
No DNS request-path code changed. The packaged smoke exercises source promotion,
backup, restart, upgrade and restore after shutting down the HTTPS publisher.

Primary API references: [Hyper HTTP/1](https://docs.rs/hyper/1.11.1/hyper/client/conn/http1/struct.Builder.html)
and [HTTP semantics](https://www.rfc-editor.org/rfc/rfc9110.html). Downloads accept
only complete 200 responses. Scheduled checks now accept validated conditional
304 replies; see [conditional retrieval](conditional-retrieval.md).
