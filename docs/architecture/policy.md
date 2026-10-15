# Policy controls and client identity

These controls use the same checked generation/publication lifecycle. Admission, explicit source-IP binding, advisory metadata and filtering tags have distinct meanings. Service catalogs remain versioned; schedules and exceptions require a correct host clock.

## Temporary exact-domain allows

Goal: temporarily allow one exact domain for clients using a chosen effective
policy, without waiting for management/SQLite to remove the exception at expiry.
Done means real UDP/TCP queries, warm caches, delayed upstream work, shadow,
restart/rollback, diagnostics and console editing all honor the same deadline.

An exception has a name, domain and absolute Unix-second `expires_at`. Domains
use the existing IDNA normalization. Bounds: 1,024 exceptions per policy, 4,096
per generation, unique names and normalized domains within a policy, and at most
seven days remaining when first accepted. Intake (`PUT /config`, `POST /shadow`,
`POST /policy/test`, rollback and `--check-config`) applies the seven-day limit
to exceptions that are not already present, identically, in the live active or
shadow revision (`PolicyConfigSet::validate_new_exceptions`). Compilation does
not: restoring a stored revision clamps the monotonic deadline to seven days, so
a wall clock that is behind at boot (an RTC-less board before NTP) cannot keep
DNS from starting. The absolute expiry still ends the allowance once the clock
is corrected. Expired entries remain valid historical configuration but are
never reactivated by compilation with a correct clock.

policy compiles an optional exact-name map into each immutable policy. Entries
retain their configuration index for provenance, absolute wall-clock expiry and
a conservative monotonic deadline. The normal path checks a single optional map
before the decision cache. No timer, plugin, mutable expiry table, DB or filesystem
is needed. An empty policy adds only a branch. A matching entry consults the
system clock; an expired monotonic deadline short-circuits that clock read. A fixed
one-way atomic expiry flag prevents an observed expiry from reviving after a
forward/backward clock jump. Rule content and deadlines remain immutable; there
is no global expiry lock or dynamically grown runtime structure.

Local rewrites keep precedence. Temporary decisions never enter the decision
cache. Normal upstream cache/single-flight keys stay generation/profile isolated;
only the private response copy sent to this client gets its record TTLs capped.
After an upstream wait, recheck the exception. If expired, apply the permanent
filter decision; synthesize a block if required. Snapshot retention does not
extend deadlines. Shadow uses the same exception evaluation without enforcement.

Alternative: schedule an automatic control-plane revision at expiry. Rejected as
the correctness mechanism: SQLite locks, executor stalls or failed promotion could
leave the exception active. Control-plane cleanup may be added independently.

Live wall-clock rollback cannot extend the monotonic deadline; a forward jump
expires an allowance early. Restarts/recompilation reconstruct remaining time
from absolute expiry and require a trustworthy system clock for exact timing; a
lagging clock is bounded by the seven-day monotonic clamp. No DNS appliance
can withdraw answers already used by applications or terminate their connections.
Sub-second remaining allowances emit TTL zero; clients must honor DNS TTLs.

Required assertions intentionally test permanent policy, excluding temporary
allows. Current-policy explanations and query telemetry identify actual temporary
decisions. Removing an exception uses normal validation/shadow/promotion and a
fresh generation. Rollback never resets its `expires_at`.

app retains fixed-size exception indices in the bounded telemetry queue. SQLite
schema 2 adds a nullable history column in a transaction, preserving schema-1
queries/revisions. Read-only maintenance accepts schema-1 snapshots; restored
stores migrate at daemon startup. New-schema stores are not downgrade compatible.
Existing configuration without exceptions remains readable and serializes as
before. Compilation/assertions/durable revision gates stay ahead of publication.

Verification: deterministic clock/normalization/limits tests; local UDP/TCP cache
and delayed/coalesced expiry checks; permanent-policy TTL isolation; expiry with
blocked management and full telemetry; strict assertion rejection; shadow and
fresh-generation removal/rollback; schema-1 upgrade/backup/restart tests; real
browser editing/explanations; targeted fuzzing and before/after Criterion with
allocator measurements. Build/test/fuzz/container jobs remain idle during timing.

### Operation

Use **Policies → Temporary exceptions** to select a policy, add a named exact
domain and choose 15 minutes, one hour, eight hours or 24 hours. The absolute
expiry is captured when added to the draft; validation/shadow time consumes that
allowance. Follow the existing validation, shadow and reviewed promotion workflow.
Removing an entry changes only the draft until promotion. Expired entries are
retained for inspection; cleanup does not control enforcement.

Policy configuration adds optional `temporary_exceptions`, an array of objects
with `name`, `domain` and numeric Unix-second `expires_at`. The API accepts the
same complete policy configuration; no separate unreviewed mutation route exists.
`GET /api/v1/temporary-exceptions` requires the management token and returns the
active generation plus each configured entry's policy, zero-based index, name,
normalized/configured domain, expiry and live active state. It reads the compiled
snapshot without SQLite. Current explanations include the active exception.
History/shadow events carry a nullable zero-based index scoped to policy and
generation; look up that revision for the original name/domain. Old events have
null provenance. Required reports explicitly state `basis: "permanent_policy"`.

## Client and network metadata

Goal: annotate existing IP/subnet policy bindings, make them searchable and
reviewable in the console, and retain those annotations through revisions,
shadow, promotion, backup, recovery and rollback. DNS admission, longest-prefix
selection and cache semantics must stay unchanged.

Observed: Binding owns a name, IP network and policy. Policy compilation builds
separate prefix-indexed IPv4/IPv6 maps; data-plane Selection borrows the winning
policy/name/network. GET clients and explanations read the current immutable
snapshot. Revisions already persist complete configuration. The current clients
table and network editor render every binding without pagination.

Design: optional BindingMetadata on each Binding with group, owner, VLAN label,
tags and note. Limits: group/owner 128 bytes, VLAN 1–4094, at most 16 unique ASCII
tags of 32 bytes each, note 1024 bytes, and at most 8 MiB combined metadata per
generation. Reject control characters, blank/edge-whitespace labels, empty
metadata and unknown fields. Metadata is descriptive; group/VLAN labels do not
create inheritance, network identity or admission. More-specific bindings use
their own metadata, never annotations from a broader binding.

PolicySnapshot compiles a sparse network-to-config-index metadata map. Only
explanations/assertion reports read that map; ClientBinding, Selection and DNS
workers remain unchanged. This avoids adding metadata strings/pointers to every
hot lookup or telemetry event. The source configuration owns the strings.

Alternative: separate client/network inventory with references from bindings.
Deferred because it adds identity and dangling-reference semantics without an
inventory discovery provider. Optional inline metadata completes a useful slice
using the existing durable safety workflow. Future inventory import must stay
outside the query path.

Compatibility: empty metadata is omitted. Existing configuration and schema-2
stores need no migration; binaries predating binding metadata require a compatible
pre-feature backup when downgrading. History continues to identify client IP,
policy ID and generation; it does not relabel historical queries with current
metadata. Explanations describe the currently selected generation.

Checklist: explore/design; quiet matched-binding benchmark baseline; implement
pure validation and control-only lookup, API/console, durable workflows; review
before fixes; fmt/Clippy/tests, browser and failure/recovery checks; compare local
benchmarks and allocations; package and verify installation/recovery.

Use the policy workbench's Clients & networks tab. Expand a binding's annotations,
edit labels, validate, stage in shadow, review and promote. Clearing every field
removes metadata. The clients inventory searches names, CIDRs, policy and all
annotation text and renders at most 20 rows; the draft editor renders at most 10.
Notes stay collapsed until requested. Metadata edits create new generations and
use the existing revision preconditions.

An individual binding in advanced JSON can look like:

```json
{
  "name": "Work laptop",
  "network": "192.0.2.10/32",
  "policy": "work",
  "metadata": {
    "group": "Work",
    "owner": "Operator",
    "vlan": 20,
    "tags": ["managed", "laptop"],
    "note": "Fixed DHCP reservation"
  }
}
```

`GET /api/v1/clients` returns generation, default_policy, allowed_clients and
bindings with optional metadata. Explain and policy-check traces include optional
binding_metadata. The offline policy-test text output prints these annotations;
JSON retains the same typed object. Group/owner/note limits count UTF-8 bytes.
The 8 MiB aggregate limit counts annotation string/tag payload, not process RSS.

## SafeSearch and YouTube policy contract

Approved continuation, 2026-10-13. Implement a complete opt-in slice through
policy compilation, DNS, explanations, history, imports and the console.

### Provider inputs and versioned coverage

Use the provider's documented CNAME enforcement endpoints, not hardcoded IPs:
[Google](https://support.google.com/websearch/answer/186669?hl=en),
[Bing](https://support.microsoft.com/en-us/bing/blocking-explicit-content-with-safesearch),
[DuckDuckGo](https://duckduckgo.com/duckduckgo-help-pages/features/safe-search) and
[YouTube](https://knowledge.workspace.google.com/admin/youtube/control-youtube-content-available-to-users?hl=en).
Google's www country-domain coverage is frozen from its
[published domain list](https://www.google.com/supported_domains), plus seven
legacy www owners from the official AdGuard SafeSearch catalog to preserve import
coverage (194 exact Google names in v1). YouTube covers
only the five documented names, with strict/moderate choices; unrelated YouTube
hostnames must not be rewritten. Do not fetch any catalog or resolve any name
during compilation or queries. Catalog v1 stays immutable for historical
provenance; changed coverage/targets require a new catalog and policy generation.

### Interfaces and precedence

`PolicyConfig.safe_search` is optional; existing serialized configs stay readable
and default off. Settings select Google/Bing/DuckDuckGo and YouTube off/moderate/
strict, plus catalog version 1. Reject unknown catalog versions and conflicting
explicit local records for protected names/targets. The reusable policy crate
owns these types and compiled data; DNS libraries never depend on the app.

Compile a bounded exact-owner redirect map off DNS workers and share identical
maps within a generation. The disabled path has no map. Local DNS keeps its
existing explicit behavior. Filtering and temporary filter exceptions are
evaluated first; blocked names stay blocked. An allowed protected name resolves
the provider endpoint through the selected policy's existing routes/transport,
then returns the compiled CNAME prefix. Allow rules and temporary pauses do not
disable SafeSearch. No failure may fall back to the unrestricted original name.

Use Hickory names/records and bounded forwarding. Decision caches are keyed by
policy generation. Raw upstream replies share the existing resolver content
identity, forcing question and DO/CD flags; each returned reply is rechecked
against the pinned/current policy. Different protected owners keep private CNAME
prefixes while safely coalescing the same forcing endpoint. Recheck CNAME validity/filtering on every returned redirect,
including cached replies; loops fail closed. Handle A/AAAA/CNAME and other accepted
types using ordinary CNAME semantics. Preserve original questions/casing and all
existing protocol restrictions. A provider outage remains a normal DNS failure.

Expose provider/target/catalog in current-policy and original-generation history
explanations. Use a distinct `safe_search` history path without a history schema
migration; counters group these routed answers with local synthesis. Shadow
evaluation marks changed redirect targets/settings as differences without issuing
extra queries or claiming to have sampled candidate provider answers.

Directly synthesizing fixed provider IPs was rejected because they can change.
Representing the feature as ordinary user rewrites was rejected because local
rewrites bypass filtering and would incorrectly unblock explicitly blocked sites.
No plugin, cloud inspection service, TLS interception or firewall enforcement.

### Import and UI

Provide a dedicated policy editor with named service choices, selected-client
policy scope, clear off state, reviewed validation/shadow/promotion and readable
coverage limits. Translate only proven AdGuard equivalents; missing/unsupported
provider flags, legacy ambiguous enablement or different domain/type/schedule
coverage remain explicit blockers/warnings. Source client/global inheritance must
not silently broaden or remove SafeSearch. Provider DNS policy is separate from
category blocklists, recursive DNSSEC and general filtering pause.

### Verification required

- Compiler: catalog bounds, identical-map sharing, defaults, unknown versions,
  local conflicts, asserted blocks and explanation provenance.
- Local mock DNS: A/AAAA/CNAME, client separation, old unsafe cache, generation
  change/rollback, coalescing, expiry, target blocks, loops, failure without
  unrestricted fallback and shadow differences.
- Real API/history/persistence and desktop/mobile reviewed publication, imports
  and configuration recovery. No public resolver queries in network tests.
- Required workspace fmt/strict Clippy/tests; independent consumers/MSRV;
  root/fuzz audit/deny and targeted sanitizer fuzzing. Capture a disabled-path
  baseline before the query-path change and compare the same local workload.
- Package the final binary/console and verify native/container recovery. Retain
  evidence under ignored `target/review/safesearch/`. DNS tests do not certify the
  provider's actual content filtering or replace deployment/browser validation.

Clients must use this DNS appliance for the listed names. VPNs, another resolver,
hardcoded addresses and independently encrypted DNS can bypass DNS policy.
SafeSearch is not a guarantee that all explicit content is removed.

## Versioned service-domain blocking

Continuation design, 2026-10-13. Done means per-client service selections work in
compiled filtering, cached/CNAME DNS, assertions/shadow, current and recorded
explanations, conservative migration, desktop/mobile reviewed publication and
packaged revision recovery, with local verification evidence.

### Shape and ownership

`PolicyConfig.blocked_services: Option<BlockedServices>` defaults absent. Version 1
selects bounded unique string IDs from a frozen, modest first-party domain catalog.
Four initial services: YouTube, TikTok, Reddit and Discord. This catalog is our own
small selection of public domain facts; no AdGuard implementation or complete
third-party rule catalog is incorporated. Exact coverage is exposed in the console
and authenticated read API. It is not a claim of complete application blocking.

The policy crate expands selections to reserved-provenance `ListInput`s on the
control executor. It borrows unchanged lists when disabled. Lists are appended
in catalog order, independent of selection order, then compiled/shared through
the existing `FilterSets` compiler and byte/rule budgets. Stored config retains
selectors, not generated lists. Historical rule IDs must reconstruct with the
same expansion method, not just raw user lists. Catalog v1 never changes; changed
coverage requires a new version and recovery verification. Unknown versions/IDs,
duplicates and forged reserved list provenance fail validation.

DNS engine evaluation is unchanged: allow rules win, temporary allows/pauses and
explicit local records retain their existing override, blocked root and reachable
CNAME targets use the existing block modes, caches are policy-generation scoped
and assertions evaluate permanent policy. Blocking YouTube wins over SafeSearch
unless an explicit filter override applies. No plugins, JSON, filesystem/HTTP/DB,
parsing, fetching or new locks on the DNS path. No new background tasks.

A separate service matcher was rejected because it would duplicate allow/cache/
CNAME/assertion behavior. Mutating stored lists was rejected because it could
silently change durable input and obscure provenance.

### Import and UI

Translate proven AdGuard global/client IDs and explicit inheritance to draft
selectors. Retain unsupported IDs, schedules, coverage differences and ambiguous
inheritance as blockers; do not guess defaults or silently disable them. Validate
inactive value types too. Source protection disabled keeps destination disabled;
general list filtering disabled does not automatically disable service settings.
Native allows and local overrides can differ from AdGuard ordering: report this.

Use an authenticated catalog endpoint and a compact policy-scoped table with
service name, category, selected checkbox and expandable exact/suffix coverage.
Settings remain drafts until validation/shadow/promotion. Current/history rule
sources identify the service and immutable catalog. Existing custom filter lists
can extend coverage; no mutable or downloaded built-in catalog.

### Coverage evidence and limits

YouTube uses its documented first-party owners (youtube.com/youtube-nocookie.com,
exact youtube[i].googleapis.com) and youtu.be, not broad google.com/googleapis.com
or shared CDN suffixes. See [Google's YouTube network controls](https://knowledge.workspace.google.com/admin/youtube/control-youtube-content-available-to-users?hl=en).
TikTok's primary site is tiktok.com; its CDN/mobile endpoints are deliberately
not claimed covered. [Discord](https://discord.com/) and its
[invite documentation](https://discord.com/safety-library) identify discord.com
and discord.gg. [Reddit's company site](https://redditinc.com/) links reddit.com.
These minimal domain facts do not copy AdGuard's broader GPL catalog. DNS policy
cannot stop VPNs, independent DoH/resolvers, cached addresses or hardcoded IPs.
Blocking an entire service also blocks content, login and support under listed
suffixes; it cannot remove just ads inside the service.

### Verification

Compiler: canonical catalog, unknown/duplicate IDs, count/rule budgets, reserved
provenance, sharing/order independence, allow precedence and assertions.
Local mock DNS/API: client isolation, warm cache after promotion/rollback, CNAME
and SafeSearch interactions, temporary exception expiry, original revision history
and disabled behavior. Import: global/inherit/off/custom, malformed IDs and
unsupported schedule/coverage settings. Real desktop/mobile console flows,
required fmt/strict Clippy/workspace tests, consumers/MSRV, audit/deny and targeted
fuzz. Compare saved loopback executable before/after. Verify final package native
upgrade/backup/restore and container restart, with evidence under ignored
`target/review/services/`. Native deployment, ARM, long soak and independent
security review remain separate gates. Weekly schedules use the explicit contract below.

## Expanded service catalog

The frozen catalog v2 includes twelve explicit first-party
service groups, an upgradeable/searchable coverage editor, conservative imported
selectors, retained versioned provenance and packaged recovery. Keep v1's four
groups/nine rules and serialized default untouched. No new dependencies, DNS
lookup, live catalog downloads, plugin execution or query-path changes.

### Ownership and compatibility

Policy owns immutable static catalogs and validates version-specific IDs/budgets.
`service_catalog()` continues returning v1; add `service_catalog_for_version()`
and `LATEST_SERVICE_CATALOG_VERSION`. Off-executor expansion uses the selected
catalog and `@service/v{version}/…` list names. Existing cache/generation/schedule/
assertion/CNAME/allow semantics apply without a new matcher. Metadata is optional
and omitted on v1 records so its authenticated API response shape stays stable.
GET service-catalog defaults to v1; explicit `?version=2` selects v2. Unsupported
versions/unknown query fields fail visibly. No SQLite schema migration; durable
revisions/backups already contain the catalog identifier. Binary downgrade from
v2 revisions requires a pre-upgrade compatible backup.

V2 preserves the original four groups unchanged and adds eight groups:

| ID | Suffixes | Provider evidence |
| --- | --- | --- |
| netflix | netflix.com | [Netflix help/sign-in](https://help.netflix.com/en/node/114701/) |
| spotify | spotify.com | [Spotify iframe API](https://developer.spotify.com/documentation/embeds/tutorials/using-the-iframe-api) |
| twitch | twitch.tv | [Twitch embed documentation](https://dev.twitch.tv/docs/embed/video-and-clips/) |
| steam | steampowered.com, steamcommunity.com, steamstatic.com | [Steamworks API](https://partner.steamgames.com/doc/webapi_overview), [Steam Community and its assets](https://steamcommunity.com/) |
| roblox | roblox.com | [Roblox API domains](https://create.roblox.com/docs/cloud/reference/domains/apis) |
| whatsapp | whatsapp.com, whatsapp.net | [WhatsApp connection settings](https://faq.whatsapp.com/852892549070029/?cms_platform=web&helpref=hc_fnav) |
| telegram | telegram.org, t.me | [Telegram FAQ/web/link names](https://telegram.org/faq) |
| signal | signal.org | [Signal firewall settings](https://support.signal.org/hc/en-us/articles/360007320291-Firewall-and-Internet-settings) |

These primary sources establish example service-owned names, not an exhaustive
blocking recipe. Selecting their suffixes is our explicit policy choice. Include
provider reference links and concrete scope notes for the new groups. Independent
media/download/game/call endpoints, cached sessions, other DNS, VPNs and direct-IP
traffic can remain. Do not block shared cloud/CDN suffixes or copy third-party
filter lists. Category labels organize services; they do not classify arbitrary
internet domains. Users may add reviewed custom lists to extend coverage.

### Editor and import

Keep each policy's existing catalog. The version chooser changes only a draft
(or the unconfigured catalog view); preserve IDs and weekly windows when upgrading.
Do not allow downgrade while selected IDs are absent from v1. Search by name/ID/
category/domain and filter categories without changing selections, with visible
result/selected counts. Coverage details expose exact/suffix names, scope notes and
provider links. Existing validate/shadow/review/promote remains the publication gate.
New AdGuard drafts may select v2's recognized IDs but retain coverage/precedence/
zone/DST/inheritance/unknown-service blockers. Never label the larger catalog full
source parity or silently publish it.

Alternative: expand v1 in place or download a third-party service registry.
Rejected because it silently changes retained policy content/provenance and adds
licensing/freshness/network risks. Frozen independent v2 is bounded and reviewable.

### Done predicate and verification

Prove every catalog ID/domain is canonical/unique/bounded, v1 bytes/provenance stay
stable and v2 IDs differ by version. Verify all twelve groups, neighboring allowed
names, manual allows, schedules/off variants, serial/parallel IDs and original
history after switching/rollback. Exercise authenticated API versions/rejections,
new AdGuard selector inheritance/unknown blockers, desktop/mobile search/category/
upgrade/downgrade/publication, and packaged v2 restart/backup/restore. Run required
fmt/Clippy/workspace tests, Bun checks/browser flows, consumers/MSRV, audit/deny and
targeted services/migration fuzz. Compare saved binary vs final local loopback
latency/RSS; retain ignored target/review/catalog-v2 evidence. Do not activate host
DNS/services. Representative-network soak, native-host/ARM and independent
security-review gates remain open.

## Weekly service schedules

Native per-client weekly service schedules use
immutable compilation, DNS/cache/inflight boundaries, actual historical state,
reviewed imports, desktop/mobile editing and packaged recovery. No management
worker/timer, plugins, parsing, filesystem, JSON or database operations on DNS.

### Inputs and compilation

Add optional `BlockedServices.schedule: WeeklySchedule`, with explicit IANA
`time_zone`, `mode: block|allow` and up to 32 windows. Each window has unique
`days` (mon..sun), `start` and `end` in HH:MM; 24:00 is end-only. Intervals include
start, exclude end; overnight windows continue into the following day, including
Sunday to Monday. Overlaps are unioned. Empty block windows mean never block;
empty allow windows mean always block. No schedule keeps today's behavior.

Parse time zones and windows off DNS workers into immutable 10080-minute bitmaps;
share identical schedules. Use chrono/chrono-tz's bundled tables, with chrono
clock/local-time features disabled. Compile both service-on and user-lists-only
filter sets through existing budgets/sharing. Permanent assertions deliberately
test the service-on policy, ignoring schedules and temporary actions; this keeps
validation independent of wall time. Current explanations evaluate actual time.

Queries select a precompiled filter set from the current civil minute. Decision
cache slots encode policy ID plus on/off state, leaving existing borrowed key
hash shape intact. Raw upstream replies keep their existing resolver identity and
are rechecked against the current scheduled state before return. No cache holds a
schedule result across states. Clock outside 2000–2099 fails closed for service
selection and returns TTL zero; it does not change client admission or local/allow
precedence. Correct host time remains a deployment requirement.

### Boundaries and provenance

Read the wall clock only for scheduled policies. Recheck at completion, including
cache hits, upstream/coalesced waits and temporary-expiry handling. If a reply was
synthesized under a block that just ended and no valid resolver answer exists,
return SERVFAIL for retry rather than retain the old block or invent an answer.
Final source drives blocked/failure counters. CNAME targets use the same selected
filter set; SafeSearch remains filter-first. Clamp all private reply records to
floor(seconds remaining to the next civil minute), preserving EDNS OPT control
bits. This conservative cap includes unrelated/local records in scheduled policies.

DST gaps contain no nonexistent local minutes; repeated local minutes apply the
same window twice. Evaluate from UTC instants, never ambiguous local timestamps.
Time-zone tables follow the deployed locked binary. Existing client answers and
wall-clock jumps cannot be recalled; no promise of exact client/firewall cutover.

Schema 5 adds nullable integer schedule state to history. Query events and shadow
metadata record active/inactive/invalid-clock state actually used by the final
reply. Original rule IDs reconstruct the corresponding retained on/off input;
do not derive state from SQLite insertion time or current timezone rules. Legacy
rows remain null and valid for unscheduled revisions. A scheduled revision with
missing/invalid recorded state must not invent provenance. Backup verification
checks the new column, bounds and backward migration; old binaries cannot read
schema 5 and downgrade requires the pre-upgrade database backup.

### UI and import

Provide explicit policy scope, schedule enable/disable, named time zone, block/
allow mode and editable day/time rows; default enabling to block all days so
existing behavior stays unchanged until reviewed edits. Explain overnight/DST,
empty windows, override semantics and minute TTLs. Live published status stays
separate from draft choices. Current/history explanations show recorded state.

Translate only established source schedule forms and explicit zones. AdGuard
windows are allow periods and its elapsed-since-midnight calculation differs on
DST dates; those differences, Local/absent zone, unrecognized duration formats
and unsupported coverage remain explicit blockers. Never guess a source zone or
silently activate an untranslated schedule. No third-party implementation copied.

### Verification

Deterministic UTC/Oslo DST, overnight/week wrap, exact/subsecond edges, invalid
clock, empty/overlap/malformed/bounded windows, serial/parallel filters and stable
on/off history IDs. Internal engine tests inject explicit instants without public
clock callbacks/plugins: warm decisions/raw replies, state transitions during
inflight, CNAME/SafeSearch/allow/local/temporary behavior, TTLs and shadow/counters.
Real local mock API/browser flows prove publication/history, scopes and restart.
Run required fmt/Clippy/workspace tests, MSRV/consumers, audit/deny/parser fuzz and
saved-binary benchmarks. Finish native/container schema-5 upgrade/backup/recovery.
Evidence under ignored target/review/schedules. Native-host, ARM, representative
soak and independent security review remain deployment gates.
