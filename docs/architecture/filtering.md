# Filtering and rule compatibility

Current imports select **adguard_v6**. The sections below describe the incremental grammar: each older interpreter remains frozen, and later versions add only the stated combinations. All allows take precedence over blocks; `$important` remains unsupported.

## Implementation ownership

The crate root is the stable public import surface. Private model owns public
records and serde shapes; parsing owns control-plane normalization/interpretation;
index owns immutable name indexes and escaped-label traversal; snapshot owns query
evaluation, context partitions and derived statistics. compile remains ordered
control-plane ingestion; existing scope/regex/value/cancellation/parallel modules
retain their roles. Contract tests in tests/matching.rs consume the public API.
Module moves do not change stored interpreter semantics or query work.

## Versioned AdGuard rule cancellation

Console validation and migration notices refer to the reviewed/imported lists
without assuming a syntax version. They retain the warning that removing a
cancellation exception can expose a block.

Goal: accept supported AdGuard `$badfilter` declarations during imports and native
editing, with visible cancellation provenance, without changing published legacy
rule IDs or adding work to DNS queries.

`native` and `adguard` remain frozen. This slice introduced `adguard_v2`; V3–V6 inherit its cancellation semantics. Opting an
existing list into that version is an explicit configuration change. V2 uses
whole-line `#` / `!` comments (inline comments are not stripped). Older binaries
cannot load v2 revisions; downgrade requires a compatible backup.

V2 accepts a sole lowercase `$badfilter` on supported basic hostname
masks and regex rules. It does not cancel hosts or bare exact-domain entries.
Escaped delimiters and mixed, negated, valued or unknown modifiers remain invalid and prevent policy
publication. Cancellation uses the literal pattern without `@@`, plus effective
allow/block action. Case, anchors and text are significant; normalized matcher
equivalence is deliberately insufficient. It operates across v2 lists within a
policy, independent of declaration order. Native, legacy AdGuard and generated
service rules remain separate. Removing an exception can expose a block rule;
no allow rule is synthesized.

The filtering compiler collects borrowed cancellation selectors in a bounded
prepass, then removes directives and their targets before deduplication and index
construction. Serial and owned parallel compilation use the same classifier and
ordered ingestion. All raw lines, including directives and disabled entries,
still consume the input budget. At most 65,536 potential declarations are accepted;
selectors are limited to 4,096 bytes and validated using the existing parser and
regex budgets. The existing 512 active-regex limit is also enforced during
ordered ingestion, after cancellation/deduplication; AdGuard parallel batches are
limited to 512 lines to bound overwork on rejected inputs. DNS evaluation is unchanged and retains no selector map.

Metadata retains totals plus the first 200 distinct cancellation targets, with
up to five directive and five disabled sources per target, in input order. The
complete revision text preserves all sources. This bounds report memory/API
size independently of publisher duplicates. `/api/v1/filter-lists` additionally
caps the combined response at 200 targets; `?policy=name` retrieves one policy's
bounded report. The UI loads missing policy details on opening their disclosure. Per-list `badfilters` and `disabled`
counts are omitted when zero for older consumers. Reports are immutable and
included in the logical payload estimate (which is not RSS).

Alternative rejected: cancel deduplicated normalized rules. That would remove
uncancelled text variants and Native rules sharing a matcher, and could change
historical IDs. Supporting arbitrary modifier combinations is a separate slice,
particularly priority modifiers that conflict with the allow-wins contract and
response modifiers requiring protocol/cache changes.

Verification: serial/parallel equivalence, cross-list order, action/text identity,
regex delimiters, malformed directives, caps, legacy parser history, imported
client scope, publication/assertion failure/rollback, bounded reports and browser
flows. Run workspace formatting, Clippy/tests, root/fuzz audit and deny, targeted
filter/migration fuzzing, Bun checks/tests and a bounded compilation benchmark.

Sources: [AdGuard DNS syntax](https://adguard-dns.io/kb/general/dns-filtering-syntax/)
and [urlfilter v0.23.4 network rules](https://github.com/AdguardTeam/urlfilter/blob/v0.23.4/rules/network.go)
(pinned by AdGuard Home revision `8dedd3278542b45ea21994e24422f5cc53e14b8f`).
This is a supported subset; broader modifiers and full source parity are not
claimed.

## Versioned per-rule domain exclusions

Goal: import and edit AdGuard `$denyallow` rules without globally unblocking an
excluded domain. A complete slice covers compiler, DNS/policy publication,
historical explanations, import diagnostics, browser flows and local evidence.

Existing Native, AdGuard and V2 interpreters remain frozen. V3 is an explicit
list syntax; V4–V6 inherit its semantics. It inherits V2 cancellation and
whole-line comments and accepts a sole lowercase `$denyallow=domain|domain` on
network masks or regex patterns. Exclusions cover the named domain and descendants,
including on exception rules. Bare domains/hosts with modifiers, unknown/combined
modifiers (including denyallow plus badfilter), wildcards/negations/empty exclusions
are rejected and block publication. This is a supported subset, not full parity.

The compiler normalizes, sorts and deduplicates exclusion domains off the query
executor. Rule identity includes the exclusion set. An unscoped suffix can subsume
a scoped descendant; a scoped suffix must never prune another rule. Separate
immutable exact/suffix indexes hold scoped candidate IDs. The ordinary indexes and
query fast path stay intact for snapshots without scoped rules. Regex matching
continues past an excluded candidate. Every allow still wins over every block.
Within an action exact precedes most-specific suffix, then regex; identical match
locations report the first active rule ID. Escaped dots remain label content.

Bounds: 512 unique uncancelled scoped rules, 64 declared exclusions per line and 8,192
normalized exclusions across unique rules, plus existing raw/byte/regex budgets.
Over-limit compilation never publishes a partial generation. The immutable rule
stores an optional shared exclusion object; logical payload estimates count its
retained domains and candidate indexes. Exclusion matching scans at most 64 suffixes per rule and checks escaped label
boundaries directly; it never repeats a query ancestor walk per candidate.
No parsing, allocation of domain strings,
I/O or JSON is added to query processing. Existing generation/cache identities
and durable assertion-before-publication boundaries remain unchanged.

Alternative: expand exclusions into global allow rules. Rejected because other
lists must remain able to block excluded tracking domains. Replacing all ordinary
indexes with vectors is also unnecessary for the bounded scoped subset.

Verification: overlap and label boundaries, exact/suffix/regex and exception rules,
legacy freeze, deduplication/redundancy, bounds, serial/parallel equivalence,
import inheritance and unsupported blockers, local DNS/cache/shadow/rollback/history,
strict Rust/Bun checks, targeted sanitizer fuzzing, audits, scoped matching and
saved-daemon measurement, browser inspection and release recovery smoke.

Sources: [AdGuard DNS syntax](https://adguard-dns.io/kb/general/dns-filtering-syntax/)
and [urlfilter v0.23.4 network rules](https://github.com/AdguardTeam/urlfilter/blob/v0.23.4/rules/network.go).

Profiling found redundant exclusion checks after an earlier candidate of the
same action had matched. Candidate vectors retain input order, so later same-action
candidates now skip those checks while still scanning for an allow. This preserves
priority/provenance and reduces the overlapping-block case without adding a new
data structure. A regression covers a later allow at the same name.

## Versioned DNS type rules

Goal: support AdGuard DNS type restrictions for questions and response values,
with accurate cache partitioning and recorded provenance, without changing stored
Native/AdGuard/V2/V3 interpretations. Complete the compiler, DNS engine, durable
history, imports, typed assertions and UI as one tested slice.

V4 introduced type restrictions; V5/V6 inherit them. V4 accepts `dnstype=A|AAAA` and `dnstype=~A|~CNAME`, alone
or with one `denyallow`. Type names are case insensitive; supported names use
Hickory's record-type vocabulary, excluding private ANAME and `*`. Unknown names,
empty entries, duplicate modifiers and other combinations (including badfilter)
block publication. Include/exclude lists are both retained; exclusions take
precedence, then a nonempty inclusion list limits matching. Existing sole badfilter
remains supported across compatible lists. V3 remains frozen.

Rule scope becomes one optional immutable object containing domain exclusions
and type restrictions. Its JSON flattens into the existing optional `denyallow`
array plus `dnstype` include/exclude arrays. This reuses the existing optional
pointer per Rule rather than adding another pointer to every ordinary rule.
The unreleased Rust field changes to `scope`, with domain/type accessors; old
unscoped/V3 JSON shapes and rule IDs remain unchanged. Scope-aware deduplication,
conservative redundancy and bounded candidate indexes remain off the executor.
512 unique scoped rules, 64 declared domains/types per line, 8192 retained domains
and 8192 retained types supplement existing raw/byte/regex limits.

`evaluate_type(name,u16)` selects only applicable rules; legacy `evaluate` defaults
to A. DNS decisions use the actual question type. The bounded decision cache adds
a type partition only when a policy has type rules; ordinary policies retain
cross-type reuse. Raw resolver caches remain keyed by resolver/question/type/flags,
retain original validated messages and never store policy-filtered synthesis.
Inflight work keeps its original immutable generation. Scheduled/temporary and
shadow re-evaluations must use the same typed semantics.

Response inspection still validates only the CNAME chain reachable from the
original IN question, with the existing 16-hop loop/conflict bound. V4 evaluates
canonical targets as CNAME, independently of question type. IPv4/IPv6 address
values and HTTPS IP hints are checked with A/AAAA/HTTPS types, only for reachable
IN owners. V4 value rules are separate bounded indexes, using original rule IDs
and the existing regex set. Native/legacy/V2/V3 rules cannot become IP rules by
accident. Numeric masks and regexes from V4 can opt into value matching; at most
4096 value rules and 256 address/hint checks per reply are accepted. Exceeding
response work bounds produces SERVFAIL, never a partially checked answer.
Rules with denyallow do not match IP values, matching the source implementation.
An explicit original-question allow, local rewrite or live temporary exception
retains its existing response exemption. SVCB hints are not added by this slice.
Whole blocked responses are synthesized; AD and upstream signatures are discarded
through the existing block builder. Allowed replies retain raw signatures, while
the existing finalizer clears AD on every reply; this slice adds no DNSSEC validation. No RRset surgery is introduced.

Schema 6 records matched response type separately from original qtype. Migration
from schema 5 labels retained matched_domain entries as CNAME: that was the only
previous response subject. Historical reconstruction continues using recorded
compiler/generation/schedule state; current-policy comparisons accept an explicit
answer subject/type alongside the original question. Typed assertions default to
A and omit that default in JSON, preserving old configurations.

Alternative rejected: question-only dnstype or filtering every answer owner by
its RR type. The source checks CNAME targets and address values instead; the
latter alternative would incorrectly block the documented ~CNAME case. Protocol
restrictions (ANY/transfers/signed/non-IN/nonrecursive queries) remain unchanged.
Full modifiers/source parity and actual host/ARM/real-network soak/security review
remain separate gates.

Verification: frozen JSON/decisions/IDs, source request/response examples, masks,
regexes, mixed/negated/duplicate/unknown types and caps; serial/parallel equivalence;
type-separated decision/cache/inflight work; reachable/unrelated CNAME/IP/HTTPS
records, original allows, schedule/exception/shadow transitions, AD/RRSIG behavior;
imports/inheritance, assertion failures, history/schema/restart/backup/rollback;
desktop/mobile flows, strict Rust/Bun/consumer/MSRV checks, audits and focused
sanitizer fuzzing; saved-binary and scoped matcher/compiler measurements; exact
final-bundle native/container recovery.

Sources: [DNS syntax](https://adguard-dns.io/kb/general/dns-filtering-syntax/),
[urlfilter v0.23.4](https://github.com/AdguardTeam/urlfilter/blob/v0.23.4/rules/network.go)
and [AdGuard Home response filtering](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/dnsforward/filter.go).

## Versioned per-rule client restrictions

Implement a complete V5 slice for `$client`: IP/CIDR and exact persistent-client
names, mixed inclusion/exclusion, escaped delimiters and combinations with
`dnstype`/`denyallow`. Preserve Native/AdGuard/V2/V3/V4 grammar and IDs, allow
precedence, existing explicit allows/rewrites/temporary exemptions, raw caches,
bounded telemetry and pinned generations. Unknown modifiers and combined badfilter
remain blockers. V5 introduced client restrictions; V6 inherits them; stored policies opt in explicitly.

The filter library owns immutable client predicates. `ClientContext` carries only
an address and an optional explicit binding name; no inventory lookup, parsing,
JSON, database or management work runs on the query path. Inclusion/exclusion
arrays serialize as canonical network or literal name strings; exclusions win,
then a nonempty inclusion list narrows matching. Missing context skips scoped
client rules, including exclusion-only rules. Existing context-free APIs remain
compatible. Names are case sensitive and limited to 128 UTF-8 bytes, with the same
control/bidirectional-text restrictions as native bindings. No ClientID/MAC or
hostname discovery is invented; imported binding names retain source names. If
named restrictions exist but a source client name is missing, migration reports
a blocker: a generated preview label cannot prove the original identity.

V5 retains 512 scoped rules, 64 declared values per modifier and 8192 total client
values alongside existing independent domain/type/regex/value limits. Rules share
one optional scope pointer; the new selector is boxed only when present.
The compiler creates sorted IP interval boundaries and a bounded exact-name map.
Profiling also justified merged CIDR membership ranges and binary-search name
matching inside each selector; these are compiled once and exposed read-only.
Reply inspection checks client applicability once: if every value rule excludes
that client, value matching is skipped. CNAME structural checks remain mandatory;
the existing 256-value limit still fails closed whenever a value rule can apply.
An interval number and name ID identify an equivalence class: equal class means
all retained client predicates agree. IPv4 and IPv6 cells stay distinct; existing
canonical mapped-client handling remains intact. No probabilistic hash substitutes
for identity. The bounded decision key adds a u32 class next to qtype (48 bytes on x86_64); ordinary filters use zero, retaining cross-client reuse. Resolver raw
cache identities are unchanged. This uses standard sorted arrays and maps, not a
new DNS parser or custom trie. A larger full-IP key is the rejected alternative:
it prevents harmless reuse and adds memory to every ordinary cache entry.

Question, CNAME/address/HTTPS, weekly/exception and shadow decisions all receive
context from the appropriate pinned snapshot's binding. Current explanations and
permanent assertions use the same context. Recorded provenance exposes client
scope from the original revision; existing schema 6 already records source client
IP and response type, so no history migration is needed. Binding renames/policy
changes publish a new generation; rollback never reuses live keys.

Verification: exact source examples and escaping; malformed/duplicate limits;
serial/parallel identity; exhaustive boundary and deterministic random checks that
same class implies same predicates; two clients sharing one policy/domain/type,
actual source names, mapped addresses, response types and raw-cache reuse; pending
publication and renamed shadow bindings; assertions/imports/history/restart/backup;
desktop/mobile publication and explanations; strict Rust/Bun/consumer/MSRV checks,
audit/deny and focused sanitizer fuzzing; saved-binary matcher/compiler/DNS/RSS
measurements and exact final native/container recovery. Evidence belongs under
ignored `target/review/client-scope/`; no hosted CI or production activation.

Sources: [syntax](https://adguard-dns.io/kb/general/dns-filtering-syntax/#client),
[urlfilter client predicates](https://github.com/AdguardTeam/urlfilter/blob/v0.23.4/rules/clients.go),
[parser](https://github.com/AdguardTeam/urlfilter/blob/v0.23.4/rules/rule.go),
[escape handling](https://github.com/AdguardTeam/urlfilter/blob/v0.23.4/rules/rules.go),
and [AdGuard client settings](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/filtering/filtering.go).

Full source parity, remaining modifiers and actual host/ARM/network-soak/security
review remain separate gates. DNSSEC validation stays with a validating resolver.

## Versioned client tag restrictions

V6 adds `$ctag` restrictions to the supported AdGuard subset. They combine with
`client`, `dnstype` and `denyallow` and retain the global allow-first contract.
Native through V5 interpreters remain frozen. Fresh AdGuard imports use V6;
stored policies opt in explicitly. Unknown modifiers, combined badfilter and
unsupported tag vocabulary remain publication blockers.

An inclusion list matches when any explicitly assigned tag intersects it.
Exclusions win, then nonempty inclusions narrow applicability. For example:

```text
||ads.example^$ctag=device_phone|user_child|~user_admin,dnstype=A|AAAA
@@||allowed.example^$ctag=user_child
```

The first rule applies to phones or children except administrators, for A/AAAA.
The second is a scoped allow and wins over matching block rules. An untagged
client can match an exclusion-only rule; absent context skips all tag rules.
Legacy ClientContext APIs represent explicitly untagged clients. Use
`ClientContext::with_tags` and `context_partition` when providing tag context;
`client_partition` remains the legacy identity-only classifier.

Filtering tags belong to an explicit binding, separately from descriptive tags:

```json
{
  "name": "Phone",
  "network": "192.168.1.22/32",
  "policy": "default",
  "filter_tags": ["device_phone", "user_child"],
  "metadata": { "tags": ["work"] }
}
```

`metadata.tags` remains advisory and never affects matching or admission.
More-specific bindings use their own filtering tags; assignments are not inherited.
Unbound clients have none. No inventory, hostname discovery, MAC or ClientID
inference is added. Assignments never grant admission through `allowed_clients`.
The editor provides supported choices, makes their effect explicit and shows
assigned tags separately from annotations in current/assertion explanations.
Historical rule scopes come from the event's original revision.

Supported names are the documented AdGuard Home vocabulary:

| Category | Tags |
| --- | --- |
| Device | `device_audio`, `device_camera`, `device_gameconsole`, `device_laptop`, `device_nas`, `device_pc`, `device_phone`, `device_printer`, `device_securityalarm`, `device_tablet`, `device_tv`, `device_other` |
| OS | `os_android`, `os_ios`, `os_linux`, `os_macos`, `os_windows`, `os_other` |
| User | `user_admin`, `user_regular`, `user_child` |

Names are exact lowercase values. Unknown/duplicate assigned tags fail validation.
Unknown rule values, empty entries, quotes and duplicate modifiers are invalid.
Rule values deduplicate after the 64-declared-value check. The broader urlfilter
parser accepts other syntactically valid names; this implementation deliberately
reports those as unsupported instead of guessing their identity or relevance.
Imports preserve source tags on every supported CIDR and report explicit blockers
for unsupported values. Existing annotations are never converted automatically.

### Boundaries and implementation

Compile assigned tags once into ClientTags, a private validated u32 mask.
FilterContext carries the original IP/name plus that mask; ClientContext's public
shape remains intact. TagSelector owns read-only sorted name arrays and masks in
an optional box within the existing scope pointer. Rule layout remains 56 bytes
on x86_64. Compilation enforces independent limits: 512 scoped rules, 64 declared
values per modifier and 8192 retained tag values, alongside existing type/client/
domain/regex budgets. Tag predicates use mask intersections on the DNS path;
parsing, inventory, management, JSON and storage remain off that path.

The cache context is u64: client equivalence in the upper 32 bits and relevant
assigned tag bits in the lower 32. Tags not used by this snapshot do not split
its decisions. No probabilistic identity hash substitutes for equivalence.
DecisionKey grows from 48 to 56 bytes on x86_64; that layout cost is explicit.
The alternative of interning every binding/tag combination couples library
matching to application binding ownership and adds unnecessary complexity.
Raw resolver answers and caches remain shared and unfiltered.

Question/response, schedule, exception, assertion and shadow paths use tags from
the appropriate pinned generation. Pending answers retain their original tags.
Reply preflight includes tag-only address rules and skips value work when all
such rules exclude the client. CNAME structure checks always run; the existing
256-value limit fails closed when any value rule can apply. The client-context
requirement flag includes tag-only rules; direct and sanitizer regressions cover it.

Schema 6 is unchanged. Older binaries cannot parse V6 rules or bindings with
`filter_tags`, even when their list version is older. Downgrade using a compatible
backup/configuration. Rollback publishes a new generation and never reuses live
cache keys for changed content.

AdGuard `$important` can make blocks override ordinary allows. That conflicts
with this repository's explicit global allow precedence, so it remains unsupported.
No partial priority interpretation is presented as parity. DNS rewriting,
unsupported identities/regex/type names, full source parity, actual host activation,
ARM, long real-network soak and independent security review remain open.
DNSSEC validation remains delegated to a validating resolver such as Unbound.

Sources: [documented tag vocabulary and semantics](https://adguard-dns.io/kb/general/dns-filtering-syntax/#ctag),
[urlfilter matching](https://github.com/AdguardTeam/urlfilter/blob/v0.23.4/rules/network.go),
[parser](https://github.com/AdguardTeam/urlfilter/blob/v0.23.4/rules/rule.go),
and [priority semantics](https://adguard-dns.io/kb/general/dns-filtering-syntax/#important).
