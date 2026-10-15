# Migration compatibility and source conversion

Imports return authenticated, revision-bound drafts. Review every compatibility blocker before validation, shadow and promotion. Unsupported source behavior must never silently become supported. Converted records are frozen until a complete reviewed reimport; ordinary downloaded-list refresh cannot update them.

## Migration parity follow-up

This slice adds Pi-hole v5 Teleporter support and translates more AdGuard resolver
configuration. Imports remain authenticated, revision-bound **draft previews**.
They never activate DNS, fetch lists, contact bootstrap servers or copy credentials.
Full source parity and production stability remain separate release objectives.

### Boundaries and design

Pi-hole Web [v5.21's exporter](https://github.com/pi-hole/web/blob/v5.21/scripts/pi-hole/php/teleporter.php)
writes JSON tables, local files and dnsmasq configuration into tar.gz. It does not
export downloaded gravity contents. Normalize the supported JSON tables into a
private SQLite schema and reuse the existing group/rule/client translator. SQL
comes exclusively from this application; source SQL and shell settings are never
executed. An independent second rule/group implementation was rejected because
it would create two places to maintain policy semantics and provenance.

- v5 requires the four exact/regex rule tables, group/client/adlist tables and
  their association tables. Missing/duplicate/malformed identities and dangling
  v5 associations fail parsing. Unknown table fields become compatibility blockers.
- Exact allow/block rules, supported regex, enabled groups and IP/CIDR bindings
  use the existing immutable policy compiler and retain assignment/provenance.
  Enabled publishers without rule contents remain blockers. No-group assignments
  require review, including in the existing gravity/v6 adapter.
- Supported hosts and multi-owner CNAME records retain targets and explicit CNAME
  TTLs. v5 NULL/NXDOMAIN/NODATA modes are translated. Destination null-address and
  implicit local-record TTLs are 60 seconds, reported as a reviewable difference.
- setupVars literal resolver addresses and supported effective dnsmasq `server`
  directives become explicit profiles/routes. The generated `01-pihole.conf`
  takes precedence over setupVars resolver values. Unknown directives, omitted
  external hosts, DHCP and unsupported private-name behavior remain blockers.
- Nonzero source privacy, disabled query logging/persistence and disabled
  protection require explicit destination review. Privacy/authentication process
  settings remain independently managed and are never part of policy publication.

TAR uses a maintained library, raw entry iteration and no extraction. The input
limit is 16 MiB; the entire gzip expansion, including metadata/padding, is bounded
at 64 MiB before TAR parsing. At most 64 entries are accepted. Checksum errors,
truncation, duplicate/unsafe paths, links, sparse/extended headers and nonzero
trailing archive data are rejected. Source JSON uses the existing depth/node/
event/scalar budgets and duplicate-key rejection. The private normalized SQLite
file is limited to 64 MiB. These are distinct resource budgets, not a claim that
the importing process peaks at 64 MiB. Heavy control-plane admission remains held
through blocking work and response retention; none of this runs on DNS workers.

AdGuard [domain-specific upstream syntax](https://github.com/AdguardTeam/AdGuardHome/wiki/Configuration#specifying-upstreams-for-domains)
becomes ordinary DNS-label suffix routes with most-specific selection. Literal
UDP endpoints and repeated declarations for the same domain are retained in
order, with at most eight distinct addresses per resolver set. Wildcard,
unqualified-only, default-resolver escape, plain hostname and unsupported
transport forms remain blockers. Each imported set must have compatible
transport/identity/trust/deadline semantics; mixed incompatible fallbacks are
never dropped to make a partial set look ready. Import reports the destination's
ordered failover behavior explicitly.

DoT/DoH URLs reuse an **already configured** destination profile only when its
DNS authentication name, port and HTTPS path/query match. Its endpoint IPs, trust,
connection limit and timeout survive. Conflicting matching profiles are blockers.
Source bootstrap DNS servers resolve names; they are not resolver endpoint IPs.
Import does not resolve names or weaken certificate verification. IP certificate
identities, DoQ/DNSCrypt and automatic bootstrap discovery are outside this slice.
The [client resolver follow-up](migration.md) adds per-client resolver
translation; the [DS routing follow-up](local-dns.md) adds explicit source parent
selection for new AdGuard drafts. Native/Pi-hole defaults remain question-based. An unresolved set preserves the destination
resolvers and produces a blocker rather than a plaintext downgrade.

### Operator workflow

1. Export Pi-hole Teleporter or AdGuard configuration. For encrypted AdGuard
   upstreams, configure the matching pinned destination profile first.
2. Open Policies → Migration, choose the source and upload the backup. The CLI
   uses the same translator:

   ```sh
   rustwalld-dns migrate --source pihole --input teleporter.tar.gz --base-config config.toml
   rustwalld-dns migrate --source adguard --input AdGuardHome.yaml --base-config config.toml
   ```

3. Inspect all compatibility diagnostics and the translated configuration. Fetch
   and review omitted publisher contents through Downloaded lists. Resolve
   unsupported settings before claiming a replacement for that source.
4. Load the local draft, validate required assertions, stage in shadow, review and
   promote. Source import alone changes neither live DNS nor the durable revision.

The console presents backup import and its compatibility report before node
copying, with optional encrypted-resolver help. Desktop/mobile verification
includes source-secret exclusion, retained active DNS and reviewed promotion.
After preview, the upload input is cleared as well as the application state,
allowing the same file to be selected again without retaining its browser input.

## AdGuard rewrite source layout and activation

Exact A/AAAA passthrough imports now work in both `dns.rewrites` and
`filtering.rewrites`. The verified `filtering.rewrites_enabled` global control
also preserves the source's activation state without disabling ordinary filters.

### Corrected source interpretation

The previous slice incorrectly associated `dns.rewrites` with the separate
rewrite/storage implementation. The pinned source says otherwise:

- [Migration to schema26](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/configmigrate/v26.go)
  moves the existing DNS-container rewrite array into filtering.
- [Migration to schema31](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/configmigrate/v31.go)
  initializes entry enabled flags to true.
- [Current configuration](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/home/config.go)
  defaults the global RewritesEnabled flag to true. Filtering configuration still
  stores LegacyRewrite entries.
- [Current API](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/filtering/rewritehttp.go)
  still reads/writes those entries and marks replacement with rewrite.Item as TODO.
- [Query processing](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/filtering/filtering.go)
  skips legacy rewrites when the global flag is false.

All references use commit `8dedd3278542b45ea21994e24422f5cc53e14b8f` (schema34).
The distinct storage module's suffix exceptions do not establish config-container
semantics. The erroneous old-container passthrough blocker is removed, and live
documentation is corrected. Historical archives/evidence retain their original
content; this correction does not claim that earlier reports were accurate.

### Import behavior

The following source omits every rewrite from the native draft, including the
entry marked enabled. Its ordinary privacy filter remains active.

```yaml
schema_version: 34
filtering:
  rewrites_enabled: false
  rewrites:
    - {domain: privacy.test, answer: 192.0.2.10, enabled: true}
    - {domain: privacy.test, answer: AAAA}
user_rules: [privacy.test]
```

An omitted global control defaults to enabled. A present control must be boolean;
null, string false, numbers and containers are rejected. Per-entry mappings,
text values, enabled booleans and unknown keys are still checked while globally
off. Unknown values are not echoed. One global-disable notice avoids a diagnostic
per inactive entry. All inherited client policies omit the same definitions.
Inactive source definitions are not retained as editable native records; the
original backup retains them. No native global toggle or source round-trip claim
is introduced.

The global control is supported only at the verified filtering location.
`dns.rewrites_enabled` remains an unknown-setting blocker. A filtering global
control combined with only old DNS-container definitions is an ambiguous mixture
of source schema layouts and remains blocked; a false control still leaves a
conservative inactive draft. Both non-null rewrite containers remain ambiguous. An explicit schema26+ hint
with old DNS-container definitions is also blocked, and those definitions are
not activated in the draft: that schema no longer runs the move-to26 migration.

Schemas before31 explicitly declaring an inactive entry are blocked while the
global control is active: source migration initializes their enabled values to
true. Current schemas31+ and inputs without a schema hint retain the established
explicit per-entry activation behavior. A schema hint must be a nonnegative
integer. Older ordinary entries without enabled fields retain their active default.
The importer does not claim general reproduction of every AdGuard schema migration.

Publication still requires validation, shadow staging and reviewed promotion.
Permanent assertions cannot silently weaken. Local DNS rules, exact passthrough,
normalized names, alias behavior, ordinary allow precedence and response inspection
use the existing policy engine. Pattern forms outside the supported subset below,
ambiguous CNAME owners and source-important priority remain compatibility limits.

### Verification

Check source layout/defaults/global controls, malformed/private fields, version
conflicts, both families, alias/client inheritance, actual DNS replies, durable
rollback and reviewed desktop/mobile publication. These remain management-only
operations; query processing, caches, syntax V6 and schema 6 are unchanged.

## Literal AdGuard DNS rewrite imports

Migration converts a bounded subset of AdGuard `user_rules` and enabled block
filter files bundled in a backup ZIP with `$dnsrewrite` into native local DNS records. This reuses tested exact/wildcard answers and
reviewed publication; it does not add a new native list interpreter.

### Supported input and results

```yaml
schema_version: 34
filtering:
  blocked_response_ttl: 17
  rewrites_enabled: false
user_rules:
  - '||private.home.arpa^$dnsrewrite=192.0.2.10'
  - '||private.home.arpa^$dnsrewrite=NOERROR;AAAA;2001:db8::10'
  - '|nas.other.home.arpa|$dnsrewrite=NOERROR;A;192.0.2.20'
```

| Source pattern | Native records | Coverage |
| --- | --- | --- |
| `||name^` | `name` and `*.name` | Apex plus descendants at any depth |
| `|name^` or `|name|` | `name` | Exact owner only |

Address forms accept shorthand literal IPs and uppercase `NOERROR;A;IP` /
`NOERROR;AAAA;IP` triples. Exact and suffix TXT/PTR/MX/SRV forms are described below. Parameter-free
[HTTPS/SVCB AliasMode and ServiceMode forms](local-dns.md) are also supported. Names must be ASCII without whitespace or a trailing root dot;
normalization must not broaden the source mask. Source reply TTL is retained:
current default 10, explicit 0 stays0, accepted range 0..86400. The SOA-only fallback
of 3600 seconds does not apply to address answers. Source settings live under
`filtering` in schema 26+ and under `dns` in older layouts. Explicit contradictory
hints or mixed filtering controls/TTLs block conversion.

A question receives records of its requested type. Other types receive local
NOERROR/NODATA, and concrete question names replace wildcard templates on wire
replies. IPv4/IPv6 values can share one pattern. Exact owners support up to 32
distinct addresses per family; suffix owners retain one per family.
Ordinary filtering rules remain separate. Destination admission and permanent
assertions are retained and still gate validation/publication.

### Same-pattern exceptions and exact address sets

```yaml
user_rules:
  - '|pool.home.arpa^$dnsrewrite=192.0.2.10'
  - '|pool.home.arpa|$dnsrewrite=192.0.2.20'
  - '|pool.home.arpa^$dnsrewrite=192.0.2.30'
  - '@@|pool.home.arpa|$dnsrewrite=NOERROR;A;192.0.2.10'
```

This exact owner returns `192.0.2.20` and `192.0.2.30` with the source reply TTL.
The exception can precede or follow the positive rules. Shorthand and full address
forms compare parsed IP values, including equivalent IPv6 spellings. A value
exception removes that address/family; a bare `@@MASK$dnsrewrite` or
`@@MASK$dnsrewrite=` removes the whole supported set for identical coverage.
Identical normalized exact coverage accepts both `|name^` and `|name|`.

The resulting records are a frozen conversion. Exceptions are reported by source
path, resolved once and omitted from the native configuration. They do **not**
become ordinary allow rules. When the last address disappears, ordinary blocking
or upstream resolution resumes. When a family disappears but another survives,
queries for the removed family receive local NODATA. A disjoint exception is a
reported no-op. Adding a new native record later does not reactivate the source
exception; reimport to reevaluate source declarations.

A positive and exception mask that partially intersect remain blockers, even when
the exception value currently differs. For example, an exact exception under a
suffix rewrite needs an effect-aware engine; turning it into an allow rule would
change behavior. Unknown/scoped/important/badfilter effects remain blockers even
if a bare exception appears to cancel them. Surviving suffix address sets still
allow only one address per family. Canceled definitions are resolved before
surviving positive overlap, legacy-priority and family-count checks. Native schema,
versioned list syntax, legacy rewrite behavior and query processing are unchanged.

### Bundled block-filter feeds

Upload a ZIP containing exactly one `AdGuardHome.yaml`/`.yml` and the enabled
block-filter files named `filters/ID.txt` or `PREFIX/filters/ID.txt`:

```yaml
filtering:
  blocked_response_ttl: 29
filters:
  - id: 7
    enabled: true
    url: https://publisher.example/feed.txt
user_rules:
  - '|pool.home.arpa^$dnsrewrite=192.0.2.10'
```

For example, bundled `data/filters/7.txt` may contain:

```text
|pool.home.arpa^$dnsrewrite=192.0.2.20
|pool.home.arpa^$dnsrewrite=192.0.2.30
@@|pool.home.arpa|$dnsrewrite=192.0.2.10
```

The combined result is the two surviving addresses with TTL 29. Custom and bundled
block rules share one extraction/resolution pass, so same-coverage exceptions and
exact address sets work across files regardless of source ordering. Ordinary text
stays in separate native lists. Feed diagnostics use `filters[index].contents.lines[offset]`
with zero-based lines, preserving source location without echoing unknown values.
The existing 512 declaration and 256 source-owner budgets cover the entire import,
not each feed separately. Archive bounds remain 64 entries and 64 MiB expanded.

Exactly one file must match each active feed ID. Missing or ambiguous active block
feeds invalidate all extracted custom/feed rewrites, including during protection
pause. Repeated configured IDs or URLs require source deduplication review while
filtering is enabled; this includes disabled entries that could precede an active
duplicate in source startup. Nonpositive active IDs require migration review.
Rewrite-containing feeds require explicit `enabled: true`. Mixed source control/TTL
layouts are checked for feed-only imports as well as custom rules. Disabled feeds
and globally filtering-disabled feeds are not interpreted or activated. Archive
entries are still decompressed under the global ZIP size/entry bounds.

**This is a frozen import snapshot.** No HTTP fetch, live filter source or automatic
schedule is created. Publisher references remain reviewable metadata. To update
or remove converted rewrite effects, reimport the complete backup and review the
new native records. A generic ordinary-list download cannot reevaluate exceptions
or remove previously converted answers; native V6 lists still reject `$dnsrewrite`.
A later publisher removing a rewrite from its ordinary list does not remove the
native record. Whitelist-feed rewrites and separate allow-engine priority remain
blockers, as do the unsupported masks/scopes/effects listed below.

### Exact TXT/PTR/MX/SRV responses

```yaml
filtering:
  blocked_response_ttl: 31
user_rules:
  - '|service.home.arpa^$dnsrewrite=NOERROR;TXT;v=spf1 -all;fixture'
  - '|10.2.0.192.in-addr.arpa|$dnsrewrite=NOERROR;PTR;nas.home.arpa.'
  - '|mailing.home.arpa|$dnsrewrite=NOERROR;MX;10 mail.home.arpa'
  - '|service.home.arpa|$dnsrewrite=NOERROR;SRV;1 2 8443 service.home.arpa'
```

These exact responses work in custom rules and bundled enabled block feeds.
They may share an exact owner with A/AAAA and each other, with up to 32 distinct
records per type. The requested type is returned; an owner without that type
returns local NODATA. Targets are record data, not CNAME forwarding directives.
They are edited in the existing typed Local DNS editor after conversion.

| Type | Supported source value | Boundary |
| --- | --- | --- |
| TXT | One plain printable ASCII string, 0..255 bytes | Internal spaces/semicolons retained; comma, quote, backslash, dollar, edge whitespace and non-ASCII require review |
| PTR | ASCII hostname, optionally ending in one root dot | Native target normalized; source FQDN case retained separately for exception comparison |
| MX | Decimal preference plus ASCII exchange, one space | 0..65535; exchange has no root dot; source null-MX form requires review |
| SRV | Decimal priority, weight, port and ASCII target, single spaces | 0..65535 fields; target has no root dot; root target `.` supported |

Hostname labels contain alphanumerics/hyphens with valid boundaries and must pass
native DNS normalization. Invalid punycode targets fail during extraction and
clear the whole extracted set. Extra numeric/target fields and source lines with
trailing whitespace remain blockers. Native manual
TXT records still support their existing larger/chunked representation; import
does not silently split a source single TXT string longer than 255 bytes.

Bare same-coverage exceptions remove all supported effects. TXT and PTR value
exceptions remove only matching values; an empty TXT value exception removes only
empty TXT, not the whole set. Source PTR comparison is case-sensitive on the FQDN:
`NAS.home.arpa` and `NAS.home.arpa.` compare equal, while `nas.home.arpa` does not
cancel the uppercase source value. Native DNS target identity remains canonical;
surviving duplicates after normalization are blockers.

MX/SRV value exceptions remain blockers because the reviewed source comparator
uses pointer-valued responses. The importer does not substitute structural equality
and claim source compatibility. Ordinary blocking, frozen reimport requirements,
activation/client settings, layout/priority guards and combined budgets remain
unchanged. Unknown/unsupported effects still invalidate all extracted definitions,
even when a bare exception appears to cancel them. Schema 6 and native list syntax
V6 are unchanged; none of this parser runs on a DNS executor.

### Typed suffix responses

The same supported TXT/PTR/MX/SRV values also accept `||name^` suffix masks in
custom rules and enabled bundled block feeds. For example:

```yaml
filtering:
  blocked_response_ttl: 31
user_rules:
  - '||service.home.arpa^$dnsrewrite=NOERROR;TXT;fixture'
  - '||service.home.arpa^$dnsrewrite=NOERROR;PTR;nas.home.arpa.'
  - '||service.home.arpa^$dnsrewrite=NOERROR;MX;10 mail.home.arpa'
  - '||service.home.arpa^$dnsrewrite=NOERROR;SRV;1 2 8443 service.home.arpa'
```

This produces eight native records, covering the apex and descendants at any
depth. Replies carry the concrete question owner, never a literal `*` name.
Up to 32 distinct records per typed RRset are supported; suffix A/AAAA remain
one address per family. The source TTL, TXT single-string restrictions, PTR
source-case comparison and MX/SRV value-exception blockers apply unchanged.
Same-suffix whole/value exceptions resolve once across custom/feed declarations.
Exact/suffix partial exceptions and overlapping surviving patterns stay blockers.

The Local DNS editor exposes apex and wildcard rows separately. Editing a wildcard
changes descendant answers; it does not change the apex. A matched typed owner
answers only its requested records and returns NODATA for missing types. In
native manual configurations, typed owners override all question families while
address-only owners retain family-aware fallback. CNAME targets under wildcard
coverage and wildcard CNAME/passthrough remain rejected. Legacy AdGuard wildcard
`rewrites` entries remain address-only; this extends pattern response imports.

Schema 6 and list V6 are unchanged. Existing bounded maps, immutable compilation,
concrete-owner substitution and Hickory encoding are reused. Older binaries may
reject the expanded wildcard types; do not downgrade to a binary that cannot
validate the active configuration. CNAME pattern imports remain separate: the
[source resolves the rewritten question](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/dnsforward/filter.go) even for CNAME queries, while native
CNAME queries return local aliases. Copying an alias would not prove parity.

### Activation correction

Pattern rules depend on source `filtering_enabled`; they can remain active while
`protection_enabled` is false. The legacy `rewrites_enabled` switch affects legacy
entries, not these rule modifiers. The importer now distinguishes these controls.
Global filtering disable omits both legacy and pattern records. Explicit client
filtering disable with `use_global_settings: false` clears source records and
lists; inherited clients retain global settings. Independent SafeSearch settings
keep their existing handling. Previously, disabled filtering could leave legacy
records active; that defect is fixed.

A client re-enabling globally omitted source filtering requires explicit review
and is a blocker. Inactive definitions stay omitted, not stored as editable native
disabled entries. Address conversion freezes the supported source behavior into
native records; later source activation changes require another reviewed import.

Protection pause does not establish that downloaded blocklists have no active
rewrite rules. Their missing contents are now blockers while filtering stays on.
Supported bundled block-feed rewrites now stay active during protection pause;
ordinary downloaded rules remain omitted. Filtering-off and disabled feeds stay
inactive. Import never contacts publisher URLs.

### Compatibility and bounds

AdGuard aggregates matching pattern answers; native local records select exact
or nearest overrides. Disjoint exact owners now aggregate distinct address values
into native RRsets. Overlapping surviving patterns, mixed exact/suffix owners, duplicate addresses,
legacy owner/alias-target coverage and separate allowlist-engine priority cannot
be silently approximated. Those combinations stay blockers. Some legacy overlap
checks intentionally reject conservative boundary cases rather than claiming
complete source precedence.

Regex rewrites and ambiguous rewrite-like regex option text, other masks, response codes, aliases/CNAME, HTTPS/SVCB forms outside the single-alias or ServiceMode/optional-port subset and other unsupported RR types, IPv4-mapped IPv6
ambiguity, partial exceptions, additional type/client/tag/domain modifiers and `$badfilter`
remain unsupported. An unsupported recognized rewrite or conversion conflict
omits every extracted custom/bundled pattern definition from the draft. Ordinary
rules still receive normal validation. Whitelist-feed effects remain unsupported;
the separate allow-engine priority guard still applies.

Limits: 512 rewrite declarations including exceptions, 256 distinct source owners
including canceled/no-op definitions, 4096 bytes per rewrite line;
existing 10000 combined local records, 256 policies and 64 MiB expanded import budgets
also apply. Legacy count is checked before bounded overlap comparisons. YAML/JSON/
ZIP parser/input/output limits remain in force. Source array/line paths and bounded
compatibility diagnostics are retained without echoing unknown values. Records
retain policy/generation/configuration provenance; original source modifier text
is not a new historical query field or a round-trip export representation.

Schema 6, syntax V6 and all older native/list interpreters are unchanged. No parsing,
JSON, database, filesystem, HTTP or plugins were added to a DNS executor. Use the
migration report, inspect the translated configuration, then edit under Local DNS
& routes, validate, stage and review promotion. Suffix conversion makes apex and
descendant records independently editable; changing one does not change the other.
Ordinary blocked replies and legacy records retain existing native TTL semantics,
with a source-TTL warning; there is no general block-TTL parity claim.

### Primary source basis

AdGuardHome commit `8dedd3278542b45ea21994e24422f5cc53e14b8f`:

- [Filtering and activation](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/filtering/filtering.go)
  gates legacy rewrites with filtering and processes rule rewrites before skipping
  ordinary results during protection pause. A separate allowlist engine can run first.
- [Rule response aggregation](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/filtering/dnsrewrite.go)
  combines RR values; CNAME/RCODE behavior needs separate semantics.
- [Typed reply construction](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/dnsforward/dnsrewrite.go)
  selects only the requested RR type, including NODATA.
- [Reply TTL](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/dnsforward/msg.go)
  reads raw BlockedResponseTTL; SOA has its own zero fallback.
- [Source layout migration](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/configmigrate/v26.go)
  moves filtering controls and TTL out of DNS settings.

[Feed storage and identity handling](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/filtering/filter.go)
and the filtering engine above establish the reviewed file layout, URL
deduplication and common block engine. The importer conservatively rejects
ambiguous source identities instead of reproducing every startup migration.

The matching urlfilter dependency is pinned to `v0.23.4` in the reviewed AdGuard
source. Its [DNS result handling](https://github.com/AdguardTeam/urlfilter/blob/v0.23.4/dnsresult.go)
and [exception comparison](https://github.com/AdguardTeam/urlfilter/blob/v0.23.4/dnsrewrite.go)
apply whole/value cancellation to rewrite effects, separate from ordinary allow
rules. The supported converter excludes important/scoped rules and partial masks.

The same dependency's [typed response parser](https://github.com/AdguardTeam/urlfilter/blob/v0.23.4/rules/dnsrewrite.go)
and [modifier parser](https://github.com/AdguardTeam/urlfilter/blob/v0.23.4/rules/network.go)
establish the restricted typed subset. AdGuard's typed reply construction above
uses one TXT character string and source reply TTL. Original target case is used
only where source exception comparison needs it; native records keep canonical names.

This is a verified subset, not reproduction of every source schema migration.

## Per-client upstream conversion

### Grounding and boundaries

Previously the importer cloned global policy to every client and reported non-empty
client upstreams as unsupported. The global converter parses literal IP/
port sets, supported literal suffix routes and matching destination DoT/DoH URLs.
Management parsing/preview run on bounded blocking workers; durable publication,
assertions, listener/self-forward validation and client CIDR admission stay intact.

Checked primary source: AdGuard Home revision
8dedd3278542b45ea21994e24422f5cc53e14b8f,
[custom configuration](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/client/upstreammanager.go),
[request selection](https://github.com/AdguardTeam/dnsproxy/blob/v0.86.0/proxy/proxy.go).
A usable custom upstream configuration is independent of use_global_settings
(which controls filtering). Empty/comment-only declarations inherit global routing.
Custom defaults handle all otherwise unmatched queries. Routes-only custom choices
fall back to global routing where no custom route matches. A custom route takes
precedence even over a more-specific global route underneath its suffix.

### Smallest implementation

Keep the existing global converter and add an internal client adapter. Parse every
client upstream value as a string array, capped at 256 declarations. Use original
destination profiles for encrypted identity/port/path/trust lookup, never newly
imported profiles as bootstrap trust. Build bounded temporary profiles (at most
289 including the 32 destination profiles), then merge required candidates into
a clone of the current registry. Reuse profiles only when ordered addresses,
transport/trust/pool settings and deadline are identical. Generate unique names
when an imported name conflicts; do not replace another client's/global profile.
Keep the published registry bounded to 32. Commit a client's profile/route change
only after every declaration and combined route shape passes validation.

An explicit client default removes inherited global routes and uses only its own
routes. A routes-only client keeps the global default and global routes except
those covered by custom routes; merge the custom routes with suffix boundaries.
This prevents a more-specific global route from overriding the client's broader
custom suffix. Unsupported/mixed/ambiguous declarations or budget overflow retain
the complete inherited default/routes and add a blocker, with no partial profile
mutation. Track the generation's actual 4096-route budget before cloning further
client policies. Missing/empty client IDs are blockers; unsupported identities are
reported without inventing source-IP bindings. Client cache booleans/sizes are
validated even when unused; native bounded resolver-identity sharing and source
per-client cache/disable/size behavior are explicitly different operational settings.

Alternative: rewrite DNS selection or share AdGuard's resolver implementation.
Rejected: existing compiled policies already implement the supported address/
identity/suffix behavior; DNS correctness and current contracts stay unchanged.
No third-party implementation is copied.


New AdGuard imports select parent-name DS routing as described in [local DNS](local-dns.md). Unsupported identities, transport/trust mixes and bootstrap discovery remain blockers.
