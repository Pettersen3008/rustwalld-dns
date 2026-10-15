# Local DNS and conditional routing

Local records and route choices compile into immutable policies. The current HTTPS/SVCB contract includes AliasMode and optional numeric `port`; other service parameters and complete alias graph validation remain open.

## Exact family rewrite passthrough

A homelab name can return a local IPv4 address while resolving IPv6 normally.
An exact family passthrough directive suppresses the local rewrite only for A
or AAAA. Ordinary filters, explicit allows, live temporary exceptions, SafeSearch,
conditional routes and response inspection still apply. This is never an
allowlist entry or a DNS record sent on the wire.

```json
{
  "dns_records": [
    {"domain":"nas.home.arpa","ttl":60,"data":{"type":"A","address":"192.0.2.10"}},
    {"domain":"nas.home.arpa","ttl":60,"data":{"type":"PASSTHROUGH","family":"AAAA"}}
  ]
}
```

This fragment belongs inside a policy. Names normalize to ASCII exact owners;
subdomains do not inherit the directive. The directive's TTL is ignored. Other
question types retain their local answers or NODATA. A matching directive wins
against address records of the same family, independent of declaration order.
It may also coexist with the older `rewrites` address representation. Duplicate
family directives and a CNAME sharing its owner with a directive fail validation.

For an alias chain ending at a passthrough owner, the matching family suppresses
the entire local chain. The engine filters and resolves the original question,
using its routes, rather than resolving the local alias target. The other family
retains its local chain. Loops and the existing chain limit remain compile errors.

The Local DNS & routes editor exposes “Family passthrough” with an explicit
IPv4/IPv6 selector. The usual validate, shadow, review and promote flow applies.
Typed explanations, permanent assertions, post-wait exception/schedule checks and
shadow comparison use the actual question type. `has_rewrite` remains an owner
inventory API; integrations deciding a question use `has_rewrite_for` or `rewrite`.

### Source compatibility

Enabled exact **legacy `filtering.rewrites` or older `dns.rewrites`** entries whose answer is `A` or
`AAAA` now translate into native directives. Disabled entries remain inactive.
Global definitions are inherited by imported client policies within the existing
record and expanded-input budgets. Ordinary source filters can still block the
passthrough family; importing a directive never inserts an allow rule.

Semantics were checked against AdGuard Home commit
[`8dedd3278542b45ea21994e24422f5cc53e14b8f`](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/filtering/filtering.go)
(`CheckHost`, `processRewrites`, `handleRewriteLoop`) and
[legacy record matching](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/filtering/rewrites.go).
The [schema-26 migration](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/configmigrate/v26.go)
moves these entries from `dns.rewrites` to `filtering.rewrites`; both locations use
the legacy semantics. The prior location-specific “modern suffix exception”
blocker was incorrect and is removed. The separate rewrite/storage implementation
is not evidence of different semantics for the old configuration location.

`filtering.rewrites_enabled: false` omits all source rewrite definitions while
ordinary filtering remains active. Explicit malformed controls and ambiguous
mixed-layout controls are rejected or blocked. Pre-31 schemas explicitly declaring
a disabled entry cannot claim source-equivalent activation. See
[rewrite source layouts](migration.md) for the verified migration path.
Unsupported wildcard types, same-owner CNAME/directive combinations and full pattern `$dnsrewrite`
forms outside the supported subset in the migration contract remain unsupported.
This is a supported-subset translation, not complete
source rewrite compatibility.

### Safety and recovery

The compiler builds a two-bit family mask in each immutable local-answer entry.
There is no additional query-path parser, scan, allocation, file, database, HTTP,
JSON or plugin operation. Existing caches, routes, connections and telemetry
limits apply. New generations continue to distinguish changed policy content;
raw upstream answers are re-evaluated against each current generation.

The tagged payload is additive and needs no SQLite schema migration (schema 6).
Older binaries reject the unknown payload instead of silently changing behavior.
Downgrading requires a compatible saved configuration/backup. Stored revisions,
restart, rollback-as-a-new-generation and native/container backup recovery retain
the directive and its question-specific behavior. Policy changes cannot recall
answers already cached by a client.

## Descendant wildcard local records

A/AAAA local records can now use `*.home.arpa`. This gives descendants a shared
address while retaining exact overrides, reviewed imports and bounded immutable
policy generations. It is a supported subset of AdGuard legacy rewrite behavior.

### Configuration and matching

```toml
[[policy.policies.dns_records]]
domain = "*.home.arpa"
ttl = 60
data = { type = "A", address = "192.0.2.10" }

[[policy.policies.dns_records]]
domain = "*.home.arpa"
ttl = 60
data = { type = "AAAA", address = "2001:db8::10" }

[[policy.policies.dns_records]]
domain = "nas.home.arpa"
ttl = 60
data = { type = "A", address = "192.0.2.20" }
```

| Question | Result |
| --- | --- |
| `apps.home.arpa A` | `192.0.2.10`, owned by `apps.home.arpa` |
| `apps.nas.home.arpa A` | `192.0.2.10` |
| `nas.home.arpa A` | Exact address `192.0.2.20` |
| `nas.home.arpa AAAA` | Wildcard family fallback `2001:db8::10` |
| `home.arpa A` | No wildcard match; ordinary policy/upstream |
| `badhome.arpa A` | No wildcard match |
| `apps.home.arpa TXT` | Local NOERROR/NODATA |

A leading `*.` matches descendants at any depth and excludes its suffix apex.
The most specific matching wildcard containing the requested address family wins;
an exact address of that family wins first. A matched owner without an eligible
family still gives local NODATA. Exact CNAME, other typed records and family
passthrough retain their owner precedence. Passthrough resumes ordinary filtering
for its family. Local address answers override filtering, as exact local records
already do; other requested types receive local NODATA.

Replies use the original concrete question owner and preserve its case. A literal
escaped dot inside a label cannot create a false suffix match. This is policy
rewriting, not RFC4592 authoritative-zone wildcard synthesis; there are no
empty-nonterminal, zone-existence or authoritative wildcard semantics.

### Conservative validation and imports

Wildcard TXT/PTR/MX/SRV and HTTPS/SVCB ServiceMode RRsets support up to 32 distinct records per type, with
a uniform TTL and the same payload validation as exact native records. A matched
owner containing one of these types overrides all question types; missing types
return NODATA instead of falling back to an ancestor. Address-only owners retain
the family fallback above. Native wildcard records exclude the apex. Supported
AdGuard pattern imports create independently editable apex and descendant records;
legacy wildcard imports remain address-only. See [pattern imports](migration.md).

Only one A and one AAAA address per wildcard owner are supported. Additional
addresses, wildcard CNAME, wildcard passthrough and other `*` patterns
are rejected before publication. CNAME chain targets under wildcard coverage are
also rejected, including otherwise exact terminals: the existing precompiled
chain representation cannot safely choose family-dependent wildcard terminals.
An exact alias owner may lie under a wildcard if its targets are outside wildcard
coverage. Overlap with enabled SafeSearch owners/targets is rejected.

Legacy AdGuard `dns.rewrites` and `filtering.rewrites` retain their version/layout,
global-activation and enabled-entry guards. Supported active wildcard address
entries become native records in all inherited client policies. Inactive entries
stay omitted. Source wildcard owners must be ASCII without a trailing root dot;
converting IDNA/root-dot input could change source matching. Native names still
use the normal configured-name normalization. Unsupported or ambiguous imports
produce blockers; preview never publishes.

The source basis is AdGuardHome commit `8dedd3278542b45ea21994e24422f5cc53e14b8f`:
[legacy matching and finalizeRewrites](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/filtering/rewrites.go),
[rewrite tests](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/filtering/rewrites_internal_test.go)
and [query handling](https://github.com/AdguardTeam/AdGuardHome/blob/8dedd3278542b45ea21994e24422f5cc53e14b8f/internal/filtering/filtering.go).
The source filters entries by question type before selecting exact/most-specific
wildcards, then truncates wildcard answers to one entry. Duplicate-address order
is therefore blocked rather than approximated. This does not implement modern
storage exceptions, full `$dnsrewrite`, general source schema migrations or
source priority rules conflicting with the repository's allow-first contract.

### Runtime and operations

Compilation separates exact owners and wildcard suffixes into ordinary hash
maps. The query path borrows label suffixes, skips presentation escapes and makes
bounded lookups without scanning configured entries, allocating wildcard strings,
parsing configuration or accessing storage. Existing owner/TTL/config budgets
apply. Hickory still parses and encodes DNS. Local wire replies retain the
existing allocations; concrete wildcard owners require cloning the question name.

Shadow comparison now includes compiled answer content, template owner and TTL,
so address/TTL/pattern changes are visible before promotion even when both
policies still rewrite. The active answer remains unchanged. Original request,
policy and generation identifiers remain in history; stored configuration retains
the wildcard owner. There is no new matched-pattern field in historical telemetry.
Rollback uses a fresh generation; cache and pending work keep existing isolation.
Schema6 and rule syntaxV6 remain unchanged. Older binaries may reject newly supported wildcard
owners; validate restored policies with the intended binary before downgrading.

Use Policies → Local DNS & routes to edit, validate, stage and review promotion.
The editor describes apex, family and alias limits. DNSSEC validation remains an
upstream responsibility; optional Unbound remains the validating recursive resolver.

## HTTPS and SVCB service records

Local DNS supports HTTPS/SVCB **AliasMode and ServiceMode** records, at exact
owners and leading `*.` descendant owners. They describe a service endpoint;
they do not configure an HTTPS listener, encrypted DNS, certificates or DNSSEC
validation. The client decides how to use these records.

For a native policy's `dns_records`:

```json
[
  {"domain":"service.home.arpa","ttl":31,"data":{"type":"HTTPS","priority":0,"target":"endpoint.home.arpa"}},
  {"domain":"*.service.home.arpa","ttl":31,"data":{"type":"SVCB","priority":2,"target":"endpoint.home.arpa","params":{"port":8443}}}
]
```

Priority is an integer in 0..65535. Priority **0 (AliasMode)** aliases only the
requested service type to another name; clients perform their own follow-up
queries. An HTTPS alias never aliases A, AAAA or SVCB questions. One alias per
owner/type is supported, without mixing ServiceMode records in that RRset.
Target `.` at priority 0 is **advisory service unavailability**; clients may ignore
it and fall back, so it is not an ad-blocking or access-control mechanism.

Priorities **1..65535 (ServiceMode)** describe endpoints. Target `.` remains the
root name on the wire; the recipient uses the **service record's owner** as the
effective target. This includes the concrete synthesized owner of a wildcard answer. After a native
CNAME chain, it means the terminal service record's owner, which can differ from
the original question. Other targets use existing native DNS name normalization.
No endpoint address lookup, service-parameter discovery or target forwarding is
performed while compiling or answering these local records.

ServiceMode accepts one optional typed parameter: `params: {"port": 8443}`.
Its integer range is 0..65535, including an explicit port 0. Without `port`, the
client keeps its original service/authority port; absence and zero are distinct.
The parameter advertises a destination port. It does not open a listener, change
a firewall or configure TLS. Clients may reject ports according to their own
protocol/security rules.

Native `params` must be an object containing only the optional numeric `port`.
Omitted/empty parameters (including `port: null`) serialize without a `params`
field. Arrays, null `params`, duplicate keys, unknown keys, strings, fractions and
out-of-range ports are rejected. AliasMode rejects every nonempty parameter set,
including `port: 0`, rather than silently ignoring it. ALPN, ECH, mandatory,
address hints, DoH path and arbitrary raw parameters remain unsupported. Import
never drops them. Use a compatible upstream for forms outside this subset.
This is not a complete implementation of
service discovery or all RFC 9460 client behavior. The server returns the local
alias record without chasing it or populating Additional records. Client
follow-up queries use ordinary DNS policy processing. Obvious exact self aliases
and wildcard targets that could alias their own synthesized owner are rejected,
including normalized case variants. Cross-owner cycles, mixed CNAME/service
alias cycles, remote targets and complete alias graphs are not validated here;
clients must bound their own resolution. These are distinct from native CNAMEs,
which retain their existing compile-time chain/loop validation.

### AdGuard imports

Custom rules and enabled block-filter files bundled in a ZIP accept these forms:

```yaml
schema_version: 34
filtering:
  blocked_response_ttl: 31
user_rules:
  - '|exact.home.arpa^$dnsrewrite=NOERROR;HTTPS;0 endpoint.home.arpa'
  - '||service.home.arpa^$dnsrewrite=NOERROR;SVCB;65535 endpoint.home.arpa port=65535'
```

Exact masks create one owner. `||name^` creates separate apex and descendant
records. Source priority and TTL are preserved, including TTL 0. Import accepts
a decimal priority and ASCII hostname or `.`, optionally followed by a single
lowercase `port=DECIMAL` for ServiceMode. Fields use one literal space. Ports are
ASCII digits in 0..65535; leading zeroes normalize to the same numeric value.
Target root dots, extra fields/whitespace, quoted/escaped/duplicate/unknown
parameters, scopes, AliasMode parameters and ambiguous mixed/multiple alias
RRsets are blockers. Targets must pass native
DNS normalization before any extracted set is emitted. Unknown values are not echoed in compatibility issues.

Whole same-coverage exceptions (`@@MASK$dnsrewrite` or `@@MASK$dnsrewrite=`)
remove all supported rewrite effects. Value-specific HTTPS/SVCB exceptions remain
blockers because the reviewed source stores pointer-valued data; native structural
equality is not substituted for source comparisons. Unsupported parser forms
still block the complete extracted set even when a whole exception appears to
cancel them. Partial/overlapping masks, legacy/whitelist priority and all shared
source/layout/activation/client guards remain as described in
[pattern rewrite imports](migration.md).

Whole exceptions resolve before native RRset/self-target admission. A canceled
syntactically supported but inadmissible RRset emits nothing; unsupported parser
forms still block all extraction even when a whole exception is present.

Conversion is frozen. Review the result under Local DNS & routes, edit apex and
descendant rows independently, validate, stage and review promotion. Reimport a
complete source backup to reevaluate effects and exceptions; ordinary list
refresh cannot update or remove these converted records.

### Native selection and bounds

These records may coexist with A/AAAA/TXT/PTR/MX/SRV at the same owner. The
requested type is returned; absent types receive local NOERROR/NODATA. A typed
owner overrides all question types instead of falling back to an ancestor's
records. Address-only family fallback is unchanged. CNAME cannot coexist at the
same owner, and CNAME targets under wildcard coverage remain rejected.

Existing constraints apply: one AliasMode record per owner/type or up to 32
distinct ServiceMode records per RRset with one TTL, 0..86400
seconds TTL, 10000 combined local records, immutable generations, assertion-gated
publication and fresh-generation rollback. Suffix addresses retain one per family.
Import also shares the 512 declaration, 256 owner and expanded-input budgets.
Large answers use existing bounded UDP truncation/TCP response handling.

Schema 6 and list V6 are unchanged. Older binaries reject the new local data
variants, and ServiceMode-only binaries reject priority 0; downgrade requires a
compatible configuration/backup. Rust embedders
constructing `LocalData::Https`/`Svcb` must now supply a `params: ServiceParams`
field (`Default::default()` preserves parameter-free behavior). This is a Rust
source compatibility change in the 0.1 API; `ServiceParams` is exported by policy.
Old native JSON/TOML without params remains valid; older binaries reject params.
Embedders with exhaustive `LocalData` matches must add `Https` and `Svcb` arms. No DNS library
depends on app, and no JSON/config parsing, HTTP, database work or plugin execution
was added to the DNS path. Hickory handles the new RDATA encoding.

Protocol references for service modes/targets and port encoding:
[RFC 9460 modes](https://www.rfc-editor.org/rfc/rfc9460.html#section-2.4),
[root targets](https://www.rfc-editor.org/rfc/rfc9460.html#section-2.5),
[port parameter](https://www.rfc-editor.org/rfc/rfc9460.html#section-7.2).
Source-import equivalence remains the restricted subset described above, rather
than a claim that every source syntax or service parameter is supported.

## DS resolver routing

Design, 2026-10-13. Close the AdGuard DS delegation-routing gap without changing
existing policy defaults or the question/filter/cache identity. Compile the choice
into immutable generations; no new dependencies, DNS parser or database schema.

### Grounding and design

Native `CompiledPolicy::upstream_for` selects the most-specific Hickory suffix for
an actual lookup name, regardless of question type. The engine passes the actual
lookup question, after any local/provider alias. Response-cache/inflight identity
already includes full resolver identity and question name/type/flags. Policy decisions
and pinned generations are separate; an unchanged resolver can reuse raw answers. Explanations
currently assume type A even for a selected history row of another type.

AdGuard dnsproxy [v0.86.0 selection](https://github.com/AdguardTeam/dnsproxy/blob/v0.86.0/proxy/proxy.go)
and [DS routing](https://github.com/AdguardTeam/dnsproxy/blob/v0.86.0/proxy/upstreams.go)
select custom/global upstreams using the DS question's parent name. Filtering and
the forwarded question remain unchanged. Client overlay precedence already maps
into the native route list. No third-party implementation is copied.

Add per-policy `ds_routing = "question" | "parent"`. Absent/default question mode
preserves existing native/backup behavior and omits serialization. AdGuard imports
explicitly choose parent mode, inherited by client policies; Pi-hole conversion
stays unchanged. Existing saved imports are not rewritten automatically. Remove
only the resolved DS compatibility blocker, preserving all other source blockers
and operational cache/failover warnings. Old binaries reject the new explicit field;
keep a compatible pre-upgrade backup when downgrading.

Add `CompiledPolicy::upstream_for_query(Name, RecordType)` while preserving the
existing name-only method. Parent DS mode considers strictly ancestral matching
zones, excluding a route equal to the queried name; this is equivalent to routing
the Hickory parent. Use Hickory `zone_of` plus name-length ordering, not
text splitting or `num_labels` (which treats wildcard labels specially). No parent
name needs construction on the query path. Empty/root/single-label names select
the default unless an existing valid parent route matches. The original question,
local overrides, original-name filtering and alias safety checks remain intact.

Add typed explanation methods with old A wrappers preserved. `/api/v1/explain`
accepts optional numeric `qtype` (default A=1), and query-log current explanations
send the selected row's type. Local/provider alias selection uses that same type.
The route editor exposes the per-policy choice with DNSSEC-validation boundaries;
import review shows the chosen mode. No resolver contact occurs on explanation.

Alternative: switch all native routes to parent DS semantics. Rejected because it
would silently change saved policies, native local DNS behavior and old imports.
A source-specific fork in the DNS engine is unnecessary; the compiled policy owns
one explicit protocol-routing choice. No cache-key extension is needed: the chosen
upstream identity separates raw answers and immutable generations separate policy
decisions. Changing routing never reuses another resolver's raw answer.

### Done predicate

Prove name-only/backward-compatible behavior and parent selection at zone apex,
nested/deeper/sibling/single-label/root and escaped/wildcard-label boundaries.
Cross-check the new selector against Hickory parent-name routing. Prove local DS
answers and original-name blocks avoid resolver I/O; DS questions forwarded unchanged
and cached independently by resolver/type/generation. Cover custom client defaults,
route-only source precedence, shadow/promotion/rollback and durable restart/backup.
Verify typed/default/malformed API explanations and selected history row UI types,
policy scope, migration ready status and explicit reviewed UI publication.
Run strict local Rust/Bun/consumers/MSRV checks, audit/deny and seeded engine/parser
fuzzing. Measure the existing DNS workload against the saved baseline and retain
all outliers; add a local DS route workload. Verify the release package in isolated
native/container fixtures. Actual host sandbox, ARM, long real-network soak and
independent security review remain separate release gates.
