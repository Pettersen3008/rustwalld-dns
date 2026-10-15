# rustwalld-dns-policy

Assertion-gated immutable DNS policy compilation, client admission/selection,
rewrites, optional versioned SafeSearch, temporary exceptions and rule provenance. Serializable input values
remain editable; compiled snapshots expose read-only accessors.

```rust
use rustwalld_dns_policy::{PolicyConfigSet, PolicySnapshot};
let config = PolicyConfigSet::default();
let snapshot = PolicySnapshot::compile(config, 1)?;
let result = snapshot.explain("127.0.0.1".parse()?, "example.test")?;
assert_eq!(snapshot.generation(), 1);
assert_eq!(result.decision.action, rustwalld_dns_filter::Action::Allow);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Compile on a blocking/control executor. Required assertions must pass before a
snapshot is returned; `PolicySnapshot::check` reports all assertion outcomes
without publication. Generation identifiers are supplied by the host and must
never be reused for changed content. Rollback recompiles under a fresh identifier.
Snapshots contain bounded forwarding resources; compilation does not resolve DNS.
Policies with identical list inputs share one compiled filter set. Combined list
text is capped at 256 MiB and distinct compiled rules at 10,000,000 per snapshot.
The library does not load files, start an HTTP server or open a database.
Rust 1.95+, edition 2024; MIT OR Apache-2.0.

With the optional `parallel` feature, `compile_parallel` and `check_parallel` use
an explicit `rustwalld_dns_filter::ParallelCompiler`. Keep the pool on the control
plane and bound concurrent compilation. The same validation and assertion gates
apply; default constructors remain sequential even when this feature is enabled.

`PolicyConfig.safe_search: Option<SafeSearchConfig>` defaults to `None` in serialized
inputs; Rust struct literals must supply the field. Catalog 1 offers independent
Google/Bing/DuckDuckGo flags and `YouTubeMode::{Off, Moderate, Strict}`. Compilation
shares identical maps, rejects unknown catalogs and conflicting local owners, and
performs no provider lookup. Explanations include optional `SafeSearchMatch`
provenance. See [coverage and precedence](../../docs/architecture/policy.md).

`PolicyConfig.blocked_services: Option<BlockedServices>` defaults absent. Rust
struct literals must supply the field. Catalog v1 accepts the unique IDs `youtube`,
`tiktok`, `reddit` and `discord`; unknown versions/IDs and duplicate IDs are errors.
`filter_inputs()` borrows disabled raw lists or expands selected groups in stable
catalog order. For scheduled history, use `filter_inputs_for_services(active)`
with the recorded state so rule IDs map to the variant that produced the reply.
Generated lists use reserved `@service/` provenance and the existing filter/rule
budget; identical expanded inputs share one filter set. Distinct service choices
can produce distinct regex sets and still obey the eight-set limit. Public
`service_catalog()` exposes the frozen exact/suffix coverage. See
[limits and precedence](../../docs/architecture/policy.md).

`BlockedServices.schedule: Option<WeeklySchedule>` defaults absent in serialized
input; Rust literals must provide it. A schedule requires a bundled IANA
`time_zone`, explicit `windows` (up to 32) and `ScheduleMode::{Block, Allow}`.
Windows have unique `ScheduleDay` values and HH:MM start/end times; end permits
24:00. Compilation creates shared 10080-minute bitmaps and both service-on/off
filter sets. Those sets spend the existing total rule/regex budgets and may
increase memory for large custom lists; identical variants share an Arc.
`CompiledPolicy.filters()` is the permanent service-on view used by assertions.
Serving hosts select `filters_for_services()` from `service_schedule_at()` and
must recheck completion/cache/CNAME semantics as core does. `explain_at()` accepts
a trusted instant for control-plane previews; `explain()` uses the current clock.
`ServiceScheduleState` and `SCHEDULE_TZDB_VERSION` expose durable state and deployed
data identity. See [schedule semantics and integration](../../docs/architecture/policy.md).

Catalog v2 adds Netflix, Spotify, Twitch, Steam, Roblox, WhatsApp, Telegram and
Signal (12 groups/21 domain rules total), with bounded provider references and
coverage notes. `LATEST_SERVICE_CATALOG_VERSION` is 2;
`service_catalog_for_version(2)` returns explicit coverage. `service_catalog()`
and omitted serialized versions retain v1. No existing input is upgraded or
changed automatically. `ServiceDefinition` Rust literals now need `limitations`
and `references`; these empty fields are omitted from v1 serialization. Generated
list provenance includes the chosen catalog version. See [catalog compatibility
and scope](../../docs/architecture/policy.md).

`PolicyConfig::ds_routing` defaults to `DsRouting::Question`; old serialized inputs
omit the setting. `Parent` selects a strict ancestor route for type DS only.
Use `CompiledPolicy::upstream_for_query` and `PolicySnapshot::explain_query` when
the question type matters. Name-only/A methods retain their existing behavior.
Explicit parent mode does not validate DNSSEC. Rust struct literals must include
the new field; `PolicyConfigSet::default()` continues to construct native defaults.
