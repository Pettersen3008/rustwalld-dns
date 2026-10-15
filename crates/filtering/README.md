# rustwalld-dns-filter

Immutable exact/suffix DNS matching with allow precedence and rule provenance.
Compilation performs normalization, validation and deduplication; evaluation is
pure and accepts **lowercase ASCII names without a trailing root dot**.
Normalize untrusted user input on the control plane, outside the query loop.

```rust
use rustwalld_dns_filter::{normalize, Action, FilterSnapshot, ListInput};
let filters = FilterSnapshot::compile(&[
    ListInput { syntax: Default::default(), name: "ads".into(), action: Action::Block, rules: "ads.test".into() },
    ListInput { syntax: Default::default(), name: "exceptions".into(), action: Action::Allow, rules: "=safe.ads.test".into() },
], 100, 4096)?;
assert_eq!(filters.evaluate("child.ads.test").action, Action::Block);
assert_eq!(filters.evaluate("safe.ads.test").action, Action::Allow);
assert_eq!(normalize("SAFE.Ads.Test.")?, "safe.ads.test");
# Ok::<(), rustwalld_dns_filter::CompileError>(())
```

Lines beginning with `=` match exactly; other domain rules match the name and its
subdomains. Evaluation walks the name once towards the root; any matching allow
rule wins over every block rule. Invalid lines are reported in list statistics. Rule identifiers and
provenance belong to this snapshot: preserve its lifetime when retaining results.
Input rule and byte limits are explicit. This crate has no networking, database,
HTTP or application dependency. Rust 1.95+, edition 2024; MIT OR Apache-2.0.

The optional `parallel` feature adds an owned `ParallelCompiler`. Create one on
the control plane, bound compilation admission, and reuse it for large lists.
`FilterSnapshot::compile` remains sequential. Worker counts are explicitly bounded
to 1–4; no global pool is used. IDs, provenance, errors and decisions match the
sequential path. Small lists use sequential work; parallel parsing can retain
extra allocator memory, so benchmark the workload and DNS latency on your host.

```rust
# #[cfg(feature = "parallel")]
# fn example() -> Result<(), Box<dyn std::error::Error>> {
use rustwalld_dns_filter::{Action, ListInput, ParallelCompiler};
let compiler = ParallelCompiler::new(2)?;
let filters = compiler.compile(&[ListInput { syntax: Default::default(),
    name: "ads".into(), action: Action::Block, rules: "ads.test".into(),
}], 100, 4096)?;
assert_eq!(filters.evaluate("child.ads.test").action, Action::Block);
# Ok(())
# }
```

`RuleSyntax::AdguardV2` adds compile-time cancellation by a sole `$badfilter` on
supported anchored masks and regex rules. Cancellation matches literal pattern
text and effective action across V2 lists before deduplication. Native/legacy
AdGuard lists and the query evaluator remain unchanged. V2 comments occupy their
own line; hosts/bare domains and mixed modifiers cannot be cancellation targets.
Raw budgets include cancelled lines and declarations; at most 65,536 potential
declarations are accepted. `cancellations()` reports the first 200 distinct targets
with up to five directive/disabled source samples each; `cancellation_targets()`
and per-list `badfilters`/`disabled` retain complete counts. Keep the revision text
for complete provenance. Removing an allow exception can expose a block.

`RuleSyntax::AdguardV3` adds sole `$denyallow=domain|domain` on basic network
masks/regex. Exclusions cover apex and descendants of one rule; they never
generate global allows. Rule identity includes sorted normalized exclusions.
512 unique scoped rules, 64 declared domains per line and 8192 retained domains
bound the added immutable candidate indexes. Unsupported combinations fail
validation. V2/legacy semantics remain frozen; see [the design](../../docs/architecture/filtering.md).


Opt-in `RuleSyntax::AdguardV4` supports bounded DNS type selectors, optionally
combined with per-rule domain exclusions. `evaluate_type(name,u16)` selects
question/CNAME rules and `evaluate_value(address,u16)` selects only explicit V4
numeric masks/regexes for response values. Callers supply normalized ASCII names
or canonical address values. `evaluate` defaults to A. Immutable `Rule::scope`
reuses the optional scope pointer; `denyallow()` / `dnstype()` expose restrictions.
Old syntax interpretations stay frozen. See [type-rule design](../../docs/architecture/filtering.md).
