# rustwalld-dns-filter

Immutable exact/suffix DNS matching with allow precedence and rule provenance.
Compilation performs normalization, validation and deduplication; evaluation is
pure and accepts **lowercase ASCII names without a trailing root dot**.
Normalize untrusted user input on the control plane, outside the query loop.

```rust
use rustwalld_dns_filter::{normalize, Action, FilterSnapshot, ListInput};
let filters = FilterSnapshot::compile(&[
    ListInput { name: "ads".into(), action: Action::Block, rules: "ads.test".into() },
    ListInput { name: "exceptions".into(), action: Action::Allow, rules: "=safe.ads.test".into() },
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
let filters = compiler.compile(&[ListInput {
    name: "ads".into(), action: Action::Block, rules: "ads.test".into(),
}], 100, 4096)?;
assert_eq!(filters.evaluate("child.ads.test").action, Action::Block);
# Ok(())
# }
```
