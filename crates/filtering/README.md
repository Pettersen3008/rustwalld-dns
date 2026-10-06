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
subdomains. Invalid lines are reported in list statistics. Rule identifiers and
provenance belong to this snapshot: preserve its lifetime when retaining results.
Input rule and byte limits are explicit. This crate has no networking, database,
HTTP or application dependency. Rust 1.95+, edition 2024; MIT OR Apache-2.0.
