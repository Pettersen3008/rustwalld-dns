#![doc = include_str!("../README.md")]
mod compile;
#[cfg(feature = "parallel")]
mod parallel;
#[cfg(feature = "parallel")]
pub use parallel::{ParallelCompiler, PoolError};

use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Block,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Matcher {
    Exact,
    Suffix,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListInput {
    pub name: String,
    pub action: Action,
    pub rules: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct Source {
    pub list: Arc<str>,
    pub line: usize,
}
#[derive(Clone, Debug, Serialize)]
pub struct Rule {
    pub id: u32,
    pub action: Action,
    pub matcher: Matcher,
    pub domain: Arc<str>,
    pub sources: Vec<Source>,
    pub redundant: bool,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct ListStats {
    pub name: String,
    pub raw: usize,
    pub unique: usize,
    pub duplicates: usize,
    pub invalid: usize,
    pub redundant: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct Decision {
    pub action: Action,
    pub rule: Option<u32>,
    pub matcher: Option<Matcher>,
}
impl Decision {
    pub const ALLOW: Self = Self {
        action: Action::Allow,
        rule: None,
        matcher: None,
    };
}
#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("invalid domain: {0}")]
    Domain(String),
    #[error("filter input exceeds rule/byte limits")]
    Limit,
    #[error("list names must be unique, nonempty and at most 128 bytes")]
    ListName,
}
/// Control-plane normalization. Query names are already ASCII DNS labels.
pub fn normalize(input: &str) -> Result<String, CompileError> {
    let input = input.strip_suffix('.').unwrap_or(input);
    let ascii = idna::domain_to_ascii(input)
        .map_err(|_| CompileError::Domain(input.to_owned()))?
        .to_ascii_lowercase();
    if ascii.is_empty()
        || ascii.len() > 253
        || ascii.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        })
    {
        return Err(CompileError::Domain(input.to_owned()));
    }
    Ok(ascii)
}
/// Rule identifiers indexed under one name: at most one allow and one block
/// rule per matcher, because identical (action, matcher, name) rules share an ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Ids {
    allow: u32,
    block: u32,
}
impl Ids {
    /// Sentinel for "no rule"; compilation never assigns it as an ID.
    pub(crate) const NONE: u32 = u32::MAX;
    pub(crate) const EMPTY: Self = Self {
        allow: Self::NONE,
        block: Self::NONE,
    };
    #[inline]
    fn id(value: u32) -> Option<u32> {
        (value != Self::NONE).then_some(value)
    }
    #[inline]
    pub(crate) fn allow(self) -> Option<u32> {
        Self::id(self.allow)
    }
    #[inline]
    pub(crate) fn block(self) -> Option<u32> {
        Self::id(self.block)
    }
    #[inline]
    pub(crate) fn get(self, action: Action) -> Option<u32> {
        match action {
            Action::Allow => self.allow(),
            Action::Block => self.block(),
        }
    }
    pub(crate) fn set(&mut self, action: Action, id: u32) {
        match action {
            Action::Allow => self.allow = id,
            Action::Block => self.block = id,
        }
    }
    pub(crate) fn clear(&mut self, action: Action) {
        self.set(action, Self::NONE);
    }
    pub(crate) fn count(self) -> usize {
        usize::from(self.allow().is_some()) + usize::from(self.block().is_some())
    }
}
/// Immutable name index. The hasher is seeded per process; keys come from
/// operator-selected lists and lookups never insert.
pub(crate) type Index = hashbrown::HashMap<Arc<str>, Ids, foldhash::fast::RandomState>;

#[derive(Debug)]
pub struct FilterSnapshot {
    rules: Vec<Rule>,
    exact: Index,
    suffix: Index,
    /// Whether any suffix allow survives; without one, the first suffix block
    /// found while walking towards the root is final.
    suffix_allows: bool,
    effective_rules: usize,
    payload_bytes: usize,
    pub stats: Vec<ListStats>,
}
impl FilterSnapshot {
    pub fn compile(
        lists: &[ListInput],
        max_rules: usize,
        max_bytes: usize,
    ) -> Result<Self, CompileError> {
        compile::build(lists, max_rules, max_bytes, &compile::Sequential)
    }
    /// Input is a normalized lower-case name without the root dot. No allocation.
    ///
    /// Any matching allow rule wins over every block rule; within an action an
    /// exact match is reported before the most specific suffix match. Both
    /// actions share one walk towards the root.
    pub fn evaluate(&self, domain: &str) -> Decision {
        let exact = self.exact.get(domain).copied().unwrap_or(Ids::EMPTY);
        if let Some(id) = exact.allow() {
            return Decision::matched(Action::Allow, id, Matcher::Exact);
        }
        let mut block_suffix = None;
        let mut name = Some(domain);
        while let Some(current) = name {
            if let Some(ids) = self.suffix.get(current) {
                if let Some(id) = ids.allow() {
                    return Decision::matched(Action::Allow, id, Matcher::Suffix);
                }
                if block_suffix.is_none() {
                    block_suffix = ids.block();
                    if block_suffix.is_some() && !self.suffix_allows {
                        break;
                    }
                }
            }
            name = parent(current);
        }
        if let Some(id) = exact.block() {
            return Decision::matched(Action::Block, id, Matcher::Exact);
        }
        if let Some(id) = block_suffix {
            return Decision::matched(Action::Block, id, Matcher::Suffix);
        }
        Decision::ALLOW
    }
    pub fn rule(&self, id: u32) -> Option<&Rule> {
        self.rules.get(id as usize)
    }
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
    /// Rules that can decide a query: compiled rules minus duplicates and rules
    /// subsumed by a same-action suffix rule.
    pub fn effective_rules(&self) -> usize {
        self.effective_rules
    }
    /// Logical payload estimate, counting shared string bytes once. Excludes
    /// allocator/Arc headers, spare capacity, stats and map overhead; not RSS.
    pub fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }
    /// Recompute the derived counters after the indexes are final.
    pub(crate) fn seal(&mut self) {
        self.effective_rules = self
            .exact
            .values()
            .chain(self.suffix.values())
            .map(|ids| ids.count())
            .sum();
        self.suffix_allows = self.suffix.values().any(|ids| ids.allow().is_some());
        self.payload_bytes = self.calculate_payload_bytes();
    }
    fn calculate_payload_bytes(&self) -> usize {
        self.rules
            .iter()
            .map(|r| {
                std::mem::size_of::<Rule>()
                    + r.domain.len()
                    + r.sources.len() * std::mem::size_of::<Source>()
            })
            .sum::<usize>()
            // Unique list names are validated. A list has retained provenance
            // iff it supplied a unique or duplicate valid rule.
            + self.stats.iter()
                .filter(|stats| stats.unique != 0 || stats.duplicates != 0)
                .map(|stats| stats.name.len())
                .sum::<usize>()
            + (self.exact.len() + self.suffix.len()) * std::mem::size_of::<(Arc<str>, Ids)>()
    }
}
impl Decision {
    #[inline]
    fn matched(action: Action, id: u32, matcher: Matcher) -> Self {
        Self {
            action,
            rule: Some(id),
            matcher: Some(matcher),
        }
    }
}
fn parent(mut domain: &str) -> Option<&str> {
    // Hickory's textual DNS names escape dots inside labels. Only an unescaped
    // dot separates labels; a pair of escaped backslashes leaves a real dot.
    loop {
        let (head, rest) = domain.split_once('.')?;
        let backslashes = head.bytes().rev().take_while(|byte| *byte == b'\\').count();
        if backslashes % 2 == 0 {
            return Some(rest);
        }
        domain = rest;
    }
}
/// Most specific suffix rule of `action` covering `domain` (inclusive).
fn suffix_match(index: &Index, action: Action, mut domain: &str) -> Option<u32> {
    loop {
        if let Some(id) = index.get(domain).and_then(|ids| ids.get(action)) {
            return Some(id);
        }
        domain = parent(domain)?;
    }
}
fn parse_rule(line: &str, default: Action) -> Result<Vec<(Action, Matcher, String)>, CompileError> {
    let fields: Vec<_> = line.split_whitespace().collect();
    if fields.len() > 1 {
        if !matches!(fields[0], "0.0.0.0" | "127.0.0.1" | "::" | "::1") {
            return Err(CompileError::Domain(line.to_owned()));
        }
        return fields[1..]
            .iter()
            .map(|domain| Ok((default, Matcher::Suffix, normalize(domain)?)))
            .collect();
    }
    let (action, line) = if let Some(line) = line.strip_prefix("@@") {
        (Action::Allow, line)
    } else {
        (default, line)
    };
    let (matcher, domain) = if let Some(domain) = line.strip_prefix('=') {
        (Matcher::Exact, domain)
    } else if let Some(domain) = line.strip_prefix("||").and_then(|s| s.strip_suffix('^')) {
        (Matcher::Suffix, domain)
    } else if let Some(domain) = line.strip_prefix("*.") {
        (Matcher::Suffix, domain)
    } else {
        (Matcher::Suffix, line)
    };
    Ok(vec![(action, matcher, normalize(domain)?)])
}
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn normalization_and_invalid() {
        assert_eq!(normalize("EXAMPLE.com.").unwrap(), "example.com");
        assert_eq!(normalize("bücher.de").unwrap(), "xn--bcher-kva.de");
        for input in [
            "",
            "a..com",
            "http://example.com",
            "a.com$badfilter",
            "-bad.com",
        ] {
            assert!(normalize(input).is_err(), "{input}");
        }
    }
    #[test]
    fn precedence_label_boundaries_sources_and_subsumption() {
        let lists=vec![ListInput { name:"deny".into(),action:Action::Block,rules:"example.com\nEXAMPLE.com.\nsub.example.com\n=exact.test\n0.0.0.0 hosts.test other.test\n||ads.test^\ninvalid$modifier".into() },ListInput { name:"allow".into(),action:Action::Allow,rules:"=safe.example.com".into() }];
        let filters = FilterSnapshot::compile(&lists, 100, 10000).unwrap();
        assert_eq!(filters.evaluate("x.example.com").action, Action::Block);
        assert_eq!(filters.evaluate("notexample.com").action, Action::Allow);
        assert_eq!(filters.evaluate("safe.example.com").action, Action::Allow);
        assert_eq!(filters.evaluate("x.safe.example.com").action, Action::Block);
        assert_eq!(filters.evaluate("x.exact.test").action, Action::Allow);
        assert_eq!(filters.stats[0].duplicates, 1);
        assert_eq!(filters.stats[0].invalid, 1);
        assert_eq!(filters.stats[0].redundant, 1);
        let rule = filters
            .rule(filters.evaluate("example.com").rule.unwrap())
            .unwrap();
        assert_eq!(rule.sources.len(), 2);
    }
    #[test]
    fn limits() {
        let list = ListInput {
            name: "test".into(),
            action: Action::Block,
            rules: "a.test\nb.test".into(),
        };
        assert!(FilterSnapshot::compile(std::slice::from_ref(&list), 1, 100).is_err());
        assert!(FilterSnapshot::compile(&[list], 10, 1).is_err());
    }

    #[test]
    fn provenance_survives_inputs_and_independent_snapshots() {
        let snapshot = {
            let lists = [
                ListInput {
                    name: "first".into(),
                    action: Action::Block,
                    rules: "EXAMPLE.test.\n=example.test\nsub.example.test\nexample.test".into(),
                },
                ListInput {
                    name: "second".into(),
                    action: Action::Allow,
                    rules: "@@=safe.example.test\n@@example.test\n@@EXAMPLE.test.".into(),
                },
            ];
            FilterSnapshot::compile(&lists, 100, 10_000).unwrap()
        };
        let replacement = FilterSnapshot::compile(
            &[ListInput {
                name: "replacement".into(),
                action: Action::Block,
                rules: "other.test".into(),
            }],
            100,
            10_000,
        )
        .unwrap();
        assert_eq!(snapshot.rules().len(), 5);
        assert_eq!(snapshot.effective_rules(), 2);
        assert_eq!(snapshot.stats[0].duplicates, 1);
        assert_eq!(snapshot.stats[0].redundant, 2);
        assert_eq!(snapshot.stats[1].duplicates, 1);
        assert_eq!(snapshot.stats[1].redundant, 1);
        let decision = snapshot.evaluate("x.example.test");
        assert_eq!(decision.action, Action::Allow);
        let rule = snapshot.rule(decision.rule.unwrap()).unwrap();
        assert_eq!(rule.domain.as_ref(), "example.test");
        assert_eq!(rule.matcher, Matcher::Suffix);
        assert_eq!(
            rule.sources
                .iter()
                .map(|source| (source.list.as_ref(), source.line))
                .collect::<Vec<_>>(),
            [("second", 2), ("second", 3)]
        );
        assert_eq!(replacement.evaluate("x.example.test"), Decision::ALLOW);
        assert_eq!(replacement.evaluate("other.test").action, Action::Block);
        assert!(snapshot.payload_bytes() > replacement.payload_bytes());
        assert_eq!(
            FilterSnapshot::compile(&[], 100, 100)
                .unwrap()
                .payload_bytes(),
            0
        );
    }

    #[test]
    fn compiled_actions_match_reference_across_overlaps() {
        let domains = ["test", "a.test", "b.test", "x.a.test"];
        let queries = [
            "test",
            "a.test",
            "b.test",
            "x.a.test",
            "y.x.a.test",
            "other.test",
            "notatest",
        ];
        // Exhaust all pairs, including equal names, different actions/matchers
        // and suffix subsumption. Duplicate lines exercise shared provenance.
        for first in 0..16 {
            for second in 0..16 {
                let inputs = [first, second].map(|index| {
                    let action = if index & 1 == 0 {
                        Action::Block
                    } else {
                        Action::Allow
                    };
                    let matcher = if index & 2 == 0 {
                        Matcher::Exact
                    } else {
                        Matcher::Suffix
                    };
                    (action, matcher, domains[index / 4])
                });
                let lists = inputs
                    .iter()
                    .enumerate()
                    .map(|(i, (action, matcher, domain))| {
                        let prefix = if *matcher == Matcher::Exact { "=" } else { "" };
                        ListInput {
                            name: format!("list{i}"),
                            action: *action,
                            rules: format!("{prefix}{domain}\n{prefix}{domain}"),
                        }
                    })
                    .collect::<Vec<_>>();
                let snapshot = FilterSnapshot::compile(&lists, 100, 10_000).unwrap();
                for query in queries {
                    let matches = |action| {
                        inputs.iter().any(|(a, matcher, domain)| {
                            *a == action
                                && (query == *domain
                                    || (*matcher == Matcher::Suffix
                                        && query
                                            .strip_suffix(domain)
                                            .is_some_and(|prefix| prefix.ends_with('.'))))
                        })
                    };
                    let expected = if matches(Action::Allow) {
                        Action::Allow
                    } else if matches(Action::Block) {
                        Action::Block
                    } else {
                        Action::Allow
                    };
                    let decision = snapshot.evaluate(query);
                    assert_eq!(decision.action, expected, "{inputs:?}: {query}");
                    if let Some(id) = decision.rule {
                        let rule = snapshot.rule(id).unwrap();
                        assert_eq!(rule.action, expected);
                        assert_eq!(rule.sources.len(), if first == second { 4 } else { 2 });
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod differential {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// Reference semantics: rules subsumed by a same-action suffix rule (above
    /// them, or at the same name for exact rules) are dropped; then any allow
    /// beats any block, and within an action an exact match beats a suffix
    /// match and nearer suffixes beat farther ones.
    fn reference(
        rules: &[(Action, Matcher, &str)],
        query: &str,
    ) -> Option<(Action, Matcher, String)> {
        let below = |name: &str, ancestor: &str| {
            name.strip_suffix(ancestor)
                .is_some_and(|prefix| prefix.ends_with('.'))
        };
        let effective: Vec<_> = rules
            .iter()
            .filter(|(action, matcher, domain)| {
                !rules.iter().any(|(a, m, d)| {
                    a == action
                        && *m == Matcher::Suffix
                        && (below(domain, d) || (*matcher == Matcher::Exact && domain == d))
                })
            })
            .collect();
        for action in [Action::Allow, Action::Block] {
            if let Some((_, _, domain)) = effective
                .iter()
                .find(|(a, m, d)| *a == action && *m == Matcher::Exact && query == *d)
            {
                return Some((action, Matcher::Exact, (*domain).to_owned()));
            }
            if let Some((_, _, domain)) = effective
                .iter()
                .filter(|(a, m, d)| {
                    *a == action && *m == Matcher::Suffix && (query == *d || below(query, d))
                })
                .max_by_key(|(_, _, d)| d.len())
            {
                return Some((action, Matcher::Suffix, (*domain).to_owned()));
            }
        }
        None
    }

    #[test]
    fn single_walk_matches_reference_on_random_overlapping_rule_sets() {
        let names = [
            "test",
            "a.test",
            "b.a.test",
            "c.b.a.test",
            "x.test",
            "other",
        ];
        let queries = [
            "test",
            "a.test",
            "b.a.test",
            "c.b.a.test",
            "d.c.b.a.test",
            "x.test",
            "y.x.test",
            "other",
            "z.other",
            "unrelated.example",
        ];
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = |bound: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            usize::try_from(seed % bound as u64).unwrap()
        };
        for _ in 0..4000 {
            let count = 1 + next(6);
            let rules: Vec<_> = (0..count)
                .map(|_| {
                    let action = if next(2) == 0 {
                        Action::Allow
                    } else {
                        Action::Block
                    };
                    let matcher = if next(2) == 0 {
                        Matcher::Exact
                    } else {
                        Matcher::Suffix
                    };
                    (action, matcher, names[next(names.len())])
                })
                .collect();
            let lists: Vec<_> = rules
                .iter()
                .enumerate()
                .map(|(index, (action, matcher, domain))| ListInput {
                    name: format!("list{index}"),
                    action: *action,
                    rules: format!(
                        "{}{domain}",
                        if *matcher == Matcher::Exact { "=" } else { "" }
                    ),
                })
                .collect();
            let snapshot = FilterSnapshot::compile(&lists, 100, 10_000).unwrap();
            for query in queries {
                let decision = snapshot.evaluate(query);
                match reference(&rules, query) {
                    None => assert_eq!(decision, Decision::ALLOW, "{rules:?} {query}"),
                    Some((action, matcher, domain)) => {
                        assert_eq!(decision.action, action, "{rules:?} {query}");
                        assert_eq!(decision.matcher, Some(matcher), "{rules:?} {query}");
                        let rule = snapshot.rule(decision.rule.unwrap()).unwrap();
                        assert_eq!(
                            (rule.action, rule.matcher, rule.domain.as_ref()),
                            (action, matcher, domain.as_str()),
                            "{rules:?} {query}"
                        );
                        assert!(!rule.redundant);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod escaped_labels {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn escaped_dots_are_not_dns_label_boundaries() {
        let snapshot = FilterSnapshot::compile(
            &[ListInput {
                name: "test".into(),
                action: Action::Block,
                rules: "example.com".into(),
            }],
            10,
            1000,
        )
        .unwrap();
        assert_eq!(
            snapshot.evaluate(r"evil\.example.com").action,
            Action::Allow
        );
        assert_eq!(
            snapshot.evaluate(r"evil\.label.example.com").action,
            Action::Block
        );
        assert_eq!(
            snapshot.evaluate(r"evil\\.example.com").action,
            Action::Block
        );
    }
}
