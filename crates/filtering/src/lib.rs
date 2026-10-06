#![doc = include_str!("../README.md")]
mod compile;
#[cfg(feature = "parallel")]
mod parallel;
#[cfg(feature = "parallel")]
pub use parallel::{ParallelCompiler, PoolError};

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};

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
#[derive(Debug)]
pub struct FilterSnapshot {
    rules: Vec<Rule>,
    allow_exact: HashMap<Arc<str>, u32>,
    allow_suffix: HashMap<Arc<str>, u32>,
    deny_exact: HashMap<Arc<str>, u32>,
    deny_suffix: HashMap<Arc<str>, u32>,
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
    pub fn evaluate(&self, domain: &str) -> Decision {
        for (action, exact, suffix) in [
            (Action::Allow, &self.allow_exact, &self.allow_suffix),
            (Action::Block, &self.deny_exact, &self.deny_suffix),
        ] {
            if let Some(id) = exact.get(domain) {
                return Decision {
                    action,
                    rule: Some(*id),
                    matcher: Some(Matcher::Exact),
                };
            }
            if let Some(id) = suffix_match(suffix, domain) {
                return Decision {
                    action,
                    rule: Some(id),
                    matcher: Some(Matcher::Suffix),
                };
            }
        }
        Decision::ALLOW
    }
    pub fn rule(&self, id: u32) -> Option<&Rule> {
        self.rules.get(id as usize)
    }
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
    pub fn effective_rules(&self) -> usize {
        self.allow_exact.len()
            + self.allow_suffix.len()
            + self.deny_exact.len()
            + self.deny_suffix.len()
    }
    /// Logical payload estimate, counting shared string bytes once. Excludes
    /// allocator/Arc headers, spare capacity, stats and map overhead; not RSS.
    pub fn payload_bytes(&self) -> usize {
        self.payload_bytes
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
            + self.effective_rules() * std::mem::size_of::<(Arc<str>, u32)>()
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
fn suffix_match(map: &HashMap<Arc<str>, u32>, mut domain: &str) -> Option<u32> {
    loop {
        if let Some(id) = map.get(domain) {
            return Some(*id);
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
