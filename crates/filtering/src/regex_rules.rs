//! Offline compilation with explicit budgets; no backtracking engine.
use crate::{Action, CompileError, Matcher, Rule};
use regex::bytes::{RegexSet, RegexSetBuilder};

pub(crate) const MAX_PATTERNS: usize = 512;
const MAX_PATTERN_BYTES: usize = 4096;
const MAX_COMPILED_BYTES: usize = 4 * 1024 * 1024;
const MAX_DFA_BYTES: usize = 1024 * 1024;

fn build<'a>(patterns: impl IntoIterator<Item = &'a str>) -> Result<RegexSet, CompileError> {
    RegexSetBuilder::new(patterns)
        .unicode(false)
        .case_insensitive(true)
        .nest_limit(64)
        .size_limit(MAX_COMPILED_BYTES)
        .dfa_size_limit(MAX_DFA_BYTES)
        .build()
        .map_err(|_| CompileError::Domain("invalid or oversized ASCII regex".into()))
}
pub(crate) fn validate(pattern: &str) -> Result<(), CompileError> {
    if pattern.is_empty() || pattern.len() > MAX_PATTERN_BYTES || !pattern.is_ascii() {
        return Err(CompileError::Domain(
            "regex must contain 1..4096 ASCII bytes".into(),
        ));
    }
    build([pattern]).map(|_| ())
}
#[derive(Debug)]
struct Set {
    compiled: RegexSet,
    ids: Vec<u32>,
}
impl Set {
    fn first_scoped(
        &self,
        domain: &str,
        rules: &[Rule],
        kind: u16,
        values: bool,
        client: Option<crate::FilterContext<'_>>,
    ) -> Option<u32> {
        self.compiled
            .matches(domain.as_bytes())
            .iter()
            .filter_map(|index| self.ids.get(index).copied())
            .find(|&id| {
                let rule = &rules[id as usize];
                (!values || rule.response_value) && rule.applies(domain, kind, client)
            })
    }
    fn first(&self, domain: &str) -> Option<u32> {
        self.compiled
            .matches(domain.as_bytes())
            .iter()
            .next()
            .and_then(|index| self.ids.get(index).copied())
    }
}
#[derive(Debug)]
pub(crate) struct RegexRules {
    allow: Option<Set>,
    block: Option<Set>,
    count: usize,
}
impl RegexRules {
    pub(crate) fn compile(rules: &[Rule]) -> Result<Option<Self>, CompileError> {
        let patterns: Vec<_> = rules
            .iter()
            .filter(|rule| rule.matcher == Matcher::Regex)
            .collect();
        if patterns.len() > MAX_PATTERNS {
            return Err(CompileError::Limit);
        }
        if patterns.is_empty() {
            return Ok(None);
        }
        let action_set = |action| -> Result<Option<Set>, CompileError> {
            let selected: Vec<_> = patterns
                .iter()
                .filter(|rule| rule.action == action)
                .collect();
            if selected.is_empty() {
                return Ok(None);
            }
            let compiled = build(selected.iter().map(|rule| rule.domain.as_ref()))?;
            Ok(Some(Set {
                compiled,
                ids: selected.iter().map(|rule| rule.id).collect(),
            }))
        };
        Ok(Some(Self {
            allow: action_set(Action::Allow)?,
            block: action_set(Action::Block)?,
            count: patterns.len(),
        }))
    }
    pub(crate) fn allow(&self, domain: &str) -> Option<u32> {
        self.allow.as_ref()?.first(domain)
    }
    pub(crate) fn block(&self, domain: &str) -> Option<u32> {
        self.block.as_ref()?.first(domain)
    }
    pub(crate) fn allow_scoped(
        &self,
        domain: &str,
        rules: &[Rule],
        kind: u16,
        values: bool,
        client: Option<crate::FilterContext<'_>>,
    ) -> Option<u32> {
        self.allow
            .as_ref()?
            .first_scoped(domain, rules, kind, values, client)
    }
    pub(crate) fn block_scoped(
        &self,
        domain: &str,
        rules: &[Rule],
        kind: u16,
        values: bool,
        client: Option<crate::FilterContext<'_>>,
    ) -> Option<u32> {
        self.block
            .as_ref()?
            .first_scoped(domain, rules, kind, values, client)
    }
    pub(crate) fn count(&self) -> usize {
        self.count
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::{FilterSnapshot, ListInput};
    #[test]
    fn bounded_regexes_keep_allow_precedence_and_provenance() {
        let snapshot = FilterSnapshot::compile(
            &[
                ListInput {
                    syntax: Default::default(),
                    name: "tracking".into(),
                    action: Action::Block,
                    rules: r"/(^|\.)track[0-9]+\.test$/
blocked.test
/^literal#name$/"
                        .into(),
                },
                ListInput {
                    syntax: Default::default(),
                    name: "exceptions".into(),
                    action: Action::Allow,
                    rules: r"/^safe\.blocked\.test$/
@@/^track42\.test$/"
                        .into(),
                },
            ],
            100,
            10000,
        )
        .unwrap();
        assert_eq!(snapshot.stats[0].invalid, 0);
        assert_eq!(snapshot.evaluate("a.track123.test").action, Action::Block);
        assert_eq!(snapshot.evaluate("track42.test").action, Action::Allow);
        assert_eq!(snapshot.evaluate("safe.blocked.test").action, Action::Allow);
        assert_eq!(snapshot.evaluate("literal#name").action, Action::Block);
        let decision = snapshot.evaluate("track123.test");
        assert_eq!(decision.matcher, Some(Matcher::Regex));
        let rule = snapshot.rule(decision.rule.unwrap()).unwrap();
        assert_eq!(rule.sources[0].list.as_ref(), "tracking");
        assert_eq!(rule.sources[0].line, 1);
        assert_eq!(snapshot.effective_rules(), 5);
        assert!(validate(r"(a)\1").is_err());
        assert!(validate(r"(?=tracking)").is_err());
        assert!(validate(&"a".repeat(4097)).is_err());
    }
    #[test]
    fn regex_budget_and_invalid_rule_accounting_are_explicit() {
        let bad = ListInput {
            syntax: Default::default(),
            name: "bad".into(),
            action: Action::Block,
            rules: "/[unterminated/\n/^good\\.test$/".into(),
        };
        let snapshot = FilterSnapshot::compile(&[bad], 100, 10000).unwrap();
        assert_eq!(snapshot.stats[0].invalid, 1);
        let patterns = (0..513)
            .map(|n| format!("/^n{n}\\.test$/"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(matches!(
            FilterSnapshot::compile(
                &[ListInput {
                    syntax: Default::default(),
                    name: "too many".into(),
                    action: Action::Block,
                    rules: patterns
                }],
                1000,
                100000
            ),
            Err(CompileError::Limit)
        ));
    }
}

#[cfg(test)]
mod syntax_tests {
    #![allow(clippy::unwrap_used)]
    use crate::{Action, FilterSnapshot, ListInput, RuleSyntax};
    #[test]
    fn adguard_bare_hosts_exact_anchors_and_masks_have_distinct_semantics() {
        let snapshot=FilterSnapshot::compile(&[ListInput{syntax:RuleSyntax::Adguard,name:"imported".into(),action:Action::Block,rules:"ads.test\n0.0.0.0 host.test\n||suffix.test^\n|exact.test^\n||ad*.wild.test^\n@@|safe.suffix.test^".into()}],100,10000).unwrap();
        assert_eq!(snapshot.stats[0].invalid, 0);
        for domain in [
            "ads.test",
            "host.test",
            "x.suffix.test",
            "exact.test",
            "ad123.wild.test",
            "x.ad123.wild.test",
        ] {
            assert_eq!(snapshot.evaluate(domain).action, Action::Block, "{domain}");
        }
        for domain in [
            "x.ads.test",
            "x.host.test",
            "x.exact.test",
            "safe.suffix.test",
            "notad123.wild.test",
        ] {
            assert_eq!(snapshot.evaluate(domain).action, Action::Allow, "{domain}");
        }
    }
}
