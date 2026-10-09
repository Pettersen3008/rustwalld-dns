//! Ordered ingestion and immutable index construction, off the query executor.
use crate::{
    Action, CompileError, FilterSnapshot, Ids, ListInput, ListStats, Matcher, Rule, Source, parent,
    parse_rule, suffix_match,
};
use std::{collections::HashMap, sync::Arc};

pub(super) type ParsedRules = Result<Vec<(Action, Matcher, String)>, CompileError>;
pub(super) trait Work {
    fn parse(
        &self,
        list: &ListInput,
        budget: usize,
        consume: impl FnMut(usize, ParsedRules) -> Result<(), CompileError>,
    ) -> Result<(), CompileError>;
    fn finish(&self, snapshot: &mut FilterSnapshot);
}
pub(super) struct Sequential;
impl Work for Sequential {
    fn parse(
        &self,
        list: &ListInput,
        budget: usize,
        mut consume: impl FnMut(usize, ParsedRules) -> Result<(), CompileError>,
    ) -> Result<(), CompileError> {
        let mut raw = 0;
        for (index, line) in list.rules.lines().enumerate() {
            let Some(line) = content(line) else {
                continue;
            };
            if raw == budget {
                return Err(CompileError::Limit);
            }
            raw += 1;
            consume(index, parse_rule(line, list.action))?;
        }
        Ok(())
    }
    fn finish(&self, snapshot: &mut FilterSnapshot) {
        for rule in &mut snapshot.rules {
            rule.redundant = redundant(&snapshot.suffix, rule);
        }
        index_exact(snapshot);
        retain_effective_suffixes(snapshot);
    }
}
/// A rule is redundant when a same-action suffix rule strictly above it (or,
/// for an exact rule, at the same name) already decides every name it matches.
pub(super) fn redundant(suffix: &crate::Index, rule: &Rule) -> bool {
    let candidate = if rule.matcher == Matcher::Exact {
        Some(rule.domain.as_ref())
    } else {
        parent(&rule.domain)
    };
    candidate.is_some_and(|domain| suffix_match(suffix, rule.action, domain).is_some())
}
/// Index every effective exact rule.
pub(super) fn index_exact(snapshot: &mut FilterSnapshot) {
    for rule in snapshot
        .rules
        .iter()
        .filter(|rule| rule.matcher == Matcher::Exact && !rule.redundant)
    {
        snapshot
            .exact
            .entry(rule.domain.clone())
            .or_insert(Ids::EMPTY)
            .set(rule.action, rule.id);
    }
}
/// Drop redundant suffix rules, and names left without any rule.
pub(super) fn retain_effective_suffixes(snapshot: &mut FilterSnapshot) {
    let rules = &snapshot.rules;
    snapshot.suffix.retain(|_, ids| {
        for action in [Action::Allow, Action::Block] {
            if ids
                .get(action)
                .is_some_and(|id| rules[id as usize].redundant)
            {
                ids.clear(action);
            }
        }
        ids.count() != 0
    });
}
pub(super) fn content(line: &str) -> Option<&str> {
    let line = line.split('#').next().unwrap_or("").trim();
    (!line.is_empty() && !line.starts_with('!')).then_some(line)
}
pub(super) fn build<W: Work>(
    lists: &[ListInput],
    max_rules: usize,
    max_bytes: usize,
    work: &W,
) -> Result<FilterSnapshot, CompileError> {
    if lists
        .iter()
        .try_fold(0usize, |total, list| total.checked_add(list.rules.len()))
        .is_none_or(|bytes| bytes > max_bytes)
    {
        return Err(CompileError::Limit);
    }
    let mut snapshot = FilterSnapshot {
        rules: Vec::new(),
        exact: crate::Index::default(),
        suffix: crate::Index::default(),
        suffix_allows: false,
        effective_rules: 0,
        payload_bytes: 0,
        stats: Vec::new(),
    };
    let mut seen = HashMap::<(Action, Matcher, Arc<str>), u32>::new();
    let mut names = std::collections::HashSet::new();
    let mut raw_count = 0usize;
    for list in lists {
        if list.name.is_empty() || list.name.len() > 128 || !names.insert(&list.name) {
            return Err(CompileError::ListName);
        }
        let mut stats = ListStats {
            name: list.name.clone(),
            ..Default::default()
        };
        // One immutable name allocation per list, shared by all provenance.
        let source_name: Arc<str> = list.name.as_str().into();
        let budget = max_rules.saturating_sub(raw_count);
        work.parse(list, budget, |line_index, parsed| {
            stats.raw += 1;
            raw_count += 1;
            let Ok(rules) = parsed else {
                stats.invalid += 1;
                return Ok(());
            };
            for (action, matcher, domain) in rules {
                if snapshot.rules.len() >= max_rules {
                    return Err(CompileError::Limit);
                }
                let source = Source {
                    list: Arc::clone(&source_name),
                    line: line_index + 1,
                };
                let domain: Arc<str> = domain.into();
                let key = (action, matcher, Arc::clone(&domain));
                if let Some(id) = seen.get(&key) {
                    snapshot.rules[*id as usize].sources.push(source);
                    stats.duplicates += 1;
                    continue;
                }
                let id = u32::try_from(snapshot.rules.len())
                    .ok()
                    .filter(|id| *id != Ids::NONE)
                    .ok_or(CompileError::Limit)?;
                seen.insert(key, id);
                snapshot.rules.push(Rule {
                    id,
                    action,
                    matcher,
                    domain,
                    sources: vec![source],
                    redundant: false,
                });
                stats.unique += 1;
            }
            Ok(())
        })?;
        snapshot.stats.push(stats);
    }
    // Build the suffix index first, then mark same-action descendants redundant.
    for rule in &snapshot.rules {
        if rule.matcher == Matcher::Suffix {
            snapshot
                .suffix
                .entry(rule.domain.clone())
                .or_insert(Ids::EMPTY)
                .set(rule.action, rule.id);
        }
    }
    work.finish(&mut snapshot);
    for rule in snapshot.rules.iter().filter(|r| r.redundant) {
        for stats in &mut snapshot.stats {
            if rule.sources.iter().any(|s| s.list.as_ref() == stats.name) {
                stats.redundant += 1;
            }
        }
    }
    // These scans belong to compilation, never to a status/API request.
    snapshot.seal();
    Ok(snapshot)
}
