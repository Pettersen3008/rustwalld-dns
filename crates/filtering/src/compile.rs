//! Ordered ingestion and immutable index construction, off the query executor.
use crate::{
    Action, CompileError, FilterSnapshot, ListInput, ListStats, Matcher, Rule, Source, parent,
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
            let suffix = if rule.action == Action::Allow {
                &snapshot.allow_suffix
            } else {
                &snapshot.deny_suffix
            };
            let candidate = if rule.matcher == Matcher::Exact {
                Some(rule.domain.as_ref())
            } else {
                parent(&rule.domain)
            };
            rule.redundant = candidate.is_some_and(|domain| suffix_match(suffix, domain).is_some());
            if !rule.redundant && rule.matcher == Matcher::Exact {
                let map = if rule.action == Action::Allow {
                    &mut snapshot.allow_exact
                } else {
                    &mut snapshot.deny_exact
                };
                map.insert(rule.domain.clone(), rule.id);
            }
        }
        snapshot
            .allow_suffix
            .retain(|_, id| !snapshot.rules[*id as usize].redundant);
        snapshot
            .deny_suffix
            .retain(|_, id| !snapshot.rules[*id as usize].redundant);
    }
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
        allow_exact: HashMap::new(),
        allow_suffix: HashMap::new(),
        deny_exact: HashMap::new(),
        deny_suffix: HashMap::new(),
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
                let id = u32::try_from(snapshot.rules.len()).map_err(|_| CompileError::Limit)?;
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
    // Build suffix maps first, then mark same-action descendants as redundant.
    for rule in &snapshot.rules {
        if rule.matcher == Matcher::Suffix {
            let map = if rule.action == Action::Allow {
                &mut snapshot.allow_suffix
            } else {
                &mut snapshot.deny_suffix
            };
            map.insert(rule.domain.clone(), rule.id);
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
    // This scan belongs to compilation, never to a status/API request.
    snapshot.payload_bytes = snapshot.calculate_payload_bytes();
    Ok(snapshot)
}
