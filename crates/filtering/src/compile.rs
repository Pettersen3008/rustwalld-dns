//! Ordered ingestion and immutable index construction, off the query executor.
use crate::badfilter::{self, ParsedLine, Targets};
use crate::index::{Ids, parent, suffix_match};
use crate::{Action, CompileError, FilterSnapshot, ListInput, ListStats, Matcher, Rule, Source};
use std::{collections::HashMap, sync::Arc};

pub(super) type ParsedRules = Result<Vec<crate::exclusions::ParsedRule>, CompileError>;
pub(super) trait Work {
    fn parse(
        &self,
        list: &ListInput,
        budget: usize,
        targets: &Targets<'_>,
        consume: impl FnMut(usize, ParsedLine) -> Result<(), CompileError>,
    ) -> Result<(), CompileError>;
    fn finish(&self, snapshot: &mut FilterSnapshot);
}
pub(super) struct Sequential;
impl Work for Sequential {
    fn parse(
        &self,
        list: &ListInput,
        budget: usize,
        targets: &Targets<'_>,
        mut consume: impl FnMut(usize, ParsedLine) -> Result<(), CompileError>,
    ) -> Result<(), CompileError> {
        let mut raw = 0;
        for (index, line) in list.rules.lines().enumerate() {
            let Some(line) = content(line, list.syntax) else {
                continue;
            };
            if raw == budget {
                return Err(CompileError::Limit);
            }
            raw += 1;
            consume(index, targets.parse(line, list))?;
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
pub(super) fn redundant(suffix: &crate::index::Index, rule: &Rule) -> bool {
    if rule.matcher == Matcher::Regex || rule.response_value {
        return false;
    }
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
        .filter(|rule| rule.matcher == Matcher::Exact && !rule.redundant && rule.scope.is_none())
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
pub(super) fn content(line: &str, syntax: crate::RuleSyntax) -> Option<&str> {
    let trimmed = line.trim();
    if matches!(
        syntax,
        crate::RuleSyntax::AdguardV2 | crate::RuleSyntax::AdguardV3 | crate::RuleSyntax::AdguardV4
    ) {
        return (!trimmed.is_empty() && !trimmed.starts_with(['#', '!'])).then_some(trimmed);
    }
    if trimmed
        .strip_prefix("@@")
        .unwrap_or(trimmed)
        .starts_with('/')
    {
        return Some(trimmed);
    }
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
    let (targets, cancellations) = Targets::collect(lists, max_rules)?;
    let mut snapshot = FilterSnapshot {
        rules: Vec::new(),
        exact: crate::index::Index::default(),
        suffix: crate::index::Index::default(),
        suffix_allows: false,
        regex: None,
        effective_rules: 0,
        payload_bytes: 0,
        stats: Vec::new(),
        cancellations,
        cancellation_targets: targets.len(),
        scoped: None,
        values: None,
        typed_response: lists.iter().any(|list| {
            matches!(
                list.syntax,
                crate::RuleSyntax::AdguardV4
                    | crate::RuleSyntax::AdguardV5
                    | crate::RuleSyntax::AdguardV6
            )
        }),
        typed_rules: false,
        client_classes: None,
        tag_mask: 0,
    };
    let mut seen =
        HashMap::<(Action, Matcher, Arc<str>, Option<Arc<crate::RuleScope>>), u32>::new();
    let mut names = std::collections::HashSet::new();
    let mut raw_count = 0usize;
    let mut regex_count = 0usize;
    let mut scoped_count = 0usize;
    let mut excluded_count = 0usize;
    let mut type_count = 0usize;
    let mut client_count = 0usize;
    let mut tag_count = 0usize;
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
        work.parse(list, budget, &targets, |line_index, parsed| {
            stats.raw += 1;
            raw_count += 1;
            let parsed = match parsed {
                ParsedLine::Directive(index) => {
                    stats.badfilters += 1;
                    badfilter::record(
                        &mut snapshot.cancellations,
                        index,
                        true,
                        &source_name,
                        line_index + 1,
                    );
                    return Ok(());
                }
                ParsedLine::Disabled(index) => {
                    stats.disabled += 1;
                    badfilter::record(
                        &mut snapshot.cancellations,
                        index,
                        false,
                        &source_name,
                        line_index + 1,
                    );
                    return Ok(());
                }
                ParsedLine::Rules(parsed) => parsed,
            };
            let Ok(rules) = parsed else {
                stats.invalid += 1;
                return Ok(());
            };
            for crate::exclusions::ParsedRule {
                action,
                matcher,
                domain,
                scope,
                response_value,
            } in rules
            {
                if snapshot.rules.len() >= max_rules {
                    return Err(CompileError::Limit);
                }
                let source = Source {
                    list: Arc::clone(&source_name),
                    line: line_index + 1,
                };
                let domain: Arc<str> = domain.into();
                let key = (action, matcher, Arc::clone(&domain), scope.clone());
                if let Some(id) = seen.get(&key) {
                    snapshot.rules[*id as usize].sources.push(source);
                    snapshot.rules[*id as usize].response_value |= response_value;
                    stats.duplicates += 1;
                    continue;
                }
                if let Some(scope) = &scope {
                    scoped_count += 1;
                    excluded_count += scope
                        .denyallow
                        .as_ref()
                        .map_or(0, |domains| domains.domains().len());
                    type_count += scope.dnstype.as_ref().map_or(0, |types| types.count());
                    client_count += scope.client.as_ref().map_or(0, |selector| selector.count());
                    tag_count += scope.ctag.as_ref().map_or(0, |selector| selector.count());
                    if tag_count > 8192
                        || client_count > 8192
                        || scoped_count > crate::exclusions::MAX_RULES
                        || excluded_count > crate::exclusions::MAX_DOMAINS
                        || type_count > 8192
                    {
                        return Err(CompileError::Limit);
                    }
                }
                // Reject oversized active regex sets before parsing an entire
                // publisher. Cancelled lines never reach this point; duplicates
                // do not consume this existing per-snapshot budget.
                if matcher == Matcher::Regex {
                    if regex_count == crate::regex_rules::MAX_PATTERNS {
                        return Err(CompileError::Limit);
                    }
                    regex_count += 1;
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
                    scope,
                    response_value,
                });
                stats.unique += 1;
            }
            Ok(())
        })?;
        snapshot.stats.push(stats);
    }
    // Build the suffix index first, then mark same-action descendants redundant.
    for rule in &snapshot.rules {
        if rule.matcher == Matcher::Suffix && rule.scope.is_none() {
            snapshot
                .suffix
                .entry(rule.domain.clone())
                .or_insert(Ids::EMPTY)
                .set(rule.action, rule.id);
        }
    }
    work.finish(&mut snapshot);
    snapshot.regex = crate::regex_rules::RegexRules::compile(&snapshot.rules)?;
    snapshot.scoped = crate::exclusions::ScopedIndexes::build(&snapshot);
    for rule in snapshot.rules.iter().filter(|r| r.redundant) {
        for stats in &mut snapshot.stats {
            if rule.sources.iter().any(|s| s.list.as_ref() == stats.name) {
                stats.redundant += 1;
            }
        }
    }
    // These scans belong to compilation, never to a status/API request.
    snapshot.values = crate::values::ValueRules::compile(&snapshot.rules)?;
    snapshot.typed_rules = snapshot.rules.iter().any(|rule| rule.dnstype().is_some());
    snapshot.client_classes = crate::clients::ClientClasses::compile(&snapshot.rules)?;
    snapshot.tag_mask = snapshot
        .rules
        .iter()
        .filter_map(|rule| rule.scope.as_ref()?.ctag.as_ref())
        .fold(0, |mask, selector| mask | selector.mask());
    snapshot.seal();
    Ok(snapshot)
}
