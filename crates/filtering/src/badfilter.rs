//! Bounded control-plane cancellation. The selector map never enters a snapshot.
use crate::parsing::parse_rule;
use crate::{Action, Cancellation, CompileError, ListInput, RuleSyntax, Source, compile};
use std::{collections::HashMap, sync::Arc};

const MAX_DECLARATIONS: usize = 65_536;
const MAX_REPORTS: usize = 200;
const MAX_SOURCES: usize = 5;
const MAX_PATTERN_BYTES: usize = 4096;

#[derive(Default)]
pub(super) struct Targets<'a> {
    selectors: HashMap<(Action, &'a str), usize>,
}
pub(super) enum ParsedLine {
    Rules(compile::ParsedRules),
    Directive(usize),
    Disabled(usize),
}
fn key(line: &str, default: Action) -> (Action, &str) {
    line.strip_prefix("@@")
        .map_or((default, line), |pattern| (Action::Allow, pattern))
}
fn whole_regex(pattern: &str) -> bool {
    pattern.starts_with('/') && pattern.ends_with('/') && pattern.len() >= 2
}
fn candidate(line: &str, action: Action) -> bool {
    let (_, pattern) = key(line, action);
    !whole_regex(pattern) && pattern.contains("$badfilter")
}
fn directive_target(line: &str) -> Option<&str> {
    let target = line.strip_suffix("$badfilter")?;
    // The source parser treats a dollar preceded by a backslash as escaped.
    (!target.ends_with('\\')).then_some(target)
}
impl<'a> Targets<'a> {
    pub(super) fn collect(
        lists: &'a [ListInput],
        max_rules: usize,
    ) -> Result<(Self, Vec<Cancellation>), CompileError> {
        let mut targets = Self::default();
        let mut reports = Vec::new();
        if !lists.iter().any(|list| {
            matches!(
                list.syntax,
                RuleSyntax::AdguardV2
                    | RuleSyntax::AdguardV3
                    | RuleSyntax::AdguardV4
                    | RuleSyntax::AdguardV5
                    | RuleSyntax::AdguardV6
            ) && list.rules.contains("$badfilter")
        }) {
            return Ok((targets, reports));
        }
        let mut raw = 0;
        let mut declarations = 0;
        let mut names = std::collections::HashSet::new();
        for list in lists {
            if list.name.is_empty() || list.name.len() > 128 || !names.insert(&list.name) {
                return Err(CompileError::ListName);
            }
            for line in list
                .rules
                .lines()
                .filter_map(|line| compile::content(line, list.syntax))
            {
                if raw == max_rules {
                    return Err(CompileError::Limit);
                }
                raw += 1;
                if !matches!(
                    list.syntax,
                    RuleSyntax::AdguardV2
                        | RuleSyntax::AdguardV3
                        | RuleSyntax::AdguardV4
                        | RuleSyntax::AdguardV5
                        | RuleSyntax::AdguardV6
                ) || !candidate(line, list.action)
                {
                    continue;
                }
                if declarations == MAX_DECLARATIONS {
                    return Err(CompileError::Limit);
                }
                declarations += 1;
                let Some(target) = directive_target(line) else {
                    continue;
                };
                let (action, pattern) = key(target, list.action);
                // Bare domains/hosts have a different source grammar. Only
                // supported basic network patterns can be cancellation targets.
                if pattern.len() > MAX_PATTERN_BYTES
                    || (!whole_regex(pattern) && pattern.chars().any(char::is_whitespace))
                    || !(whole_regex(pattern) || pattern.contains(['|', '^', '*']))
                {
                    continue;
                }
                if targets.selectors.contains_key(&(action, pattern)) {
                    continue;
                }
                if parse_rule(target, list.action, RuleSyntax::AdguardV2).is_err() {
                    continue;
                }
                let index = targets.selectors.len();
                targets.selectors.insert((action, pattern), index);
                if index < MAX_REPORTS {
                    reports.push(Cancellation {
                        action,
                        pattern: pattern.into(),
                        directives: 0,
                        directive_sources: Vec::new(),
                        disabled: 0,
                        disabled_sources: Vec::new(),
                    });
                }
            }
        }
        Ok((targets, reports))
    }
    pub(super) fn len(&self) -> usize {
        self.selectors.len()
    }
    pub(super) fn parse(&self, line: &str, list: &ListInput) -> ParsedLine {
        if matches!(
            list.syntax,
            RuleSyntax::AdguardV2
                | RuleSyntax::AdguardV3
                | RuleSyntax::AdguardV4
                | RuleSyntax::AdguardV5
                | RuleSyntax::AdguardV6
        ) {
            if let Some(target) = directive_target(line)
                && let Some(&index) = self.selectors.get(&key(target, list.action))
            {
                return ParsedLine::Directive(index);
            }
            if let Some(&index) = self.selectors.get(&key(line, list.action)) {
                return ParsedLine::Disabled(index);
            }
        }
        ParsedLine::Rules(crate::exclusions::parse(line, list.action, list.syntax))
    }
}
pub(super) fn record(
    reports: &mut [Cancellation],
    index: usize,
    directive: bool,
    list: &Arc<str>,
    line: usize,
) {
    let Some(report) = reports.get_mut(index) else {
        return;
    };
    let (total, sources) = if directive {
        (&mut report.directives, &mut report.directive_sources)
    } else {
        (&mut report.disabled, &mut report.disabled_sources)
    };
    *total += 1;
    if sources.len() < MAX_SOURCES {
        sources.push(Source {
            list: Arc::clone(list),
            line,
        });
    }
}
