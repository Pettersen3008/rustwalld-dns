//! Bounded per-rule exclusions and immutable candidate indexes.
use crate::index::{Ids, parent};
use crate::parsing::parse_rule;
use crate::{Action, CompileError, Decision, FilterSnapshot, Matcher, RuleSyntax, normalize};
use std::sync::Arc;

pub(super) const MAX_RULES: usize = 512;
pub(super) const MAX_DOMAINS: usize = 8192;
const MAX_PER_RULE: usize = 64;

/// Sorted normalized domains excluded from one rule, including descendants.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(transparent)]
pub struct DomainExclusions {
    domains: Box<[Arc<str>]>,
}
impl DomainExclusions {
    /// Sorted unique domains; these never create global allow rules.
    pub fn domains(&self) -> &[Arc<str>] {
        &self.domains
    }
    pub(super) fn contains(&self, domain: &str) -> bool {
        // At most 64 retained domains. Do not walk every query ancestor for
        // each rule: deep valid DNS names otherwise multiply the scoped cost.
        self.domains.iter().any(|candidate| {
            let Some(prefix) = domain.strip_suffix(candidate.as_ref()) else {
                return false;
            };
            if prefix.is_empty() {
                return true;
            }
            let Some(prefix) = prefix.strip_suffix('.') else {
                return false;
            };
            // An escaped dot is label content. A pair of backslashes leaves
            // a real boundary, matching the ordinary parent walker.
            prefix
                .bytes()
                .rev()
                .take_while(|byte| *byte == b'\\')
                .count()
                .is_multiple_of(2)
        })
    }
    pub(super) fn payload_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.domains.len() * std::mem::size_of::<Arc<str>>()
            + self.domains.iter().map(|name| name.len()).sum::<usize>()
    }
}
#[derive(Debug)]
pub(super) struct ParsedRule {
    pub action: Action,
    pub matcher: Matcher,
    pub domain: String,
    pub scope: Option<Arc<crate::RuleScope>>,
    pub response_value: bool,
}
impl ParsedRule {
    pub(super) fn plain(action: Action, matcher: Matcher, domain: String) -> Self {
        Self {
            action,
            matcher,
            domain,
            scope: None,
            response_value: false,
        }
    }
}
pub(super) fn parse(line: &str, action: Action, syntax: RuleSyntax) -> crate::compile::ParsedRules {
    if matches!(
        syntax,
        RuleSyntax::AdguardV4 | RuleSyntax::AdguardV5 | RuleSyntax::AdguardV6
    ) {
        return parse_v4(line, action, syntax);
    }
    let mut denyallow = None;
    let mut pattern = line;
    let unmarked = line.strip_prefix("@@").unwrap_or(line);
    if syntax == RuleSyntax::AdguardV3
        && !(unmarked.starts_with('/') && unmarked.ends_with('/'))
        && let Some((head, value)) = line.rsplit_once("$denyallow=")
    {
        if head.ends_with('\\')
            || head.len() > 4096
            || value.is_empty()
            || value.contains(',')
            || value.split('|').count() > MAX_PER_RULE
        {
            return Err(CompileError::Domain(
                "invalid or oversized denyallow modifier".into(),
            ));
        }
        let mask = head.strip_prefix("@@").unwrap_or(head);
        if !(mask.contains(['|', '^', '*']) || (mask.starts_with('/') && mask.ends_with('/')))
            || (!(mask.starts_with('/') && mask.ends_with('/'))
                && mask.chars().any(char::is_whitespace))
        {
            return Err(CompileError::Domain(
                "denyallow requires a network pattern".into(),
            ));
        }
        let mut domains: Vec<Arc<str>> = value
            .split('|')
            .map(|domain| normalize(domain).map(Arc::from))
            .collect::<Result<_, _>>()?;
        domains.sort_unstable();
        domains.dedup();
        denyallow = Some(Arc::new(DomainExclusions {
            domains: domains.into_boxed_slice(),
        }));
        pattern = head;
    }
    let scope = denyallow.map(|domains| {
        Arc::new(crate::RuleScope {
            denyallow: Some(domains),
            dnstype: None,
            client: None,
            ctag: None,
            ignore_ip_domains: false,
        })
    });
    parse_rule(pattern, action, syntax).map(|mut rules| {
        for rule in &mut rules {
            rule.scope = scope.clone();
        }
        rules
    })
}

type Index = hashbrown::HashMap<Arc<str>, Vec<u32>, foldhash::fast::RandomState>;
#[derive(Debug, Default)]
pub(super) struct ScopedIndexes {
    exact: Index,
    suffix: Index,
}
impl ScopedIndexes {
    pub(super) fn build(snapshot: &FilterSnapshot) -> Option<Box<Self>> {
        if !snapshot
            .rules
            .iter()
            .any(|rule| rule.scope.is_some() && !rule.redundant)
        {
            return None;
        }
        let mut indexes = Self::default();
        for rule in snapshot
            .rules
            .iter()
            .filter(|rule| rule.scope.is_some() && !rule.redundant)
        {
            let index = match rule.matcher {
                Matcher::Exact => &mut indexes.exact,
                Matcher::Suffix => &mut indexes.suffix,
                Matcher::Regex => continue,
            };
            index.entry(rule.domain.clone()).or_default().push(rule.id);
        }
        Some(Box::new(indexes))
    }
    pub(super) fn count(&self) -> usize {
        self.exact
            .values()
            .chain(self.suffix.values())
            .map(Vec::len)
            .sum()
    }
    pub(super) fn payload_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + (self.exact.len() + self.suffix.len()) * std::mem::size_of::<(Arc<str>, Vec<u32>)>()
            + self.count() * std::mem::size_of::<u32>()
    }
    fn ids(
        snapshot: &FilterSnapshot,
        unscoped: &crate::index::Index,
        scoped: &Index,
        name: &str,
        query: &str,
        kind: u16,
        client: Option<crate::FilterContext<'_>>,
    ) -> Ids {
        let mut ids = unscoped.get(name).copied().unwrap_or(Ids::EMPTY);
        if let Some(candidates) = scoped.get(name) {
            for &id in candidates {
                let rule = &snapshot.rules[id as usize];
                // Candidate IDs retain input order. Once an earlier rule of
                // this action matched, later candidates cannot replace it.
                // Keep scanning for the other action: allows must still win.
                if ids.get(rule.action).is_some_and(|current| current < id) {
                    continue;
                }
                if !rule.applies(query, kind, client) {
                    continue;
                }
                if ids.get(rule.action).is_none_or(|current| id < current) {
                    ids.set(rule.action, id);
                }
            }
        }
        ids
    }
    pub(super) fn evaluate(
        &self,
        snapshot: &FilterSnapshot,
        domain: &str,
        kind: u16,
        client: Option<crate::FilterContext<'_>>,
    ) -> Decision {
        let exact = Self::ids(
            snapshot,
            &snapshot.exact,
            &self.exact,
            domain,
            domain,
            kind,
            client,
        );
        if let Some(id) = exact.allow() {
            return Decision::matched(Action::Allow, id, Matcher::Exact);
        }
        let mut name = Some(domain);
        let mut block_suffix = None;
        while let Some(current) = name {
            let ids = Self::ids(
                snapshot,
                &snapshot.suffix,
                &self.suffix,
                current,
                domain,
                kind,
                client,
            );
            if let Some(id) = ids.allow() {
                return Decision::matched(Action::Allow, id, Matcher::Suffix);
            }
            if block_suffix.is_none() {
                block_suffix = ids.block();
            }
            name = parent(current);
        }
        if let Some(id) = snapshot
            .regex
            .as_ref()
            .and_then(|rules| rules.allow_scoped(domain, &snapshot.rules, kind, false, client))
        {
            return Decision::matched(Action::Allow, id, Matcher::Regex);
        }
        if let Some(id) = exact.block() {
            return Decision::matched(Action::Block, id, Matcher::Exact);
        }
        if let Some(id) = block_suffix {
            return Decision::matched(Action::Block, id, Matcher::Suffix);
        }
        if let Some(id) = snapshot
            .regex
            .as_ref()
            .and_then(|rules| rules.block_scoped(domain, &snapshot.rules, kind, false, client))
        {
            return Decision::matched(Action::Block, id, Matcher::Regex);
        }
        Decision::ALLOW
    }
}

fn parse_v4(line: &str, action: Action, syntax: RuleSyntax) -> crate::compile::ParsedRules {
    let unmarked = line.strip_prefix("@@").unwrap_or(line);
    let (pattern, options) = if unmarked.starts_with('/') && unmarked.ends_with('/') {
        (line, None)
    } else if matches!(syntax, RuleSyntax::AdguardV5 | RuleSyntax::AdguardV6) {
        line.char_indices()
            .rev()
            .find(|(index, c)| *c == '$' && (*index == 0 || line.as_bytes()[index - 1] != b'\\'))
            .map_or((line, None), |(index, _)| {
                (&line[..index], Some(&line[index + 1..]))
            })
    } else {
        line.rsplit_once('$')
            .filter(|(head, _)| !head.ends_with('\\'))
            .map_or((line, None), |(head, value)| (head, Some(value)))
    };
    let (mut denyallow, mut dnstype, mut client, mut ctag) = (None, None, None, None);
    if let Some(options) = options {
        let mask = pattern.strip_prefix("@@").unwrap_or(pattern);
        if pattern.len() > 4096
            || !(mask.contains(['|', '^', '*']) || (mask.starts_with('/') && mask.ends_with('/')))
            || (!(mask.starts_with('/') && mask.ends_with('/'))
                && mask.chars().any(char::is_whitespace))
        {
            return Err(CompileError::Domain(
                "modifiers require a bounded network pattern".into(),
            ));
        }
        let options = if matches!(syntax, RuleSyntax::AdguardV5 | RuleSyntax::AdguardV6) {
            crate::clients::split_escaped(&options.replace("\\$", "$"), ',')
        } else {
            options.split(',').map(str::to_owned).collect()
        };
        for option in options {
            if let Some(value) = option.strip_prefix("ctag=")
                && syntax == RuleSyntax::AdguardV6
                && ctag.is_none()
            {
                ctag = Some(Box::new(crate::TagSelector::parse(value)?));
                continue;
            }
            if let Some(value) = option.strip_prefix("client=")
                && matches!(syntax, RuleSyntax::AdguardV5 | RuleSyntax::AdguardV6)
                && client.is_none()
            {
                client = Some(Box::new(crate::ClientSelector::parse(value)?));
                continue;
            }
            if let Some(value) = option.strip_prefix("dnstype=")
                && dnstype.is_none()
            {
                dnstype = Some(crate::TypeSelector::parse(value)?);
            } else if let Some(value) = option.strip_prefix("denyallow=")
                && denyallow.is_none()
            {
                if value.is_empty() || value.split('|').count() > MAX_PER_RULE {
                    return Err(CompileError::Domain(
                        "invalid or oversized denyallow modifier".into(),
                    ));
                }
                let mut domains: Vec<Arc<str>> = value
                    .split('|')
                    .map(|name| normalize(name).map(Arc::from))
                    .collect::<Result<_, _>>()?;
                domains.sort_unstable();
                domains.dedup();
                denyallow = Some(Arc::new(DomainExclusions {
                    domains: domains.into_boxed_slice(),
                }));
            } else {
                return Err(CompileError::Domain(
                    "unsupported or duplicate modifier".into(),
                ));
            }
        }
    }
    let scope = (denyallow.is_some() || dnstype.is_some() || client.is_some() || ctag.is_some())
        .then(|| {
            Arc::new(crate::RuleScope {
                denyallow,
                dnstype,
                client,
                ctag,
                ignore_ip_domains: true,
            })
        });
    parse_rule(pattern, action, syntax).map(|mut rules| {
        for rule in &mut rules {
            rule.scope = scope.clone();
            rule.response_value = rule
                .scope
                .as_ref()
                .is_none_or(|scope| scope.denyallow.is_none())
                && (rule.matcher == Matcher::Regex || numeric_suffix(&rule.domain));
        }
        rules
    })
}
fn numeric_suffix(name: &str) -> bool {
    name.split('.').count() <= 4 && name.split('.').all(|label| label.parse::<u8>().is_ok())
}
