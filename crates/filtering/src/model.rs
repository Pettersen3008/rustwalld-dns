//! Public rule, configuration, provenance and decision records.
use crate::{ClientSelector, DomainExclusions, FilterContext, RuleScope, TypeSelector};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// What a matching rule does. Any matching allow rule wins over every block rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Resolve the name normally.
    Allow,
    /// Answer NXDOMAIN locally.
    Block,
}
/// Which names a rule covers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Matcher {
    /// Only the rule's own name (`=example.com`).
    Exact,
    /// The name and every name below it (`example.com`, `||example.com^`).
    Suffix,
    /// Precompiled, case-insensitive ASCII regex (`/pattern/`).
    Regex,
}
/// One named filter list to compile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListInput {
    /// Unique, nonempty list name of at most 128 bytes; used for provenance.
    pub name: String,
    /// Default action for the list's rules; `@@` lines are always allows.
    pub action: Action,
    /// Rule text: domains, `=exact`, `||adblock^`, `*.wildcard` or hosts
    /// lines, with `#`/`!` comments.
    pub rules: String,
    /// Parser semantics retained when a downloaded list is refreshed.
    #[serde(default, skip_serializing_if = "RuleSyntax::is_native")]
    pub syntax: RuleSyntax,
}
/// Input interpretation. Native preserves the original suffix-domain format;
/// AdGuard makes bare/hosts domains exact and supports hostname masks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleSyntax {
    /// Original exact/suffix format, unchanged for stored configurations.
    #[default]
    Native,
    /// AdGuard DNS hosts/domain/Adblock-style interpretation.
    Adguard,
    /// AdGuard rules with whole-line comments and compile-time `$badfilter`.
    AdguardV2,
    /// V2 semantics plus per-rule `$denyallow` domain exclusions.
    AdguardV3,
    /// V3 plus typed request/response rules and explicit value filtering.
    AdguardV4,
    /// V4 plus explicit per-rule source-IP/network/name restrictions.
    AdguardV5,
    /// V5 plus explicit client-tag restrictions.
    AdguardV6,
}
impl RuleSyntax {
    fn is_native(&self) -> bool {
        *self == Self::Native
    }
}
/// Where a rule came from.
#[derive(Clone, Debug, Serialize)]
pub struct Source {
    /// List name.
    pub list: Arc<str>,
    /// One-based line number within the list text.
    pub line: usize,
}
/// One deduplicated compiled rule with every place it was declared.
#[derive(Clone, Debug, Serialize)]
pub struct Rule {
    /// Identifier within this snapshot; see [`crate::FilterSnapshot::rule`].
    pub id: u32,
    /// Allow or block.
    pub action: Action,
    /// Exact or suffix matching.
    pub matcher: Matcher,
    /// Normalized ASCII name without the root dot, or the ASCII regex pattern.
    pub domain: Arc<str>,
    /// Every list line that declared this rule, in input order.
    pub sources: Vec<Source>,
    /// A same-action suffix rule already decides every name this rule matches,
    /// so it is not indexed; decisions report the subsuming rule instead.
    pub redundant: bool,
    /// Shared optional domain/type restrictions, flattened in JSON.
    #[serde(flatten)]
    pub scope: Option<Arc<RuleScope>>,
    /// V4 response-value eligibility; not a DNS input or JSON field.
    #[serde(skip)]
    pub response_value: bool,
}
impl Rule {
    /// Domains excluded from this rule only.
    pub fn denyallow(&self) -> Option<&Arc<DomainExclusions>> {
        self.scope.as_ref()?.denyallow.as_ref()
    }
    /// Type restriction, if any.
    pub fn dnstype(&self) -> Option<&TypeSelector> {
        self.scope.as_ref()?.dnstype.as_ref()
    }
    /// Client restriction, if present.
    pub fn client(&self) -> Option<&ClientSelector> {
        self.scope.as_ref()?.client.as_deref()
    }
    pub(crate) fn applies(
        &self,
        domain: &str,
        kind: u16,
        client: Option<FilterContext<'_>>,
    ) -> bool {
        self.scope
            .as_ref()
            .is_none_or(|scope| scope.applies(domain, kind, client))
    }
}
/// Per-list compilation counts.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ListStats {
    /// List name.
    pub name: String,
    /// Non-comment, non-empty lines.
    pub raw: usize,
    /// Rules first declared by this list.
    pub unique: usize,
    /// Rules already declared earlier (in this or another list).
    pub duplicates: usize,
    /// Lines that could not be parsed.
    pub invalid: usize,
    /// Rules this list declared that are subsumed by a same-action suffix rule.
    pub redundant: usize,
    /// Valid v2 cancellation declarations (including unmatched declarations).
    #[serde(skip_serializing_if = "is_zero")]
    pub badfilters: usize,
    /// Original v2 rule lines removed by cancellation, before deduplication.
    #[serde(skip_serializing_if = "is_zero")]
    pub disabled: usize,
}
fn is_zero(value: &usize) -> bool {
    *value == 0
}
/// Bounded provenance for one literal `$badfilter` target.
#[derive(Clone, Debug, Serialize)]
pub struct Cancellation {
    /// Effective action of the rules being cancelled.
    pub action: Action,
    /// Literal pattern without the `@@` exception marker or modifier.
    pub pattern: Arc<str>,
    /// Total matching cancellation declarations.
    pub directives: usize,
    /// First five declaration sources, in input order.
    pub directive_sources: Vec<Source>,
    /// Total original input lines disabled by these declarations.
    pub disabled: usize,
    /// First five disabled sources, in input order.
    pub disabled_sources: Vec<Source>,
}
/// Result of [`crate::FilterSnapshot::evaluate`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct Decision {
    /// Allow or block.
    pub action: Action,
    /// Deciding rule, or `None` for the default allow.
    pub rule: Option<u32>,
    /// How the deciding rule matched.
    pub matcher: Option<Matcher>,
}
impl Decision {
    /// Default allow: no rule matched.
    pub const ALLOW: Self = Self {
        action: Action::Allow,
        rule: None,
        matcher: None,
    };
}
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
/// Why compilation or normalization failed.
pub enum CompileError {
    /// A name is not a valid DNS name after IDNA conversion.
    #[error("invalid domain: {0}")]
    Domain(String),
    /// The rule-count or byte budget was exceeded.
    #[error("filter input exceeds rule/byte limits")]
    Limit,
    /// A list name is empty, longer than 128 bytes or repeated.
    #[error("list names must be unique, nonempty and at most 128 bytes")]
    ListName,
}
impl Decision {
    #[inline]
    pub(super) fn matched(action: Action, id: u32, matcher: Matcher) -> Self {
        Self {
            action,
            rule: Some(id),
            matcher: Some(matcher),
        }
    }
}
