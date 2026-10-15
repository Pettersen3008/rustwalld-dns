//! Immutable compiled snapshots, matching and derived statistics.
use crate::index::{Ids, Index, parent};
use crate::{
    Action, Cancellation, ClientContext, CompileError, Decision, FilterContext, ListInput,
    ListStats, Matcher, Rule, Source, clients, compile, exclusions, regex_rules, values,
};
use std::sync::Arc;

/// Immutable compiled filter set with rule provenance. Build once off the DNS
/// executor and share it. Optional regex sets have bounded compiled/search state;
/// the domain-only path retains the existing name indexes.
#[derive(Debug)]
pub struct FilterSnapshot {
    pub(super) rules: Vec<Rule>,
    pub(super) exact: Index,
    pub(super) suffix: Index,
    /// Whether any suffix allow survives; without one, the first suffix block
    /// found while walking towards the root is final.
    pub(super) suffix_allows: bool,
    pub(super) regex: Option<regex_rules::RegexRules>,
    pub(super) effective_rules: usize,
    pub(super) payload_bytes: usize,
    /// Counts per input list, in input order.
    pub stats: Vec<ListStats>,
    pub(super) cancellations: Vec<Cancellation>,
    pub(super) cancellation_targets: usize,
    pub(super) scoped: Option<Box<exclusions::ScopedIndexes>>,
    pub(super) values: Option<Box<values::ValueRules>>,
    pub(super) typed_response: bool,
    pub(super) typed_rules: bool,
    pub(super) client_classes: Option<Box<clients::ClientClasses>>,
    pub(super) tag_mask: u32,
}
impl FilterSnapshot {
    /// Parse, normalize, deduplicate and index `lists` sequentially.
    ///
    /// `max_rules` bounds both raw rule lines and unique rules; `max_bytes`
    /// bounds the combined list text.
    ///
    /// # Errors
    ///
    /// [`CompileError::Limit`] when a bound is exceeded and
    /// [`CompileError::ListName`] for an invalid or repeated list name.
    /// Invalid rule lines are counted in [`ListStats::invalid`], not errors.
    pub fn compile(
        lists: &[ListInput],
        max_rules: usize,
        max_bytes: usize,
    ) -> Result<Self, CompileError> {
        compile::build(lists, max_rules, max_bytes, &compile::Sequential)
    }
    /// Input is a normalized lower-case name without the root dot.
    ///
    /// Any matching allow rule wins over every block rule; within an action an
    /// exact match is reported before the most specific suffix match. Both
    /// actions share one walk towards the root.
    pub fn evaluate(&self, domain: &str) -> Decision {
        self.evaluate_type(domain, 1)
    }
    /// Evaluate a normalized name for the actual question or CNAME record type.
    pub fn evaluate_type(&self, domain: &str, kind: u16) -> Decision {
        self.evaluate_context(domain, kind, None)
    }
    /// Evaluate with the actual source IP and explicit binding name.
    pub fn evaluate_client<'a>(
        &self,
        domain: &str,
        kind: u16,
        client: impl Into<FilterContext<'a>>,
    ) -> Decision {
        self.evaluate_context(domain, kind, Some(client.into()))
    }
    fn evaluate_context(
        &self,
        domain: &str,
        kind: u16,
        client: Option<FilterContext<'_>>,
    ) -> Decision {
        if let Some(scoped) = &self.scoped {
            return scoped.evaluate(self, domain, kind, client);
        }
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
        if let Some(id) = self.regex.as_ref().and_then(|rules| rules.allow(domain)) {
            return Decision::matched(Action::Allow, id, Matcher::Regex);
        }
        if let Some(id) = exact.block() {
            return Decision::matched(Action::Block, id, Matcher::Exact);
        }
        if let Some(id) = block_suffix {
            return Decision::matched(Action::Block, id, Matcher::Suffix);
        }
        if let Some(id) = self.regex.as_ref().and_then(|rules| rules.block(domain)) {
            return Decision::matched(Action::Block, id, Matcher::Regex);
        }
        Decision::ALLOW
    }
    /// Whether type restrictions require question-type cache partitioning.
    pub fn has_type_rules(&self) -> bool {
        self.typed_rules
    }
    /// Whether a V4 list enables response-type interpretation.
    pub fn typed_responses(&self) -> bool {
        self.typed_response
    }
    /// Whether any V4 rule can inspect address/HTTPS hint values.
    pub fn has_value_rules(&self) -> bool {
        self.values.is_some()
    }
    /// Whether any address rule can apply to this actual client. Checked once per reply.
    pub fn has_value_rules_for_client<'a>(&self, client: impl Into<FilterContext<'a>>) -> bool {
        self.values
            .as_ref()
            .is_some_and(|index| index.applicable(&self.rules, client.into()))
    }
    /// Evaluate a canonical address value with the response RR type, using V4 rules only.
    pub fn evaluate_value(&self, value: &str, kind: u16) -> Decision {
        self.evaluate_value_context(value, kind, None)
    }
    /// Evaluate a response value for the original client, using actual RR type.
    pub fn evaluate_value_client<'a>(
        &self,
        value: &str,
        kind: u16,
        client: impl Into<FilterContext<'a>>,
    ) -> Decision {
        self.evaluate_value_context(value, kind, Some(client.into()))
    }
    fn evaluate_value_context(
        &self,
        value: &str,
        kind: u16,
        client: Option<FilterContext<'_>>,
    ) -> Decision {
        self.values.as_ref().map_or(Decision::ALLOW, |index| {
            index.evaluate(self, value, kind, client)
        })
    }
    /// Identity-only class for legacy/untagged contexts; zero for ordinary rules.
    /// Use [`Self::context_partition`] when explicit filtering tags are supplied.
    pub fn client_partition(&self, client: ClientContext<'_>) -> u32 {
        self.client_classes
            .as_ref()
            .map_or(0, |classes| classes.partition(client))
    }
    /// Complete bounded cache identity, ignoring tags not used by this generation.
    pub fn context_partition(&self, context: FilterContext<'_>) -> u64 {
        (u64::from(self.client_partition(context.client)) << 32)
            | u64::from(context.tags.bits() & self.tag_mask)
    }
    /// Whether any retained rule uses explicit client tags.
    pub fn has_tag_rules(&self) -> bool {
        self.tag_mask != 0
    }
    /// Whether explicit client context is required by any retained rule.
    pub fn has_client_rules(&self) -> bool {
        self.client_classes.is_some() || self.has_tag_rules()
    }
    /// The rule with identifier `id`, as reported by [`Decision::rule`].
    pub fn rule(&self, id: u32) -> Option<&Rule> {
        self.rules.get(id as usize)
    }
    /// Every compiled rule, indexed by identifier.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
    /// Rules that can decide a query: compiled rules minus duplicates and rules
    /// subsumed by a same-action suffix rule.
    pub fn effective_rules(&self) -> usize {
        self.effective_rules
    }
    /// First 200 distinct cancellation targets, with bounded source samples.
    pub fn cancellations(&self) -> &[Cancellation] {
        &self.cancellations
    }
    /// Complete count of distinct valid cancellation targets.
    pub fn cancellation_targets(&self) -> usize {
        self.cancellation_targets
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
            .sum::<usize>()
            + self.regex.as_ref().map_or(0, |rules| rules.count());
        self.effective_rules += self.scoped.as_ref().map_or(0, |index| index.count());
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
                    + r.scope.as_ref().map_or(0, |domains| domains.payload_bytes())
            })
            .sum::<usize>()
            // Unique list names are validated. A list has retained provenance
            // iff it supplied a rule or a retained cancellation source sample.
            + self.stats.iter()
                .filter(|stats| stats.unique != 0 || stats.duplicates != 0 || self.cancellations.iter().any(|report| report.directive_sources.iter().chain(&report.disabled_sources).any(|source| source.list.as_ref() == stats.name)))
                .map(|stats| stats.name.len())
                .sum::<usize>()
            + self.cancellations.iter().map(|report| {
                std::mem::size_of::<Cancellation>() + report.pattern.len()
                    + (report.directive_sources.len() + report.disabled_sources.len())
                        * std::mem::size_of::<Source>()
            }).sum::<usize>()
            + (self.exact.len() + self.suffix.len()) * std::mem::size_of::<(Arc<str>, Ids)>()
            + self.scoped.as_ref().map_or(0, |index| index.payload_bytes())
            + self.values.as_ref().map_or(0, |index| index.payload_bytes())
            + self.client_classes.as_ref().map_or(0, |classes| classes.payload_bytes())
    }
}
