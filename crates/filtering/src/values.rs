//! Bounded V4-only response address indexes; reuse the snapshot's regex set.
use crate::index::{Ids, parent};
use crate::{Action, CompileError, Decision, FilterSnapshot, Matcher, Rule};
use std::sync::Arc;
type Index = hashbrown::HashMap<Arc<str>, Vec<u32>, foldhash::fast::RandomState>;
#[derive(Debug, Default)]
pub(super) struct ValueRules {
    exact: Index,
    suffix: Index,
    clients: Option<Box<[u32]>>,
}
impl ValueRules {
    pub(super) fn compile(rules: &[Rule]) -> Result<Option<Box<Self>>, CompileError> {
        let mut result = Self::default();
        let mut count = 0;
        let mut client_ids = Vec::new();
        let mut all_restricted = true;
        for rule in rules.iter().filter(|rule| rule.response_value) {
            count += 1;
            if rule
                .scope
                .as_ref()
                .is_some_and(|scope| scope.client.is_some() || scope.ctag.is_some())
            {
                client_ids.push(rule.id);
            } else {
                all_restricted = false;
            }
            if count > 4096 {
                return Err(CompileError::Limit);
            }
            let index = match rule.matcher {
                Matcher::Exact => &mut result.exact,
                Matcher::Suffix => &mut result.suffix,
                Matcher::Regex => continue,
            };
            index.entry(rule.domain.clone()).or_default().push(rule.id);
        }
        if all_restricted {
            result.clients = Some(client_ids.into_boxed_slice());
        }
        Ok((count != 0).then(|| Box::new(result)))
    }
    pub(super) fn payload_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self
                .clients
                .as_ref()
                .map_or(0, |ids| ids.len() * std::mem::size_of::<u32>())
            + (self.exact.len() + self.suffix.len()) * std::mem::size_of::<(Arc<str>, Vec<u32>)>()
            + self
                .exact
                .values()
                .chain(self.suffix.values())
                .map(|ids| ids.len() * std::mem::size_of::<u32>())
                .sum::<usize>()
    }
    pub(super) fn applicable(&self, rules: &[Rule], client: crate::FilterContext<'_>) -> bool {
        self.clients.as_ref().is_none_or(|ids| {
            ids.iter().any(|&id| {
                rules[id as usize]
                    .scope
                    .as_ref()
                    .is_some_and(|scope| scope.client_matches(Some(client)))
            })
        })
    }
    fn ids(
        snapshot: &FilterSnapshot,
        index: &Index,
        name: &str,
        value: &str,
        kind: u16,
        client: Option<crate::FilterContext<'_>>,
    ) -> Ids {
        let mut ids = Ids::EMPTY;
        if let Some(candidates) = index.get(name) {
            for &id in candidates {
                let rule = &snapshot.rules[id as usize];
                if ids.get(rule.action).is_none() && rule.applies(value, kind, client) {
                    ids.set(rule.action, id);
                }
            }
        }
        ids
    }
    pub(super) fn evaluate(
        &self,
        snapshot: &FilterSnapshot,
        value: &str,
        kind: u16,
        client: Option<crate::FilterContext<'_>>,
    ) -> Decision {
        let exact = Self::ids(snapshot, &self.exact, value, value, kind, client);
        if let Some(id) = exact.allow() {
            return Decision::matched(Action::Allow, id, Matcher::Exact);
        }
        let mut name = Some(value);
        let mut block = None;
        while let Some(current) = name {
            let ids = Self::ids(snapshot, &self.suffix, current, value, kind, client);
            if let Some(id) = ids.allow() {
                return Decision::matched(Action::Allow, id, Matcher::Suffix);
            }
            if block.is_none() {
                block = ids.block();
            }
            name = parent(current);
        }
        if let Some(id) = snapshot
            .regex
            .as_ref()
            .and_then(|rules| rules.allow_scoped(value, &snapshot.rules, kind, true, client))
        {
            return Decision::matched(Action::Allow, id, Matcher::Regex);
        }
        if let Some(id) = exact.block() {
            return Decision::matched(Action::Block, id, Matcher::Exact);
        }
        if let Some(id) = block {
            return Decision::matched(Action::Block, id, Matcher::Suffix);
        }
        if let Some(id) = snapshot
            .regex
            .as_ref()
            .and_then(|rules| rules.block_scoped(value, &snapshot.rules, kind, true, client))
        {
            return Decision::matched(Action::Block, id, Matcher::Regex);
        }
        Decision::ALLOW
    }
}
