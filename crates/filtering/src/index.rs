//! Immutable name indexes and escape-aware DNS label traversal.
use crate::Action;
use std::sync::Arc;

/// Rule identifiers indexed under one name: at most one allow and one block
/// rule per matcher, because identical (action, matcher, name) rules share an ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Ids {
    allow: u32,
    block: u32,
}
impl Ids {
    /// Sentinel for "no rule"; compilation never assigns it as an ID.
    pub(crate) const NONE: u32 = u32::MAX;
    pub(crate) const EMPTY: Self = Self {
        allow: Self::NONE,
        block: Self::NONE,
    };
    #[inline]
    fn id(value: u32) -> Option<u32> {
        (value != Self::NONE).then_some(value)
    }
    #[inline]
    pub(crate) fn allow(self) -> Option<u32> {
        Self::id(self.allow)
    }
    #[inline]
    pub(crate) fn block(self) -> Option<u32> {
        Self::id(self.block)
    }
    #[inline]
    pub(crate) fn get(self, action: Action) -> Option<u32> {
        match action {
            Action::Allow => self.allow(),
            Action::Block => self.block(),
        }
    }
    pub(crate) fn set(&mut self, action: Action, id: u32) {
        match action {
            Action::Allow => self.allow = id,
            Action::Block => self.block = id,
        }
    }
    pub(crate) fn clear(&mut self, action: Action) {
        self.set(action, Self::NONE);
    }
    pub(crate) fn count(self) -> usize {
        usize::from(self.allow().is_some()) + usize::from(self.block().is_some())
    }
}
/// Immutable name index. The hasher is seeded per process; keys come from
/// operator-selected lists and lookups never insert.
pub(crate) type Index = hashbrown::HashMap<Arc<str>, Ids, foldhash::fast::RandomState>;

pub(super) fn parent(mut domain: &str) -> Option<&str> {
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
/// Most specific suffix rule of `action` covering `domain` (inclusive).
pub(super) fn suffix_match(index: &Index, action: Action, mut domain: &str) -> Option<u32> {
    loop {
        if let Some(id) = index.get(domain).and_then(|ids| ids.get(action)) {
            return Some(id);
        }
        domain = parent(domain)?;
    }
}
