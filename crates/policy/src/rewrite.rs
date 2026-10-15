use crate::CompiledPolicy;
use hickory_proto::rr::{Name, Record, RecordType};
/// Local answers for one name, grouped by type when compiled so that a query
/// borrows its records instead of filtering them.
#[derive(Default)]
pub(crate) struct LocalAnswers {
    pub(crate) a: Vec<Record>,
    pub(crate) aaaa: Vec<Record>,
    pub(crate) cname: Vec<Record>,
    pub(crate) chain: Vec<Record>,
    pub(crate) other: std::collections::HashMap<RecordType, Vec<Record>>,
    pub(crate) forward: Option<Name>,
    pub(crate) passthrough: u8,
}
/// Off-executor exact owners and descendant wildcard suffixes.
#[derive(Default)]
pub(crate) struct Rewrites {
    pub(crate) exact: std::collections::HashMap<String, LocalAnswers>,
    pub(crate) wildcards: std::collections::HashMap<String, LocalAnswers>,
}
/// DNS label boundaries, including names containing Hickory presentation escapes.
pub(crate) fn suffixes(domain: &str) -> impl Iterator<Item = &str> {
    let mut escaped = false;
    domain.bytes().enumerate().filter_map(move |(index, byte)| {
        if escaped {
            escaped = false;
            return None;
        }
        if byte == b'\\' {
            escaped = true;
            return None;
        }
        (byte == b'.').then(|| &domain[index + 1..])
    })
}
impl LocalAnswers {
    fn eligible(&self, kind: RecordType) -> bool {
        !self.cname.is_empty()
            || !self.other.is_empty()
            || self.passthrough != 0
            || match kind {
                RecordType::A => !self.a.is_empty(),
                RecordType::AAAA => !self.aaaa.is_empty(),
                _ => true,
            }
    }
}
impl Rewrites {
    pub(crate) fn len(&self) -> usize {
        self.exact.len() + self.wildcards.len()
    }
    fn select(&self, domain: &str, kind: RecordType) -> Option<&LocalAnswers> {
        let exact = self.exact.get(domain);
        if self.wildcards.is_empty() || exact.is_some_and(|answer| answer.eligible(kind)) {
            return exact;
        }
        let mut fallback = exact;
        for suffix in suffixes(domain) {
            if let Some(answer) = self.wildcards.get(suffix) {
                fallback = fallback.or(Some(answer));
                if answer.eligible(kind) {
                    return Some(answer);
                }
            }
        }
        // A matched owner without a record of this type still answers NODATA.
        fallback
    }
}
impl CompiledPolicy {
    /// Exact or descendant wildcard answer records (empty means NODATA), or
    /// `None` when the question has no rewrite, including family passthrough.
    /// Wildcard records are compiled templates. The response encoder
    /// must substitute the original question's concrete owner after cloning.
    pub fn rewrite(&self, domain: &str, kind: RecordType) -> Option<&[Record]> {
        let answers = self.rewrites.select(domain, kind)?;
        let bit = match kind {
            RecordType::A => 1,
            RecordType::AAAA => 2,
            _ => 0,
        };
        if answers.passthrough & bit != 0 {
            return None;
        }
        Some(match kind {
            RecordType::A => &answers.a,
            RecordType::AAAA => &answers.aaaa,
            RecordType::CNAME => &answers.cname,
            _ => answers
                .other
                .get(&kind)
                .map_or(answers.chain.as_slice(), Vec::as_slice),
        })
    }
    /// Whether this name matches any local owner or rewrite directive.
    /// Use `has_rewrite_for` to determine whether a question is rewritten.
    pub fn has_rewrite(&self, domain: &str) -> bool {
        self.rewrites.exact.contains_key(domain)
            || (!self.rewrites.wildcards.is_empty()
                && suffixes(domain).any(|suffix| self.rewrites.wildcards.contains_key(suffix)))
    }
    /// Whether this question is rewritten, including local NODATA.
    pub fn has_rewrite_for(&self, domain: &str, kind: RecordType) -> bool {
        self.rewrite(domain, kind).is_some()
    }
    /// External terminal of a local CNAME chain. Resolve this name through the
    /// selected policy's routes, then prepend the borrowed local alias records.
    pub fn rewrite_forward(&self, domain: &str, kind: RecordType) -> Option<(&Name, &[Record])> {
        if kind == RecordType::CNAME {
            return None;
        }
        let answers = self.rewrites.select(domain, kind)?;
        Some((answers.forward.as_ref()?, &answers.chain))
    }
}
