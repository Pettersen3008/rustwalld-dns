use crate::CompiledPolicy;
use hickory_proto::rr::{Record, RecordType};
/// Local answers for one name, grouped by type when compiled so that a query
/// borrows its records instead of filtering them.
#[derive(Default)]
pub(crate) struct LocalAnswers {
    pub(crate) a: Vec<Record>,
    pub(crate) aaaa: Vec<Record>,
}
impl CompiledPolicy {
    /// Local answer records of `kind` for `domain` (empty means NODATA), or
    /// `None` when the policy has no rewrite for the name.
    pub fn rewrite(&self, domain: &str, kind: RecordType) -> Option<&[Record]> {
        let answers = self.rewrites.get(domain)?;
        Some(match kind {
            RecordType::A => &answers.a,
            RecordType::AAAA => &answers.aaaa,
            _ => &[],
        })
    }
    /// Whether the policy rewrites `domain` for any record type.
    pub fn has_rewrite(&self, domain: &str) -> bool {
        self.rewrites.contains_key(domain)
    }
}
