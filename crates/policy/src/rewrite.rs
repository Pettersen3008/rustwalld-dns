use crate::CompiledPolicy;
use hickory_proto::rr::{Record, RecordType};
impl CompiledPolicy {
    /// Local answer records of `kind` for `domain` (possibly empty, meaning
    /// NODATA), or `None` when the policy has no rewrite for the name.
    pub fn rewrite(&self, domain: &str, kind: RecordType) -> Option<Vec<Record>> {
        let records = self.rewrites.get(domain)?;
        Some(
            records
                .iter()
                .filter(|record| record.data.record_type() == kind)
                .cloned()
                .collect(),
        )
    }
    /// Whether the policy rewrites `domain` for any record type.
    pub fn has_rewrite(&self, domain: &str) -> bool {
        self.rewrites.contains_key(domain)
    }
}
