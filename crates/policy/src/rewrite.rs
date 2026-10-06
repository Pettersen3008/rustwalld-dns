use crate::CompiledPolicy;
use hickory_proto::rr::{Record, RecordType};
impl CompiledPolicy {
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
    pub fn has_rewrite(&self, domain: &str) -> bool {
        self.rewrites.contains_key(domain)
    }
}
