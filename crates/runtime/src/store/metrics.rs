//! History persistence counters and read-only samples.
use std::sync::atomic::{AtomicU64, Ordering};

/// History persistence counters.
#[derive(Default)]
pub struct StoreMetrics {
    /// Events lost because a batch failed to write.
    pub(super) write_failures: AtomicU64,
    /// Events written.
    pub(super) persisted_events: AtomicU64,
}
/// Plain counter values sampled by [`StoreMetrics::snapshot`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StoreMetricsSnapshot {
    /// Events lost because a batch failed to write.
    pub write_failures: u64,
    /// Events written.
    pub persisted_events: u64,
}
impl StoreMetrics {
    /// Sample counters with relaxed loads. Values are independent observations,
    /// so concurrent updates can occur between fields; this is not a transaction.
    pub fn snapshot(&self) -> StoreMetricsSnapshot {
        StoreMetricsSnapshot {
            write_failures: self.write_failures.load(Ordering::Relaxed),
            persisted_events: self.persisted_events.load(Ordering::Relaxed),
        }
    }
}
