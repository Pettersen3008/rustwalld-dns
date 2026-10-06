use resolver::{FailureKind, UpstreamHealth};
use std::sync::atomic::Ordering;

pub fn reconciled(health: &UpstreamHealth) {
    assert_eq!(health.inflight.load(Ordering::SeqCst), 0);
    let failures: u64 = FailureKind::ALL
        .into_iter()
        .map(|kind| health.failure_count(kind))
        .sum();
    assert_eq!(
        health.attempts.load(Ordering::SeqCst),
        health.successes.load(Ordering::SeqCst) + failures
    );
}
pub fn failure(health: &UpstreamHealth, kind: FailureKind, count: u64) {
    reconciled(health);
    assert_eq!(health.failure_count(kind), count, "{kind:?}: {health:?}");
}
