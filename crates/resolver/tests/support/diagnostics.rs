use rustwalld_dns_resolver::{FailureKind, UpstreamHealth};

pub fn reconciled(health: &UpstreamHealth) {
    let health = health.snapshot();
    assert_eq!(health.inflight, 0);
    let failures: u64 = FailureKind::ALL
        .into_iter()
        .map(|kind| health.failure_count(kind))
        .sum();
    assert_eq!(health.attempts, health.successes + failures);
}
pub fn failure(health: &UpstreamHealth, kind: FailureKind, count: u64) {
    reconciled(health);
    assert_eq!(health.failure_count(kind), count, "{kind:?}: {health:?}");
}
