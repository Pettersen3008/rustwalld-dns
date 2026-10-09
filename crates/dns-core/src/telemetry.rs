use rustwalld_dns_filter::Decision;
use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};
use tokio::sync::mpsc;
#[derive(Clone, Debug)]
pub struct QueryEvent {
    pub client: IpAddr,
    pub domain: String,
    pub qtype: u16,
    pub generation: u64,
    pub policy: usize,
    pub decision: Decision,
    pub decision_cached: bool,
    pub response_code: u16,
    pub source: QuerySource,
    pub latency_us: u64,
    pub shadow: Option<ShadowDecision>,
    pub temporary_exception: Option<u16>,
}
#[derive(Clone, Debug)]
pub struct ShadowDecision {
    pub generation: u64,
    pub policy: usize,
    pub decision: Decision,
    pub rewrite: bool,
    pub differs: bool,
    pub temporary_exception: Option<u16>,
}
#[derive(Default)]
pub struct Metrics {
    pub requests: AtomicU64,
    pub blocked: AtomicU64,
    pub rewrites: AtomicU64,
    pub failures: AtomicU64,
    pub decision_hits: AtomicU64,
    pub dropped_events: AtomicU64,
    pub shadow_differences: AtomicU64,
    pub temporary_allows: AtomicU64,
    /// UDP queries dropped because `max_udp_queries` workers were busy.
    pub udp_overloads: AtomicU64,
    /// TCP connections closed because `max_tcp_connections` were open.
    pub tcp_overloads: AtomicU64,
    /// Failed UDP receives or TCP accepts; the listener keeps serving.
    pub listener_errors: AtomicU64,
    pub latency_sum_us: AtomicU64,
    pub latency_buckets: [AtomicU64; 8],
}
pub const LATENCY_US: [u64; 8] = [20, 50, 100, 150, 500, 1000, 10000, u64::MAX];
impl Metrics {
    pub fn observe(&self, start: Instant) -> u64 {
        let us = start.elapsed().as_micros().min(u64::MAX as u128) as u64;
        self.latency_sum_us.fetch_add(us, Ordering::Relaxed);
        if let Some(index) = LATENCY_US.iter().position(|bound| us <= *bound) {
            self.latency_buckets[index].fetch_add(1, Ordering::Relaxed);
        }
        us
    }
}
#[derive(Clone)]
pub struct Telemetry {
    sender: mpsc::Sender<QueryEvent>,
    pub metrics: Arc<Metrics>,
}
impl Telemetry {
    pub fn channel(capacity: usize) -> (Self, mpsc::Receiver<QueryEvent>) {
        let (sender, receiver) = mpsc::channel(capacity.max(1));
        (
            Self {
                sender,
                metrics: Arc::new(Metrics::default()),
            },
            receiver,
        )
    }
    pub fn emit(&self, event: QueryEvent) {
        if self.sender.try_send(event).is_err() {
            self.metrics.dropped_events.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuerySource {
    Rewrite,
    Blocked,
    Cache,
    Upstream,
    Coalesced,
    Failure,
}
impl QuerySource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rewrite => "rewrite",
            Self::Blocked => "blocked",
            Self::Cache => "cache",
            Self::Upstream => "upstream",
            Self::Coalesced => "coalesced",
            Self::Failure => "failure",
        }
    }
}
