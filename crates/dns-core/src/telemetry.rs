//! Bounded, nonblocking query events and aggregate counters.
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
/// One answered query (refusals are counted but not reported).
#[derive(Clone, Debug)]
pub struct QueryEvent {
    /// Canonical client address.
    pub client: IpAddr,
    /// Normalized query name without the root dot.
    pub domain: String,
    /// Query type code.
    pub qtype: u16,
    /// Policy generation that decided the query.
    pub generation: u64,
    /// Index of the selected policy within that generation.
    pub policy: usize,
    /// Filter decision (after any temporary exception expiry).
    pub decision: Decision,
    /// Whether the decision came from the decision cache.
    pub decision_cached: bool,
    /// Response code sent to the client.
    pub response_code: u16,
    /// How the answer was produced.
    pub source: QuerySource,
    /// Processing time in microseconds, from receipt to encoding.
    pub latency_us: u64,
    /// Shadow-policy decision, when a shadow generation is staged.
    pub shadow: Option<ShadowDecision>,
    /// Index of the temporary exception that allowed the query, if any.
    pub temporary_exception: Option<u16>,
}
/// How the staged shadow generation would have decided a query.
#[derive(Clone, Debug)]
pub struct ShadowDecision {
    /// Shadow generation.
    pub generation: u64,
    /// Policy index selected in the shadow generation.
    pub policy: usize,
    /// Shadow filter decision.
    pub decision: Decision,
    /// Whether the shadow policy has a rewrite for the name.
    pub rewrite: bool,
    /// Whether the shadow outcome differs from the active one.
    pub differs: bool,
    /// Shadow temporary exception index, if one applied.
    pub temporary_exception: Option<u16>,
}
/// Monotonic counters and a fixed latency histogram; updated with relaxed atomics.
#[derive(Default)]
pub struct Metrics {
    /// Parsed queries (responses and malformed packets excluded).
    pub requests: AtomicU64,
    /// Queries answered NXDOMAIN by a block rule.
    pub blocked: AtomicU64,
    /// Queries answered by a local rewrite.
    pub rewrites: AtomicU64,
    /// Queries answered SERVFAIL.
    pub failures: AtomicU64,
    /// Expired-cache answers sent after upstream failure and final policy checks.
    pub stale_answers: AtomicU64,
    /// Decisions served from the decision cache.
    pub decision_hits: AtomicU64,
    /// Events dropped because the telemetry queue was full or closed.
    pub dropped_events: AtomicU64,
    /// Queries whose shadow outcome differed from the active one.
    pub shadow_differences: AtomicU64,
    /// Queries allowed by a temporary exception.
    pub temporary_allows: AtomicU64,
    /// UDP queries dropped because `max_udp_queries` workers were busy.
    pub udp_overloads: AtomicU64,
    /// UDP cache misses answered SERVFAIL because `max_udp_upstream_waits`
    /// queries were already waiting on upstreams.
    pub forward_overloads: AtomicU64,
    /// TCP connections closed because `max_tcp_connections` were open.
    pub tcp_overloads: AtomicU64,
    /// Failed UDP receives or TCP accepts; the listener keeps serving.
    pub listener_errors: AtomicU64,
    /// Sum of observed latencies in microseconds.
    pub latency_sum_us: AtomicU64,
    /// Counts per [`LATENCY_US`] bucket (not cumulative).
    pub latency_buckets: [AtomicU64; 8],
}
/// Inclusive upper bounds of the latency buckets, in microseconds.
pub const LATENCY_US: [u64; 8] = [20, 50, 100, 150, 500, 1000, 10000, u64::MAX];
impl Metrics {
    /// Record the time since `start` and return it in microseconds.
    pub fn observe(&self, start: Instant) -> u64 {
        let us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
        self.latency_sum_us.fetch_add(us, Ordering::Relaxed);
        if let Some(index) = LATENCY_US.iter().position(|bound| us <= *bound) {
            self.latency_buckets[index].fetch_add(1, Ordering::Relaxed);
        }
        us
    }
}
/// Event delivery and counters shared by every DNS worker.
#[derive(Clone)]
pub struct Telemetry {
    sender: mpsc::Sender<QueryEvent>,
    /// Aggregate counters.
    pub metrics: Arc<Metrics>,
}
impl Telemetry {
    /// Telemetry with a queue of `capacity` events (at least one) and its receiver.
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
    /// Queue `event` without waiting; a full or closed queue drops it and
    /// counts the drop.
    pub fn emit(&self, event: QueryEvent) {
        if self.sender.try_send(event).is_err() {
            self.metrics.dropped_events.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// How a query was answered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum QuerySource {
    /// A local rewrite.
    Rewrite,
    /// A block rule (NXDOMAIN).
    Blocked,
    /// The response cache.
    Cache,
    /// An expired-cache answer after every upstream failed.
    Stale,
    /// An upstream lookup this query started.
    Upstream,
    /// An identical upstream lookup already in flight.
    Coalesced,
    /// SERVFAIL: upstream failure, overload or shedding.
    Failure,
}
impl QuerySource {
    /// Stable lowercase name used in history and the API.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rewrite => "rewrite",
            Self::Blocked => "blocked",
            Self::Cache => "cache",
            Self::Stale => "stale",
            Self::Upstream => "upstream",
            Self::Coalesced => "coalesced",
            Self::Failure => "failure",
        }
    }
}
