//! Fixed endpoint accounting; independent of logging, storage and query identity.
use crate::admission::{Admission, AdmissionStatus, Ticket};
use serde::Serialize;
use std::{
    net::SocketAddr,
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

/// Classified outcome of a failed upstream attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(usize)]
#[non_exhaustive]
pub enum FailureKind {
    Deadline,
    Connection,
    TlsAuthentication,
    TlsProtocol,
    HttpProtocol,
    HttpStatus,
    HttpEnvelope,
    DnsResponse,
    Servfail,
    Refused,
    Cancelled,
    LocalError,
}
impl FailureKind {
    pub const ALL: [Self; 12] = [
        Self::Deadline,
        Self::Connection,
        Self::TlsAuthentication,
        Self::TlsProtocol,
        Self::HttpProtocol,
        Self::HttpStatus,
        Self::HttpEnvelope,
        Self::DnsResponse,
        Self::Servfail,
        Self::Refused,
        Self::Cancelled,
        Self::LocalError,
    ];
}

#[derive(Debug)]
pub struct UpstreamHealth {
    pub address: SocketAddr,
    pub attempts: AtomicU64,
    pub successes: AtomicU64,
    pub inflight: AtomicU64,
    pub ewma_us: AtomicU64,
    pub backoff_skips: AtomicU64,
    pub recovery_probes: AtomicU64,
    admission: Admission,
    failures: [AtomicU64; FailureKind::ALL.len()],
}
impl UpstreamHealth {
    pub(crate) fn new(address: SocketAddr) -> Self {
        Self {
            address,
            attempts: AtomicU64::new(0),
            successes: AtomicU64::new(0),
            inflight: AtomicU64::new(0),
            ewma_us: AtomicU64::new(0),
            backoff_skips: AtomicU64::new(0),
            recovery_probes: AtomicU64::new(0),
            admission: Admission::default(),
            failures: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
    pub fn failure_count(&self, kind: FailureKind) -> u64 {
        self.failures[kind as usize].load(Ordering::Relaxed)
    }
    pub fn admission_status(&self) -> AdmissionStatus {
        self.admission.status(Instant::now())
    }
    pub(crate) fn start(&self) -> Option<Attempt<'_>> {
        let start = Instant::now();
        let Some(ticket) = self.admission.enter(start) else {
            self.backoff_skips.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        if ticket.probe {
            self.recovery_probes.fetch_add(1, Ordering::Relaxed);
        }
        self.attempts.fetch_add(1, Ordering::Relaxed);
        self.inflight.fetch_add(1, Ordering::Relaxed);
        Some(Attempt {
            health: self,
            start,
            ticket,
            completed: false,
        })
    }
}
// A dropped forwarder future must reconcile counters even while pool admission,
// TLS handshake, HTTP driver or DNS response work is still pending.
pub(crate) struct Attempt<'a> {
    health: &'a UpstreamHealth,
    start: Instant,
    completed: bool,
    ticket: Ticket,
}
impl Attempt<'_> {
    pub(crate) fn failure(mut self, kind: FailureKind) {
        self.health.failures[kind as usize].fetch_add(1, Ordering::Relaxed);
        self.health
            .admission
            .finish(self.ticket, Some(kind), Instant::now());
        self.completed = true;
    }
    pub(crate) fn success(mut self) {
        self.health.successes.fetch_add(1, Ordering::Relaxed);
        self.health
            .admission
            .finish(self.ticket, None, Instant::now());
        let elapsed = u64::try_from(self.start.elapsed().as_micros()).unwrap_or(u64::MAX);
        // Rust 1.99 renamed this API; keep the equivalent operation for our 1.95 MSRV.
        #[allow(deprecated, reason = "fetch_update remains compatible with Rust 1.95")]
        let _ = self
            .health
            .ewma_us
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                Some(if old == 0 {
                    elapsed
                } else {
                    old.saturating_mul(7).saturating_add(elapsed) / 8
                })
            });
        self.completed = true;
    }
}
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.health.failures[FailureKind::Cancelled as usize].fetch_add(1, Ordering::Relaxed);
            self.health
                .admission
                .finish(self.ticket, Some(FailureKind::Cancelled), Instant::now());
        }
        self.health.inflight.fetch_sub(1, Ordering::Relaxed);
    }
}
