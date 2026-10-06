//! Per-endpoint admission. The short mutex is never held across I/O or an await.
use crate::FailureKind;
use serde::Serialize;
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

const FAILURE_THRESHOLD: u8 = 3;
const INITIAL_DELAY: Duration = Duration::from_millis(250);
const MAX_STEP: u8 = 3; // 250 ms, 500 ms, 1 s, 2 s; never an unbounded timer.

#[derive(Debug, Default)]
struct State {
    epoch: u64,
    failures: u8,
    step: u8,
    until: Option<Instant>,
    probing: bool,
}
#[derive(Debug, Default)]
pub(crate) struct Admission(Mutex<State>);
#[derive(Clone, Copy)]
pub(crate) struct Ticket {
    epoch: u64,
    pub(crate) probe: bool,
}
#[derive(Debug, Serialize)]
pub struct AdmissionStatus {
    pub state: &'static str,
    pub retry_after_ms: u64,
}

impl Admission {
    pub(crate) fn enter(&self, now: Instant) -> Option<Ticket> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if state.probing || state.until.is_some_and(|until| now < until) {
            return None;
        }
        let probe = state.until.is_some();
        if probe {
            state.probing = true;
            state.epoch = state.epoch.wrapping_add(1);
        }
        Some(Ticket {
            epoch: state.epoch,
            probe,
        })
    }
    pub(crate) fn finish(&self, ticket: Ticket, failure: Option<FailureKind>, now: Instant) {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        // Replies already in flight when a cooldown/probe started cannot change
        // its state. In particular an old success cannot release a newer probe.
        if ticket.epoch != state.epoch {
            return;
        }
        if failure.is_none()
            || matches!(failure, Some(FailureKind::Servfail | FailureKind::Refused))
        {
            state.failures = 0;
            if ticket.probe {
                state.step = 0;
                state.until = None;
                state.probing = false;
                state.epoch = state.epoch.wrapping_add(1);
            }
        } else if failure.is_some_and(qualifies) {
            state.failures = state.failures.saturating_add(1);
            if ticket.probe || state.failures >= FAILURE_THRESHOLD {
                if ticket.probe {
                    state.step = state.step.saturating_add(1).min(MAX_STEP);
                }
                state.until = Some(now + INITIAL_DELAY * (1 << state.step));
                state.probing = false;
                state.epoch = state.epoch.wrapping_add(1);
            }
        } else if ticket.probe {
            // Cancellation/deadline does not prove remote failure. Release the
            // single probe slot without a penalty; the next query may retry.
            state.probing = false;
            state.epoch = state.epoch.wrapping_add(1);
        } else {
            // Ambiguous and local failures break the qualifying streak.
            state.failures = 0;
        }
    }
    pub(crate) fn status(&self, now: Instant) -> AdmissionStatus {
        let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let remaining = state
            .until
            .map(|until| until.saturating_duration_since(now))
            .unwrap_or_default();
        AdmissionStatus {
            state: if state.probing {
                "probing"
            } else if state.until.is_some() {
                "cooldown"
            } else {
                "ready"
            },
            retry_after_ms: remaining
                .as_nanos()
                .div_ceil(1_000_000)
                .min(u64::MAX as u128) as u64,
        }
    }
}
fn qualifies(kind: FailureKind) -> bool {
    matches!(
        kind,
        FailureKind::Connection
            | FailureKind::TlsAuthentication
            | FailureKind::TlsProtocol
            | FailureKind::HttpProtocol
            | FailureKind::HttpStatus
            | FailureKind::HttpEnvelope
            | FailureKind::DnsResponse
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn trip(gate: &Admission, now: Instant) {
        for _ in 0..FAILURE_THRESHOLD {
            gate.finish(
                gate.enter(now).unwrap(),
                Some(FailureKind::DnsResponse),
                now,
            );
        }
        assert!(gate.enter(now).is_none());
    }
    #[test]
    fn bounded_delay_single_probe_and_stale_completion() {
        let gate = Admission::default();
        let mut now = Instant::now();
        let old = gate.enter(now).unwrap();
        trip(&gate, now);
        gate.finish(old, None, now);
        assert!(gate.enter(now).is_none());
        for step in 0..8 {
            now += INITIAL_DELAY * (1 << step.min(MAX_STEP));
            let probe = gate.enter(now).unwrap();
            assert!(probe.probe);
            assert!(gate.enter(now).is_none());
            gate.finish(probe, Some(FailureKind::DnsResponse), now);
            assert!(gate.status(now).retry_after_ms <= 2000);
        }
        now += Duration::from_secs(2);
        let probe = gate.enter(now).unwrap();
        gate.finish(probe, None, now);
        assert_eq!(gate.status(now).state, "ready");
        assert!(!gate.enter(now).unwrap().probe);
    }
    #[test]
    fn retry_hint_rounds_up_and_validated_domain_errors_restore_admission() {
        for kind in [FailureKind::Servfail, FailureKind::Refused] {
            let gate = Admission::default();
            let now = Instant::now();
            let old = gate.enter(now).unwrap();
            trip(&gate, now);
            assert_eq!(
                gate.status(now + INITIAL_DELAY - Duration::from_nanos(1))
                    .retry_after_ms,
                1
            );
            let probe = gate.enter(now + INITIAL_DELAY).unwrap();
            gate.finish(probe, Some(kind), now + INITIAL_DELAY);
            assert_eq!(gate.status(now + INITIAL_DELAY).state, "ready");
            gate.finish(
                old,
                Some(FailureKind::TlsAuthentication),
                now + INITIAL_DELAY,
            );
            assert_eq!(gate.status(now + INITIAL_DELAY).state, "ready");
        }
    }
    #[test]
    fn cancellation_and_ambiguous_failures_do_not_poison_endpoint() {
        let gate = Admission::default();
        let now = Instant::now();
        for kind in [
            FailureKind::Servfail,
            FailureKind::Refused,
            FailureKind::Deadline,
            FailureKind::Cancelled,
            FailureKind::LocalError,
        ] {
            for _ in 0..5 {
                gate.finish(gate.enter(now).unwrap(), Some(kind), now);
            }
            assert_eq!(gate.status(now).state, "ready");
        }
        trip(&gate, now);
        let later = now + INITIAL_DELAY;
        let probe = gate.enter(later).unwrap();
        gate.finish(probe, Some(FailureKind::Cancelled), later);
        let second = gate.enter(later).unwrap();
        // Even a late completion of the cancelled probe cannot release second.
        gate.finish(probe, None, later);
        assert!(gate.enter(later).is_none());
        gate.finish(second, None, later);
        assert_eq!(gate.status(later).state, "ready");
    }
}
