//! Checked control-plane publication. Queries never acquire this mutex.
use arc_swap::{ArcSwap, ArcSwapOption, Guard};
use rustwalld_dns_policy::PolicySnapshot;
use std::sync::{Arc, Mutex};

/// Active and optional shadow identifiers used for optimistic concurrency.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyVersion {
    /// Active generation.
    pub active: u64,
    /// Shadow generation, if one is staged.
    pub shadow: Option<u64>,
}

/// Target of an assertion-gated publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationTarget {
    /// Enforce the snapshot; clears any shadow.
    Active,
    /// Stage the snapshot for side-by-side evaluation without enforcing it.
    Shadow,
}

/// A policy update was rejected before changing live state.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PublicationError {
    /// Another reservation is outstanding.
    #[error("policy publication already running")]
    Busy,
    /// The live version differs from the caller's expected version.
    #[error("configuration changed; inspect the current revision before retrying")]
    Stale,
    /// The snapshot's generation was already reserved or published.
    #[error("policy generation must exceed all previously reserved generations")]
    Generation,
    /// A restored generation high-water mark is lower than a snapshot's generation.
    #[error("restored generation high-water mark is invalid")]
    Restore,
}

struct Admission {
    highest: u64,
    busy: bool,
}
struct Inner {
    active: Arc<ArcSwap<PolicySnapshot>>,
    shadow: Arc<ArcSwapOption<PolicySnapshot>>,
    admission: Mutex<Admission>,
}

/// Write capability kept separately from the serving engine.
///
/// Compilation belongs off the DNS executor. This handle validates generation
/// and concurrency preconditions, but cannot verify a host's persistence. A
/// durable host reserves an update, commits its revision, then calls
/// [`PendingPublication::commit`]. Dropping a reservation leaves live policy
/// unchanged and burns its generation identifier.
#[derive(Clone)]
pub struct PolicyController {
    inner: Arc<Inner>,
}
impl PolicyController {
    pub(crate) fn new(
        active: Arc<ArcSwap<PolicySnapshot>>,
        shadow: Arc<ArcSwapOption<PolicySnapshot>>,
        highest: u64,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                active,
                shadow,
                admission: Mutex::new(Admission {
                    highest,
                    busy: false,
                }),
            }),
        }
    }
    pub(crate) fn controls(&self, active: &Arc<ArcSwap<PolicySnapshot>>) -> bool {
        Arc::ptr_eq(&self.inner.active, active)
    }
    /// Highest reserved identifier, including aborted and retired revisions.
    pub fn highest_generation(&self) -> u64 {
        self.inner
            .admission
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .highest
    }
    /// Read a snapshot without exposing its ArcSwap write handle.
    pub fn active(&self) -> Guard<Arc<PolicySnapshot>> {
        self.inner.active.load()
    }
    /// Pin an active generation across asynchronous work.
    pub fn snapshot(&self) -> Arc<PolicySnapshot> {
        self.inner.active.load_full()
    }
    /// Read the shadow snapshot without exposing its write handle.
    pub fn shadow(&self) -> Guard<Option<Arc<PolicySnapshot>>> {
        self.inner.shadow.load()
    }
    /// Pin a shadow generation across asynchronous work.
    pub fn shadow_snapshot(&self) -> Option<Arc<PolicySnapshot>> {
        self.inner.shadow.load_full()
    }
    /// Consistent control-plane version. This is not called by query processing.
    pub fn version(&self) -> PolicyVersion {
        let _admission = self
            .inner
            .admission
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        self.current_version()
    }
    fn current_version(&self) -> PolicyVersion {
        PolicyVersion {
            active: self.inner.active.load().generation(),
            shadow: self.inner.shadow.load().as_ref().map(|s| s.generation()),
        }
    }
    /// Reserve an immutable, assertion-gated candidate without publishing it.
    /// No mutex is retained by the returned reservation, including across awaits.
    pub fn prepare(
        &self,
        snapshot: PolicySnapshot,
        target: PublicationTarget,
        expected: PolicyVersion,
    ) -> Result<PendingPublication, PublicationError> {
        let action = match target {
            PublicationTarget::Active => Action::Active(Arc::new(snapshot)),
            PublicationTarget::Shadow => Action::Shadow(Arc::new(snapshot)),
        };
        self.reserve(action, expected)
    }
    /// Reserve shadow removal. A durable host persists removal before commit.
    pub fn prepare_clear(
        &self,
        expected: PolicyVersion,
    ) -> Result<PendingPublication, PublicationError> {
        self.reserve(Action::Clear, expected)
    }
    fn reserve(
        &self,
        action: Action,
        expected: PolicyVersion,
    ) -> Result<PendingPublication, PublicationError> {
        let mut admission = self
            .inner
            .admission
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if admission.busy {
            return Err(PublicationError::Busy);
        }
        if self.current_version() != expected {
            return Err(PublicationError::Stale);
        }
        if let Action::Active(snapshot) | Action::Shadow(snapshot) = &action {
            if snapshot.generation() <= admission.highest {
                return Err(PublicationError::Generation);
            }
            admission.highest = snapshot.generation();
        }
        admission.busy = true;
        Ok(PendingPublication {
            inner: self.inner.clone(),
            action,
            committed: false,
        })
    }
}
enum Action {
    Active(Arc<PolicySnapshot>),
    Shadow(Arc<PolicySnapshot>),
    Clear,
}

/// Exclusive publication reservation; dropping it aborts without publication.
/// The caller must finish any durable commit before committing this reservation.
#[must_use = "dropping a reservation aborts publication"]
pub struct PendingPublication {
    inner: Arc<Inner>,
    action: Action,
    committed: bool,
}
impl PendingPublication {
    /// Publish after successful persistence, returning the previous active snapshot.
    /// This performs no I/O and cannot fail after the durable commit.
    pub fn commit(mut self) -> Arc<PolicySnapshot> {
        let mut admission = self
            .inner
            .admission
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let previous = match &self.action {
            Action::Active(snapshot) => {
                let previous = self.inner.active.swap(snapshot.clone());
                self.inner.shadow.store(None);
                previous
            }
            Action::Shadow(snapshot) => {
                self.inner.shadow.store(Some(snapshot.clone()));
                self.inner.active.load_full()
            }
            Action::Clear => {
                self.inner.shadow.store(None);
                self.inner.active.load_full()
            }
        };
        admission.busy = false;
        self.committed = true;
        previous
    }
}
impl Drop for PendingPublication {
    fn drop(&mut self) {
        if !self.committed {
            self.inner
                .admission
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .busy = false;
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::{Engine, EngineConfig, telemetry::Telemetry};
    use rustwalld_dns_policy::PolicyConfigSet;
    fn snapshot(generation: u64) -> PolicySnapshot {
        PolicySnapshot::compile(PolicyConfigSet::default(), generation).unwrap()
    }
    fn setup() -> (Engine, PolicyController) {
        let (telemetry, _) = Telemetry::channel(1);
        Engine::controlled(snapshot(1), EngineConfig::default(), telemetry)
    }
    #[test]
    fn controllers_are_bound_to_their_engine() {
        let (first, controller) = setup();
        let (second, other) = setup();
        assert!(first.is_controlled_by(&controller));
        assert!(!first.is_controlled_by(&other));
        assert!(!second.is_controlled_by(&controller));
    }
    #[test]
    fn reservations_reject_stale_busy_and_reused_ids_without_changing_live_policy() {
        let (engine, controller) = setup();
        let initial = controller.version();
        let pending = controller
            .prepare(snapshot(2), PublicationTarget::Shadow, initial)
            .unwrap();
        assert!(matches!(
            controller.prepare(snapshot(3), PublicationTarget::Active, initial),
            Err(PublicationError::Busy)
        ));
        assert_eq!(engine.active().generation(), 1);
        assert!(engine.shadow().is_none());
        drop(pending);
        assert!(matches!(
            controller.prepare(snapshot(2), PublicationTarget::Active, initial),
            Err(PublicationError::Generation)
        ));
        controller
            .prepare(snapshot(3), PublicationTarget::Shadow, initial)
            .unwrap()
            .commit();
        assert!(matches!(
            controller.prepare(snapshot(4), PublicationTarget::Active, initial),
            Err(PublicationError::Stale)
        ));
        assert_eq!(engine.active().generation(), 1);
        assert_eq!(engine.shadow().as_ref().unwrap().generation(), 3);
        let previous = controller
            .prepare(snapshot(4), PublicationTarget::Active, controller.version())
            .unwrap()
            .commit();
        assert_eq!(previous.generation(), 1);
        assert_eq!(engine.active().generation(), 4);
        assert!(engine.shadow().is_none());
    }
    #[test]
    fn restore_includes_retired_revisions_and_clear_reservations_are_abortable() {
        let (telemetry, _) = Telemetry::channel(1);
        let (engine, controller) = Engine::restore(
            snapshot(7),
            Some(snapshot(9)),
            100,
            EngineConfig::default(),
            telemetry,
        )
        .unwrap();
        assert!(matches!(
            controller.prepare(
                snapshot(99),
                PublicationTarget::Active,
                controller.version()
            ),
            Err(PublicationError::Generation)
        ));
        drop(controller.prepare_clear(controller.version()).unwrap());
        assert_eq!(engine.shadow().as_ref().unwrap().generation(), 9);
        controller
            .prepare_clear(controller.version())
            .unwrap()
            .commit();
        assert!(engine.shadow().is_none());
        controller
            .prepare(
                snapshot(101),
                PublicationTarget::Active,
                controller.version(),
            )
            .unwrap()
            .commit();
        assert_eq!(engine.active().generation(), 101);
        let (telemetry, _) = Telemetry::channel(1);
        assert!(matches!(
            Engine::restore(
                snapshot(7),
                Some(snapshot(9)),
                8,
                EngineConfig::default(),
                telemetry
            ),
            Err(PublicationError::Restore)
        ));
    }
    #[test]
    fn concurrent_writers_admit_exactly_one_reservation() {
        let (_engine, controller) = setup();
        let version = controller.version();
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let results = std::thread::scope(|scope| {
            let handles = (2..10)
                .map(|generation| {
                    let controller = controller.clone();
                    let barrier = barrier.clone();
                    scope.spawn(move || {
                        let snapshot = snapshot(generation);
                        barrier.wait();
                        controller.prepare(snapshot, PublicationTarget::Active, version)
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        drop(results);
        assert_eq!(controller.version(), version);
    }
}
