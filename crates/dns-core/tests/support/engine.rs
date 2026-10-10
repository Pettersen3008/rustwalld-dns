//! Fixture compatibility for pre-refactor benchmarks and protocol cases.
#![allow(clippy::unwrap_used, dead_code)]
use rustwalld_dns_core::{
    Engine, EngineConfig, PolicyController, PublicationTarget, telemetry::Telemetry,
};
use rustwalld_dns_policy::PolicySnapshot;
use std::{ops::Deref, sync::Arc};

pub struct TestEngine {
    inner: Arc<Engine>,
    pub active: Active,
    pub shadow: Shadow,
    config: EngineConfig,
}
pub struct Active(PolicyController);
pub struct Shadow(PolicyController);
impl TestEngine {
    pub fn new(
        snapshot: PolicySnapshot,
        cache_entries: usize,
        decision_entries: usize,
        max_inflight: usize,
        telemetry: Telemetry,
    ) -> Self {
        let config = EngineConfig {
            cache_entries,
            decision_entries,
            max_inflight,
            ..Default::default()
        };
        let (engine, control) = Engine::controlled(snapshot, config, telemetry);
        Self {
            inner: Arc::new(engine),
            active: Active(control.clone()),
            shadow: Shadow(control),
            config,
        }
    }
    pub fn handle(&self) -> Arc<Engine> {
        self.inner.clone()
    }
    #[allow(dead_code)]
    pub fn with_telemetry(mut self, telemetry: Telemetry) -> Self {
        let inner =
            Arc::try_unwrap(self.inner).unwrap_or_else(|_| panic!("fixture engine is shared"));
        self.inner = Arc::new(inner.with_telemetry(telemetry));
        self
    }
    #[allow(dead_code)]
    pub fn without_response_cache(self) -> Self {
        Self::new(
            PolicySnapshot::compile(
                self.active.load().config().clone(),
                self.active.load().generation(),
            )
            .unwrap(),
            0,
            self.config.decision_entries,
            self.config.max_inflight,
            self.telemetry().clone(),
        )
    }
}
impl Deref for TestEngine {
    type Target = Engine;
    fn deref(&self) -> &Engine {
        &self.inner
    }
}
impl Active {
    pub fn load(&self) -> arc_swap::Guard<Arc<PolicySnapshot>> {
        self.0.active()
    }
    #[allow(dead_code)]
    pub fn load_full(&self) -> Arc<PolicySnapshot> {
        self.0.snapshot()
    }
    pub fn store(&self, snapshot: Arc<PolicySnapshot>) {
        self.swap(snapshot);
    }
    pub fn swap(&self, snapshot: Arc<PolicySnapshot>) -> Arc<PolicySnapshot> {
        let snapshot =
            Arc::try_unwrap(snapshot).unwrap_or_else(|_| panic!("fixture snapshot is shared"));
        self.0
            .prepare(snapshot, PublicationTarget::Active, self.0.version())
            .unwrap()
            .commit()
    }
}
impl Shadow {
    #[allow(dead_code)]
    pub fn load(&self) -> arc_swap::Guard<Option<Arc<PolicySnapshot>>> {
        self.0.shadow()
    }
    #[allow(dead_code)]
    pub fn load_full(&self) -> Option<Arc<PolicySnapshot>> {
        self.0.shadow_snapshot()
    }
    #[allow(dead_code)]
    pub fn store(&self, snapshot: Option<Arc<PolicySnapshot>>) {
        let pending = match snapshot {
            Some(snapshot) => self
                .0
                .prepare(
                    Arc::try_unwrap(snapshot)
                        .unwrap_or_else(|_| panic!("fixture snapshot is shared")),
                    PublicationTarget::Shadow,
                    self.0.version(),
                )
                .unwrap(),
            None => self.0.prepare_clear(self.0.version()).unwrap(),
        };
        pending.commit();
    }
}
