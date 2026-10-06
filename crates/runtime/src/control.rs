//! Durable policy operations independent of HTTP requests and process signals.
use crate::{
    config::validate_policy,
    downloads, refreshes,
    store::{ClearShadowReport, CommitReport, Revision, RevisionMode, Store},
};
use rustwalld_dns_core::{Engine, PolicyController, PolicyVersion, PublicationTarget};
use rustwalld_dns_policy::{CheckReport, PolicyConfigSet, PolicySnapshot};
use serde_json::Value;
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use tokio::sync::Semaphore;

/// Adapter-independent management failure. HTTP status mapping belongs in app.
#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Unavailable(String),
    #[error("{0}")]
    Conflict(String),
    #[error("configuration changed; inspect the current revision before retrying")]
    Stale,
    #[error("revision not found")]
    MissingRevision,
}
fn invalid(error: impl ToString) -> ControlError {
    ControlError::Invalid(error.to_string())
}
fn unavailable(error: impl ToString) -> ControlError {
    ControlError::Unavailable(error.to_string())
}

/// Input to the same assertion-gated workflow used by manual and scheduled edits.
pub enum Candidate {
    Config(PolicyConfigSet),
    Shadow,
    Refresh {
        config: PolicyConfigSet,
        source: usize,
    },
}

/// Shared bounded control-plane services. Query workers use only `engine`.
#[derive(Clone)]
pub struct ControlService {
    pub engine: Arc<Engine>,
    pub store: Store,
    pub listen: SocketAddr,
    next_generation: Arc<AtomicU64>,
    pub mutation: Arc<Semaphore>,
    pub downloads: Arc<Semaphore>,
    pub refreshes: Arc<refreshes::Refresher>,
    controller: PolicyController,
    stopping: Arc<AtomicBool>,
}
impl ControlService {
    /// Pair the engine's write capability with its durable store.
    /// `next_generation` comes from the maximum durable revision ID plus one.
    pub fn new(
        engine: Arc<Engine>,
        controller: PolicyController,
        store: Store,
        listen: SocketAddr,
        next_generation: u64,
    ) -> Result<Self, ControlError> {
        if !engine.is_controlled_by(&controller) {
            return Err(invalid("policy controller belongs to a different engine"));
        }
        if next_generation <= controller.highest_generation() || next_generation > i64::MAX as u64 {
            return Err(invalid("invalid next generation"));
        }
        Ok(Self {
            engine,
            controller,
            stopping: Arc::new(AtomicBool::new(false)),
            store,
            listen,
            next_generation: Arc::new(AtomicU64::new(next_generation)),
            mutation: Arc::new(Semaphore::new(1)),
            downloads: Arc::new(Semaphore::new(1)),
            refreshes: Arc::new(refreshes::Refresher::default()),
        })
    }
    /// Next identifier to attempt; callers cannot reset or reuse it.
    pub fn next_generation(&self) -> u64 {
        self.next_generation.load(Ordering::Relaxed)
    }
    /// Select a new runtime-only refresh worker while sharing revision admission.
    pub fn with_refresher(mut self, refresher: Arc<refreshes::Refresher>) -> Self {
        self.refreshes = refresher;
        self
    }
    pub(crate) fn stop_admission(&self) {
        self.stopping.store(true, Ordering::Release);
    }
    fn admit(&self) -> Result<(), ControlError> {
        if self.stopping.load(Ordering::Acquire) {
            Err(unavailable("control service stopped"))
        } else {
            Ok(())
        }
    }
    pub fn version(&self) -> PolicyVersion {
        self.controller.version()
    }
    pub fn check_revision(&self, expected: Option<PolicyVersion>) -> Result<(), ControlError> {
        if expected.is_some_and(|expected| self.version() != expected) {
            Err(ControlError::Stale)
        } else {
            Ok(())
        }
    }
    /// Report every assertion without creating or publishing a revision.
    pub async fn test(
        self: &Arc<Self>,
        config: PolicyConfigSet,
    ) -> Result<CheckReport, ControlError> {
        self.admit()?;
        let guard = self
            .mutation
            .clone()
            .try_acquire_owned()
            .map_err(|_| ControlError::Conflict("policy compilation already running".into()))?;
        self.admit()?;
        let listen = self.listen;
        tokio::spawn(async move {
            let _guard = guard;
            tokio::task::spawn_blocking(move || {
                validate_policy(&config, listen).map_err(invalid)?;
                PolicySnapshot::check(config).map_err(invalid)
            })
            .await
            .map_err(unavailable)?
        })
        .await
        .map_err(unavailable)?
    }
    /// Persist and publish a new revision. Client cancellation cannot interrupt
    /// the admitted commit/publication sequence; shutdown drains admitted work.
    pub async fn stage(
        self: &Arc<Self>,
        candidate: Candidate,
        expected: Option<PolicyVersion>,
        target: PublicationTarget,
        actor: &str,
    ) -> Result<CommitReport, ControlError> {
        self.admit()?;
        let guard = self
            .mutation
            .clone()
            .try_acquire_owned()
            .map_err(|_| ControlError::Conflict("policy compilation already running".into()))?;
        self.admit()?;
        self.check_revision(expected)?;
        let (config, refresh_source) = match candidate {
            Candidate::Config(config) => (config, None),
            Candidate::Refresh { config, source } => (config, Some(source)),
            Candidate::Shadow => (
                self.engine
                    .shadow_snapshot()
                    .ok_or_else(|| invalid("no shadow revision"))?
                    .config()
                    .clone(),
                None,
            ),
        };
        let id = self.next_generation.fetch_add(1, Ordering::Relaxed);
        if id > i64::MAX as u64 {
            return Err(unavailable("revision ID exhausted"));
        }
        let state = self.clone();
        let actor = actor.to_owned();
        tokio::spawn(async move {
            let _guard = guard;
            let old = state.engine.snapshot();
            let version = state.version();
            let listen = state.listen;
            let snapshot = tokio::task::spawn_blocking(move || {
                validate_policy(&config, listen)
                    .map_err(rustwalld_dns_policy::PolicyError::Invalid)?;
                let snapshot = PolicySnapshot::compile(config, id)?;
                if let Some(source) = refresh_source {
                    downloads::validate_candidate(&snapshot, source)
                        .map_err(rustwalld_dns_policy::PolicyError::Invalid)?;
                }
                Ok::<_, rustwalld_dns_policy::PolicyError>(snapshot)
            })
            .await
            .map_err(unavailable)?
            .map_err(invalid)?;
            let content = serde_json::to_string(snapshot.config()).map_err(unavailable)?;
            let diff = configuration_diff(old.config(), snapshot.config());
            let pending = state
                .controller
                .prepare(snapshot, target, version)
                .map_err(unavailable)?;
            let shadow = target == PublicationTarget::Shadow;
            let result = state
                .store
                .commit(
                    id,
                    content,
                    if shadow {
                        RevisionMode::Shadow
                    } else {
                        RevisionMode::Promoted
                    },
                    actor,
                    diff,
                )
                .await
                .map_err(unavailable)?;
            pending.commit();
            tracing::info!(generation = id, shadow, "policy revision published");
            Ok(result)
        })
        .await
        .map_err(unavailable)?
    }
    /// Scheduled changed content stages only a shadow against its captured version.
    pub async fn stage_refresh(
        self: &Arc<Self>,
        config: PolicyConfigSet,
        source: usize,
        generation: u64,
    ) -> Result<(), ControlError> {
        self.stage(
            Candidate::Refresh { config, source },
            Some(PolicyVersion {
                active: generation,
                shadow: None,
            }),
            PublicationTarget::Shadow,
            "scheduled-refresh",
        )
        .await?;
        Ok(())
    }
    /// Persist shadow removal before clearing live shadow state.
    pub async fn clear_shadow(
        self: &Arc<Self>,
        expected: Option<PolicyVersion>,
    ) -> Result<ClearShadowReport, ControlError> {
        self.admit()?;
        let guard = self
            .mutation
            .clone()
            .try_acquire_owned()
            .map_err(|_| ControlError::Conflict("policy mutation already running".into()))?;
        self.admit()?;
        self.check_revision(expected)?;
        let state = self.clone();
        tokio::spawn(async move {
            let _guard = guard;
            let pending = state
                .controller
                .prepare_clear(state.version())
                .map_err(unavailable)?;
            let result = state.store.clear_shadow().await.map_err(unavailable)?;
            pending.commit();
            Ok(result)
        })
        .await
        .map_err(unavailable)?
    }
    /// Read a historical draft. Rollback subsequently recompiles as a fresh ID.
    pub async fn revision(&self, id: u64) -> Result<Revision, ControlError> {
        if id > i64::MAX as u64 {
            return Err(ControlError::MissingRevision);
        }
        let revision = self.store.revision(id).await.map_err(unavailable)?;
        revision.ok_or(ControlError::MissingRevision)
    }
}
fn configuration_diff(old: &PolicyConfigSet, new: &PolicyConfigSet) -> String {
    let old = serde_json::to_value(old).unwrap_or(Value::Null);
    let new = serde_json::to_value(new).unwrap_or(Value::Null);
    [
        "default_policy",
        "policies",
        "upstreams",
        "bindings",
        "allowed_clients",
        "assertions",
        "filter_sources",
    ]
    .iter()
    .filter(|field| old.get(**field) != new.get(**field))
    .copied()
    .collect::<Vec<_>>()
    .join(", ")
}
