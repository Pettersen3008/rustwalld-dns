//! Durable policy operations independent of HTTP requests and process signals.
use crate::{
    config::validate_policy,
    downloads, refreshes,
    store::{
        ClearShadowReport, CommitReport, HistoryEntry, Revision, RevisionMode, RevisionSummary,
        Store, StoreMetrics,
    },
};
use rustwalld_dns_core::{Engine, PolicyController, PolicyVersion, PublicationTarget};
use rustwalld_dns_policy::{CheckReport, PolicyConfigSet, PolicyError, PolicySnapshot};
use serde::Serialize;
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Adapter-independent management failure. HTTP status mapping belongs in app.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ControlError {
    /// The request or candidate configuration is invalid.
    #[error("{0}")]
    Invalid(String),
    /// The service is stopping, or storage/compilation workers failed.
    #[error("{0}")]
    Unavailable(String),
    /// Another mutation, download or review is in progress.
    #[error("{0}")]
    Conflict(String),
    /// The caller's expected version is no longer current.
    #[error("configuration changed; inspect the current revision before retrying")]
    Stale,
    #[error("revision not found")]
    MissingRevision,
    /// A remote list download failed.
    #[error("{0}")]
    Upstream(String),
}
fn invalid(error: impl ToString) -> ControlError {
    ControlError::Invalid(error.to_string())
}
fn unavailable(error: impl ToString) -> ControlError {
    ControlError::Unavailable(error.to_string())
}

/// Input to the same assertion-gated workflow used by manual and scheduled edits.
#[non_exhaustive]
pub enum Candidate {
    Config(PolicyConfigSet),
    Shadow,
    Refresh {
        config: PolicyConfigSet,
        source: usize,
    },
}

/// A downloaded list applied to a candidate configuration and checked against
/// every assertion, without creating or publishing a revision.
#[derive(Debug, Serialize)]
pub struct DownloadPreview {
    pub config: PolicyConfigSet,
    pub report: CheckReport,
    /// Whether the downloaded text differs from the candidate's current list.
    pub changed: bool,
}

/// Shared bounded control-plane services. Query workers use only the engine.
///
/// Fields are private so that every durable change passes mutation admission,
/// generation reservation, the configured compiler and checked publication.
#[derive(Clone)]
pub struct ControlService {
    engine: Arc<Engine>,
    store: Store,
    listen: SocketAddr,
    next_generation: Arc<AtomicU64>,
    mutation: Arc<Semaphore>,
    downloads: Arc<Semaphore>,
    refreshes: Arc<refreshes::Refresher>,
    compiler: crate::compiler::Compiler,
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
        if next_generation <= controller.highest_generation()
            || i64::try_from(next_generation).is_err()
        {
            return Err(invalid("invalid next generation"));
        }
        Ok(Self {
            engine,
            compiler: crate::compiler::Compiler::Sequential,
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
    pub(crate) fn with_compiler(mut self, compiler: crate::compiler::Compiler) -> Self {
        self.compiler = compiler;
        self
    }
    /// Next identifier to attempt; callers cannot reset or reuse it.
    pub fn next_generation(&self) -> u64 {
        self.next_generation.load(Ordering::Relaxed)
    }
    /// Read-only DNS engine: snapshots, telemetry and resolver observations.
    /// Publication requires this service's controller.
    #[inline]
    pub fn engine(&self) -> &Arc<Engine> {
        &self.engine
    }
    /// DNS listener used for self-forwarding checks.
    #[inline]
    pub fn listen(&self) -> SocketAddr {
        self.listen
    }
    /// Durable store shared with this service. Read freely; change revisions
    /// only through this service, which reserves generations and publishes.
    #[inline]
    pub fn store(&self) -> &Store {
        &self.store
    }
    /// History persistence counters.
    pub fn store_metrics(&self) -> &StoreMetrics {
        &self.store.metrics
    }
    /// Whether a policy test, stage, clear or preview holds mutation admission.
    pub fn is_mutating(&self) -> bool {
        self.mutation.available_permits() == 0
    }
    /// Whether a list download (preview or scheduled check) holds its slot.
    pub fn is_downloading(&self) -> bool {
        self.downloads.available_permits() == 0
    }
    /// Revision summaries, newest first.
    pub async fn revisions(&self) -> Result<Vec<RevisionSummary>, ControlError> {
        self.store.revisions().await.map_err(unavailable)
    }
    /// The most recent `limit` persisted query events.
    pub async fn queries(&self, limit: usize) -> Result<Vec<HistoryEntry>, ControlError> {
        self.store.queries(limit).await.map_err(unavailable)
    }
    /// Scheduled refresh state for the active generation, including why
    /// checks are paused.
    pub fn refresh_status(&self) -> Result<refreshes::Status, ControlError> {
        let mut status = self
            .refreshes
            .status(&self.engine.active())
            .map_err(unavailable)?;
        status.paused = if self.engine.shadow().is_some() {
            Some("shadow_review")
        } else if self.is_mutating() {
            Some("policy_mutation")
        } else {
            None
        };
        Ok(status)
    }
    /// Queue an immediate scheduled check of `source` against `expected`.
    /// Returns the active generation the check belongs to.
    pub fn queue_refresh(
        &self,
        source: usize,
        expected: PolicyVersion,
    ) -> Result<u64, ControlError> {
        self.admit()?;
        let _guard = self.try_mutation("policy mutation already running")?;
        self.check_revision(Some(expected))?;
        if self.engine.shadow().is_some() || self.is_downloading() {
            return Err(ControlError::Conflict(
                "review the existing shadow or wait for the running download".into(),
            ));
        }
        let snapshot = self.engine.snapshot();
        if snapshot
            .config()
            .filter_sources
            .get(source)
            .is_none_or(|source| source.refresh_interval_secs.is_none())
        {
            return Err(invalid("source has no active refresh schedule"));
        }
        self.refreshes
            .enqueue(&snapshot, source)
            .map_err(ControlError::Conflict)?;
        Ok(snapshot.generation())
    }
    /// Download `source` into `config` and check the result with the configured
    /// compiler. Nothing is persisted or published; stage the returned
    /// configuration to apply it.
    pub async fn preview_download(
        self: &Arc<Self>,
        config: PolicyConfigSet,
        source: usize,
        expected: PolicyVersion,
    ) -> Result<DownloadPreview, ControlError> {
        self.admit()?;
        self.check_revision(Some(expected))?;
        let download = self
            .downloads
            .clone()
            .try_acquire_owned()
            .map_err(|_| ControlError::Conflict("list download already running".into()))?;
        let listen = self.listen;
        // Admission moves into blocking jobs, so caller cancellation cannot
        // release a slot early. The fetch stays cancellable; its guard closes I/O.
        let (mut config, download) = tokio::task::spawn_blocking(move || {
            validate_policy(&config, listen).map_err(invalid)?;
            if source >= config.filter_sources.len() {
                return Err(invalid("unknown source index"));
            }
            Ok((config, download))
        })
        .await
        .map_err(unavailable)??;
        let target = config
            .filter_sources
            .get(source)
            .ok_or_else(|| invalid("unknown source index"))?;
        let (policy, list) = (target.policy.clone(), target.list.clone());
        let (text, stamp) = downloads::fetch(target)
            .await
            .map_err(ControlError::Upstream)?;
        let rules = &mut config
            .policies
            .iter_mut()
            .find(|candidate| candidate.name == policy)
            .and_then(|candidate| candidate.lists.iter_mut().find(|l| l.name == list))
            .ok_or_else(|| invalid("source target missing"))?
            .rules;
        let changed = *rules != text;
        *rules = text;
        config
            .filter_sources
            .get_mut(source)
            .ok_or_else(|| invalid("unknown source index"))?
            .download = Some(stamp);
        let guard = self.try_mutation("policy compilation already running")?;
        // The download took time; never return a candidate for a newer revision.
        self.check_revision(Some(expected))?;
        let compiler = self.compiler.clone();
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            let _download = download;
            validate_policy(&config, listen).map_err(invalid)?;
            let report = compiler.check(config.clone()).map_err(invalid)?;
            if report.valid {
                let raw = report
                    .list_stats
                    .iter()
                    .find(|stats| stats.policy == policy)
                    .and_then(|stats| stats.lists.iter().find(|stats| stats.name == list))
                    .ok_or_else(|| invalid("compiled download target missing"))?
                    .raw;
                if raw == 0 {
                    return Err(invalid("downloaded list has no rules"));
                }
                downloads::validate_size(&config).map_err(invalid)?;
            }
            Ok(DownloadPreview {
                config,
                report,
                changed,
            })
        })
        .await
        .map_err(unavailable)?
    }
    fn try_mutation(&self, busy: &str) -> Result<OwnedSemaphorePermit, ControlError> {
        self.mutation
            .clone()
            .try_acquire_owned()
            .map_err(|_| ControlError::Conflict(busy.into()))
    }
    /// Select a new runtime-only refresh worker while sharing revision admission.
    #[doc(hidden)]
    pub fn with_refresher(mut self, refresher: Arc<refreshes::Refresher>) -> Self {
        self.refreshes = refresher;
        self
    }
    /// Wait until every admitted mutation has completed. A semaphore is
    /// admission, not a mutex held across network I/O.
    pub(crate) async fn drain_mutations(&self) {
        let _ = self.mutation.acquire().await;
    }
    pub(crate) fn refresher(&self) -> &Arc<refreshes::Refresher> {
        &self.refreshes
    }
    pub(crate) fn downloads(&self) -> &Arc<Semaphore> {
        &self.downloads
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
        let guard = self.try_mutation("policy compilation already running")?;
        self.admit()?;
        let listen = self.listen;
        let compiler = self.compiler.clone();
        let accepted = self.accepted();
        tokio::spawn(async move {
            let _guard = guard;
            tokio::task::spawn_blocking(move || {
                validate_policy(&config, listen).map_err(invalid)?;
                validate_intake(&config, &accepted).map_err(invalid)?;
                compiler.check(config).map_err(invalid)
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
        let guard = self.try_mutation("policy compilation already running")?;
        self.admit()?;
        self.check_revision(expected)?;
        // Shadow promotion and refreshes reuse exceptions accepted earlier;
        // only operator-supplied configuration is new intake.
        let (draft, refresh_source, intake) = match candidate {
            Candidate::Config(config) => (Draft::Owned(config), None, Some(self.accepted())),
            Candidate::Refresh { config, source } => (Draft::Owned(config), Some(source), None),
            Candidate::Shadow => (
                Draft::Shadow(
                    self.engine
                        .shadow_snapshot()
                        .ok_or_else(|| invalid("no shadow revision"))?,
                ),
                None,
                None,
            ),
        };
        let id = self.next_generation.fetch_add(1, Ordering::Relaxed);
        if i64::try_from(id).is_err() {
            return Err(unavailable("revision ID exhausted"));
        }
        let state = self.clone();
        let actor = actor.to_owned();
        tokio::spawn(async move {
            let _guard = guard;
            let old = state.engine.snapshot();
            let version = state.version();
            let listen = state.listen;
            let compiler = state.compiler.clone();
            // Cloning, compilation, serialization and diffing are all CPU work
            // proportional to configuration size; keep them off async workers.
            let (snapshot, content, diff) = tokio::task::spawn_blocking(move || {
                let config = draft.into_config();
                validate_policy(&config, listen).map_err(PolicyError::Invalid)?;
                if let Some(accepted) = &intake {
                    validate_intake(&config, accepted)?;
                }
                let snapshot = compiler.compile(config, id)?;
                if let Some(source) = refresh_source {
                    downloads::validate_candidate(&snapshot, source)
                        .map_err(PolicyError::Invalid)?;
                }
                let content = serde_json::to_string(snapshot.config())
                    .map_err(|error| PolicyError::Invalid(error.to_string()))?;
                let diff = configuration_diff(old.config(), snapshot.config());
                Ok::<_, PolicyError>((snapshot, content, diff))
            })
            .await
            .map_err(unavailable)?
            .map_err(invalid)?;
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
        let guard = self.try_mutation("policy mutation already running")?;
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
        if i64::try_from(id).is_err() {
            return Err(ControlError::MissingRevision);
        }
        let revision = self.store.revision(id).await.map_err(unavailable)?;
        revision.ok_or(ControlError::MissingRevision)
    }
}
type Accepted = (Arc<PolicySnapshot>, Option<Arc<PolicySnapshot>>);
impl ControlService {
    /// Live active/shadow revisions whose exceptions passed intake earlier.
    fn accepted(&self) -> Accepted {
        (self.engine.snapshot(), self.engine.shadow_snapshot())
    }
}
fn validate_intake(
    config: &PolicyConfigSet,
    (active, shadow): &Accepted,
) -> Result<(), rustwalld_dns_policy::PolicyError> {
    let mut accepted = vec![active.config()];
    accepted.extend(shadow.as_deref().map(PolicySnapshot::config));
    config.validate_new_exceptions(&accepted)
}
/// Candidate content, cloned from a live shadow only on a blocking thread.
enum Draft {
    Owned(PolicyConfigSet),
    Shadow(Arc<PolicySnapshot>),
}
impl Draft {
    fn into_config(self) -> PolicyConfigSet {
        match self {
            Self::Owned(config) => config,
            Self::Shadow(snapshot) => snapshot.config().clone(),
        }
    }
}
/// Names of the top-level sections that differ, compared in place.
fn configuration_diff(old: &PolicyConfigSet, new: &PolicyConfigSet) -> String {
    [
        ("default_policy", old.default_policy == new.default_policy),
        ("policies", old.policies == new.policies),
        ("upstreams", old.upstreams == new.upstreams),
        ("bindings", old.bindings == new.bindings),
        (
            "allowed_clients",
            old.allowed_clients == new.allowed_clients,
        ),
        ("assertions", old.assertions == new.assertions),
        ("filter_sources", old.filter_sources == new.filter_sources),
    ]
    .iter()
    .filter(|(_, same)| !same)
    .map(|(field, _)| *field)
    .collect::<Vec<_>>()
    .join(", ")
}
