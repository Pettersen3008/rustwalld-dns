//! One bounded control-plane worker. Timers never promote production policy.
use crate::{ControlService, downloads};
use rustwalld_dns_policy::{DownloadStamp, FilterSource, PolicyConfigSet, PolicySnapshot};
use serde::Serialize;
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Notify, OwnedSemaphorePermit};
use tokio_util::sync::CancellationToken;

const RETRY_BUSY: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    #[default]
    Waiting,
    Unchanged,
    Staged,
    Failed,
    Deferred,
    Cancelled,
}
#[derive(Clone, Serialize)]
pub struct Running {
    generation: u64,
    source: usize,
    policy: String,
    list: String,
}
#[derive(Clone, Copy, Serialize)]
pub struct Queued {
    generation: u64,
    source: usize,
}
#[derive(Serialize)]
pub struct EntryStatus {
    source: usize,
    policy: String,
    list: String,
    interval_secs: u64,
    next_check_at: u64,
    last_checked_at: Option<u64>,
    checked_generation: Option<u64>,
    outcome: Outcome,
    error: Option<String>,
    last_http_status: Option<u16>,
    last_download_bytes: Option<usize>,
}
#[derive(Serialize)]
pub struct Status {
    generation: u64,
    pub paused: Option<&'static str>,
    running: Option<Running>,
    queued: Option<Queued>,
    entries: Vec<EntryStatus>,
}
#[derive(Clone)]
struct Cached {
    // Last live generation validated against this fingerprint; None for staged bytes.
    generation: Option<u64>,
    sha256: String,
    bytes: usize,
    validators: downloads::Validators,
}
struct Entry {
    index: usize,
    source: FilterSource,
    next: Instant,
    last_checked: Option<u64>,
    checked_generation: Option<u64>,
    outcome: Outcome,
    error: Option<String>,
    transfer: Option<(u16, usize)>,
    cached: Option<Cached>,
}
#[derive(Default)]
struct Runtime {
    generation: u64,
    entries: Vec<Entry>,
    running: Option<Running>,
    queued: Option<Queued>,
}
#[derive(Default)]
pub struct Refresher {
    inner: Mutex<Runtime>,
    wake: Notify,
}
fn wall_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.as_secs())
}
fn same_source(a: &FilterSource, b: &FilterSource) -> bool {
    a.policy == b.policy
        && a.list == b.list
        && a.url == b.url
        && a.bootstrap_ips == b.bootstrap_ips
        && a.ca_pem == b.ca_pem
        && a.refresh_interval_secs == b.refresh_interval_secs
}
impl Runtime {
    fn synchronize(&mut self, snapshot: &PolicySnapshot, now: Instant, wall: u64) {
        // Rollback also allocates a new generation. A delayed status/begin call
        // carrying a retired Arc must never rewind deadlines or clear a new queue.
        if self.generation >= snapshot.generation() {
            return;
        }
        self.generation = snapshot.generation();
        if self
            .queued
            .is_some_and(|queued| queued.generation != self.generation)
        {
            self.queued = None;
        }
        let mut old = std::mem::take(&mut self.entries);
        self.entries = snapshot
            .config()
            .filter_sources
            .iter()
            .enumerate()
            .filter_map(|(index, source)| {
                let interval = source.refresh_interval_secs?;
                if let Some(position) = old
                    .iter()
                    .position(|entry| same_source(&entry.source, source))
                {
                    let mut entry = old.swap_remove(position);
                    entry.index = index;
                    if entry.source.download != source.download
                        && let Some(stamp) = &source.download
                    {
                        let remaining =
                            interval.saturating_sub(wall.saturating_sub(stamp.retrieved_at));
                        entry.next = entry.next.max(now + Duration::from_secs(remaining));
                    }
                    entry.source = source.clone();
                    Some(entry)
                } else {
                    let remaining = source.download.as_ref().map_or(0, |stamp| {
                        interval.saturating_sub(wall.saturating_sub(stamp.retrieved_at))
                    });
                    Some(Entry {
                        index,
                        source: source.clone(),
                        next: now + Duration::from_secs(remaining),
                        last_checked: None,
                        checked_generation: None,
                        outcome: Outcome::Waiting,
                        error: None,
                        transfer: None,
                        cached: None,
                    })
                }
            })
            .collect();
    }
}
impl Refresher {
    fn discard_queued(&self) -> Result<(), String> {
        self.inner
            .lock()
            .map_err(|_| "refresh state unavailable")?
            .queued = None;
        Ok(())
    }
    pub fn status(&self, snapshot: &PolicySnapshot) -> Result<Status, String> {
        let now = Instant::now();
        let wall = wall_now();
        let mut runtime = self.inner.lock().map_err(|_| "refresh state unavailable")?;
        runtime.synchronize(snapshot, now, wall);
        Ok(Status {
            generation: runtime.generation,
            paused: None,
            running: runtime.running.clone(),
            queued: runtime.queued,
            entries: runtime
                .entries
                .iter()
                .map(|entry| EntryStatus {
                    source: entry.index,
                    policy: entry.source.policy.clone(),
                    list: entry.source.list.clone(),
                    interval_secs: entry.source.refresh_interval_secs.unwrap_or(0),
                    next_check_at: wall
                        .saturating_add(entry.next.saturating_duration_since(now).as_secs()),
                    last_checked_at: entry.last_checked,
                    checked_generation: entry.checked_generation,
                    outcome: entry.outcome,
                    error: entry.error.clone(),
                    last_http_status: entry.transfer.map(|value| value.0),
                    last_download_bytes: entry.transfer.map(|value| value.1),
                })
                .collect(),
        })
    }
    pub fn enqueue(&self, snapshot: &PolicySnapshot, index: usize) -> Result<(), String> {
        let mut runtime = self.inner.lock().map_err(|_| "refresh state unavailable")?;
        runtime.synchronize(snapshot, Instant::now(), wall_now());
        if runtime.generation != snapshot.generation() {
            return Err("configuration changed before scheduling the check".into());
        }
        if runtime.running.is_some() || runtime.queued.is_some() {
            return Err("scheduled check already queued or running".into());
        }
        if !runtime.entries.iter().any(|entry| entry.index == index) {
            return Err("source has no active refresh schedule".into());
        }
        runtime.queued = Some(Queued {
            generation: snapshot.generation(),
            source: index,
        });
        drop(runtime);
        self.wake.notify_one();
        Ok(())
    }
    fn begin(
        self: &Arc<Self>,
        snapshot: Arc<PolicySnapshot>,
        downloads: &Arc<tokio::sync::Semaphore>,
    ) -> Result<Option<Job>, String> {
        let now = Instant::now();
        let mut runtime = self.inner.lock().map_err(|_| "refresh state unavailable")?;
        runtime.synchronize(&snapshot, now, wall_now());
        if runtime.running.is_some() || runtime.generation != snapshot.generation() {
            return Ok(None);
        }
        // Peek at a manual request; it is consumed only once a download slot
        // is held, so contention defers it instead of losing it.
        let queued = runtime.queued;
        let position = if let Some(queued) = queued {
            let position = runtime
                .entries
                .iter()
                .position(|entry| entry.index == queued.source);
            if position.is_none() {
                runtime.queued = None;
            }
            position
        } else {
            runtime
                .entries
                .iter()
                .enumerate()
                .filter(|(_, entry)| entry.next <= now)
                .min_by_key(|(_, entry)| entry.next)
                .map(|(position, _)| position)
        };
        let Some(entry) = position.and_then(|position| runtime.entries.get_mut(position)) else {
            return Ok(None);
        };
        let permit = match downloads.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                entry.outcome = Outcome::Deferred;
                entry.error = Some("another list download is running".into());
                entry.next = now + RETRY_BUSY;
                return Ok(None);
            }
        };
        let source = entry.source.clone();
        let cached = entry.cached.clone();
        let index = entry.index;
        if queued.is_some() {
            runtime.queued = None;
        }
        runtime.running = Some(Running {
            generation: snapshot.generation(),
            source: index,
            policy: source.policy.clone(),
            list: source.list.clone(),
        });
        Ok(Some(Job {
            refresher: self.clone(),
            snapshot,
            source,
            index,
            _permit: permit,
            finished: false,
            cached,
            transfer: None,
        }))
    }
}
struct Job {
    refresher: Arc<Refresher>,
    snapshot: Arc<PolicySnapshot>,
    source: FilterSource,
    index: usize,
    _permit: OwnedSemaphorePermit,
    finished: bool,
    cached: Option<Cached>,
    transfer: Option<(u16, usize)>,
}
impl Job {
    fn rules(&self) -> Result<&str, String> {
        self.snapshot
            .config()
            .policies
            .iter()
            .find(|policy| policy.name == self.source.policy)
            .and_then(|policy| {
                policy
                    .lists
                    .iter()
                    .find(|list| list.name == self.source.list)
            })
            .map(|list| list.rules.as_str())
            .ok_or_else(|| "scheduled source target missing".into())
    }
    fn conditions(&mut self) -> Result<Option<downloads::Validators>, String> {
        let Some(cache) = &self.cached else {
            return Ok(None);
        };
        // Stamps have already been checked against stored text at publication.
        let valid = cache.generation == Some(self.snapshot.generation())
            || self
                .source
                .download
                .as_ref()
                .is_some_and(|stamp| stamp.sha256 == cache.sha256 && stamp.bytes == cache.bytes)
            || {
                let rules = self.rules()?;
                rules.len() == cache.bytes && downloads::sha256(rules.as_bytes()) == cache.sha256
            };
        if valid {
            let cache = self.cached.as_mut().ok_or("validator state missing")?;
            cache.generation = Some(self.snapshot.generation());
            Ok(Some(cache.validators.clone()))
        } else {
            self.cached = None;
            Ok(None)
        }
    }
    fn finish(&mut self, outcome: Outcome, error: Option<String>) {
        if let Ok(mut runtime) = self.refresher.inner.lock() {
            if runtime.running.as_ref().is_some_and(|running| {
                running.generation == self.snapshot.generation() && running.source == self.index
            }) {
                runtime.running = None;
            }
            let current = runtime.generation == self.snapshot.generation();
            if let Some(entry) = runtime
                .entries
                .iter_mut()
                .find(|entry| same_source(&entry.source, &self.source))
            {
                entry.last_checked = Some(wall_now());
                entry.checked_generation = Some(self.snapshot.generation());
                entry.outcome = outcome;
                entry.transfer = self.transfer;
                if current && !matches!(outcome, Outcome::Deferred | Outcome::Cancelled) {
                    entry.cached = self.cached.clone();
                }
                entry.error = error.map(|message| message.chars().take(256).collect());
                let next = Instant::now()
                    + if outcome == Outcome::Deferred {
                        RETRY_BUSY
                    } else {
                        Duration::from_secs(self.source.refresh_interval_secs.unwrap_or(86400))
                    };
                // A retired fetch must not shorten the wait established by a
                // newly published download stamp for this same source.
                entry.next = if entry.source.download != self.source.download
                    && entry.source.download.is_some()
                {
                    entry.next.max(next)
                } else {
                    next
                };
            }
        }
        self.finished = true;
    }
}
impl Drop for Job {
    fn drop(&mut self) {
        if !self.finished {
            self.finish(Outcome::Cancelled, Some("scheduled check cancelled".into()));
        }
    }
}

/// Record `Failed` for any error; only cancellation leaves a job unfinished,
/// so that `Drop` records `Cancelled`.
impl Job {
    fn ok_or_fail<T>(&mut self, result: Result<T, String>) -> Option<T> {
        match result {
            Ok(value) => Some(value),
            Err(error) => {
                self.finish(Outcome::Failed, Some(error));
                None
            }
        }
    }
    /// Classify a completed fetch. Returns changed content still to stage;
    /// every other outcome is recorded here.
    fn receive(
        &mut self,
        fetched: Result<downloads::Fetch, String>,
        active_generation: u64,
        shadow: bool,
    ) -> Option<(String, DownloadStamp)> {
        let fetched = match fetched {
            Ok(value) => value,
            Err(error) => {
                self.cached = None; // Next check can recover with an unconditional GET.
                self.finish(Outcome::Failed, Some(error));
                return None;
            }
        };
        if active_generation != self.snapshot.generation() || shadow {
            self.finish(
                Outcome::Deferred,
                Some("configuration or shadow changed during download".into()),
            );
            return None;
        }
        let (text, stamp, validators) = match fetched {
            downloads::Fetch::NotModified { validators } => {
                self.transfer = Some((304, 0));
                if let Some(cache) = &mut self.cached {
                    cache.validators = validators;
                }
                self.finish(Outcome::Unchanged, None);
                return None;
            }
            downloads::Fetch::Modified {
                text,
                stamp,
                validators,
            } => (text, stamp, validators),
        };
        self.transfer = Some((200, stamp.bytes));
        let rules = self.rules().map(|rules| rules == text);
        let unchanged = self.ok_or_fail(rules)?;
        self.cached = validators.usable().then(|| Cached {
            generation: unchanged.then_some(self.snapshot.generation()),
            sha256: stamp.sha256.clone(),
            bytes: stamp.bytes,
            validators,
        });
        if unchanged {
            self.finish(Outcome::Unchanged, None);
            return None;
        }
        Some((text, stamp))
    }
    /// Full configuration clone with the downloaded text; run off executor.
    fn candidate(&self, text: String, stamp: DownloadStamp) -> Result<PolicyConfigSet, String> {
        let mut config = self.snapshot.config().clone();
        let list = config
            .policies
            .iter_mut()
            .find(|policy| policy.name == self.source.policy)
            .and_then(|policy| {
                policy
                    .lists
                    .iter_mut()
                    .find(|list| list.name == self.source.list)
            })
            .ok_or("scheduled source target missing")?;
        list.rules = text;
        config
            .filter_sources
            .get_mut(self.index)
            .ok_or("scheduled source missing")?
            .download = Some(stamp);
        Ok(config)
    }
}

async fn check(state: &Arc<ControlService>, stop: &CancellationToken) -> Result<(), String> {
    // A shadow is review work. Never replace it or run more checks while it exists.
    if state.engine().shadow().is_some() {
        state.refresher().discard_queued()?;
        return Ok(());
    }
    if stop.is_cancelled() || state.is_mutating() {
        return Ok(());
    }
    let Some(job) = state
        .refresher()
        .begin(state.engine().snapshot(), state.downloads())?
    else {
        return Ok(());
    };
    // Validate content binding off executor; full configuration is cloned only
    // after changed bytes arrive. Admission remains owned by every blocking task.
    let (mut job, conditions) = tokio::task::spawn_blocking(move || {
        let mut job = job;
        let conditions = job.conditions();
        (job, conditions)
    })
    .await
    .map_err(|_| "refresh preparation stopped")?;
    let Some(conditions) = job.ok_or_fail(conditions) else {
        return Ok(());
    };
    let fetched = tokio::select! {
        _ = stop.cancelled() => return Ok(()),
        result = downloads::fetch_conditional(&job.source, conditions.as_ref()) => result,
    };
    if stop.is_cancelled() {
        return Ok(());
    }
    let active = state.engine().active().generation();
    let shadow = state.engine().shadow().is_some();
    if let Some((text, stamp)) = job.receive(fetched, active, shadow) {
        stage(state, job, text, stamp).await?;
    }
    Ok(())
}

/// Stage changed content as a shadow through the normal assertion-gated path.
async fn stage(
    state: &Arc<ControlService>,
    job: Job,
    text: String,
    stamp: DownloadStamp,
) -> Result<(), String> {
    let (mut job, config) = tokio::task::spawn_blocking(move || {
        let config = job.candidate(text, stamp);
        (job, config)
    })
    .await
    .map_err(|_| "refresh candidate preparation stopped")?;
    let Some(config) = job.ok_or_fail(config) else {
        return Ok(());
    };
    // Once compilation/commit starts, drain it before SQLite shutdown. stage_refresh
    // retains mutation admission until its durable commit and shadow publication end.
    match state
        .stage_refresh(config, job.index, job.snapshot.generation())
        .await
    {
        Ok(()) => job.finish(Outcome::Staged, None),
        Err(error) => {
            let outcome = if matches!(
                error,
                crate::ControlError::Conflict(_) | crate::ControlError::Stale
            ) {
                Outcome::Deferred
            } else {
                Outcome::Failed
            };
            job.cached = None;
            job.finish(outcome, Some(error.to_string()));
        }
    }
    Ok(())
}

pub async fn run(state: Arc<ControlService>, stop: CancellationToken) {
    loop {
        if stop.is_cancelled() {
            return;
        }
        if let Err(error) = check(&state, &stop).await {
            tracing::warn!(%error, "scheduled list check failed");
        }
        tokio::select! {
            _ = stop.cancelled() => return,
            _ = state.refresher().wake.notified() => {},
            _ = tokio::time::sleep(Duration::from_secs(1)) => {},
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use rustwalld_dns_policy::{DownloadStamp, PolicyConfigSet};
    fn config() -> PolicyConfigSet {
        let mut config = PolicyConfigSet::default();
        config.policies[0].lists = vec![rustwalld_dns_filter::ListInput {
            name: "test".into(),
            action: rustwalld_dns_filter::Action::Block,
            rules: "ads.test\n".into(),
        }];
        config.filter_sources = vec![FilterSource {
            policy: "default".into(),
            list: "test".into(),
            url: "https://lists.test/domains".into(),
            bootstrap_ips: vec!["127.0.0.1".parse().unwrap()],
            ca_pem: None,
            download: None,
            refresh_interval_secs: Some(300),
        }];
        config
    }
    #[test]
    fn validators_follow_content_and_retired_completions_cannot_install_them() {
        let config = config();
        let snapshot = Arc::new(PolicySnapshot::compile(config.clone(), 1).unwrap());
        let refresher = Arc::new(Refresher::default());
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let mut job = refresher
            .begin(snapshot.clone(), &semaphore)
            .unwrap()
            .unwrap();
        let mut headers = hyper::HeaderMap::new();
        headers.insert(hyper::header::ETAG, "\"one\"".parse().unwrap());
        let cached = Cached {
            generation: None,
            sha256: downloads::sha256(b"new.test\n"),
            bytes: 9,
            validators: downloads::Validators::from_headers(&headers),
        };
        job.cached = Some(cached.clone());
        assert!(job.conditions().unwrap().is_none()); // discarded shadow cannot validate old content
        job.cached = Some(Cached {
            sha256: downloads::sha256(b"ads.test\n"),
            ..cached.clone()
        });
        assert!(job.conditions().unwrap().is_some()); // exact content, no durable stamp
        assert_eq!(job.cached.as_ref().unwrap().generation, Some(1));
        let mut changed = config;
        changed.policies[0].lists[0].rules = "new.test\n".into();
        let newer = Arc::new(PolicySnapshot::compile(changed, 2).unwrap());
        refresher.status(&newer).unwrap();
        job.finish(Outcome::Unchanged, None);
        assert!(refresher.inner.lock().unwrap().entries[0].cached.is_none());
        drop(job);
        refresher.enqueue(&newer, 0).unwrap();
        let mut job = refresher.begin(newer.clone(), &semaphore).unwrap().unwrap();
        job.cached = Some(cached);
        assert!(job.conditions().unwrap().is_some()); // promoted matching body
        job.finish(Outcome::Unchanged, None);
        drop(job);
        // A URL/trust/interval change starts with no validators.
        let mut changed = newer.config().clone();
        changed.filter_sources[0].url.push_str("?different");
        let third = Arc::new(PolicySnapshot::compile(changed, 3).unwrap());
        assert!(
            refresher.status(&third).unwrap().entries[0]
                .last_http_status
                .is_none()
        );
        refresher.enqueue(&third, 0).unwrap();
        assert!(
            refresher
                .begin(third, &semaphore)
                .unwrap()
                .unwrap()
                .cached
                .is_none()
        );
    }
    #[test]
    fn deadlines_survive_clock_and_generation_changes_and_fresh_stamps_wait() {
        let mut config = config();
        let now = Instant::now();
        let mut runtime = Runtime::default();
        let original = PolicySnapshot::compile(config.clone(), 1).unwrap();
        runtime.synchronize(&original, now, 1000);
        assert_eq!(runtime.entries[0].next, now);
        runtime.entries[0].next = now + RETRY_BUSY;
        runtime.entries[0].outcome = Outcome::Deferred;
        runtime.queued = Some(Queued {
            generation: 1,
            source: 0,
        });
        config.policies[0].name = "renamed".into();
        config.default_policy = "renamed".into();
        config.filter_sources[0].policy = "renamed".into();
        let changed_source = PolicySnapshot::compile(config.clone(), 2).unwrap();
        runtime.synchronize(&changed_source, now, 1000);
        assert!(runtime.queued.is_none());
        assert_eq!(runtime.entries[0].outcome, Outcome::Waiting);
        runtime.entries[0].next = now + RETRY_BUSY;
        let unrelated = PolicySnapshot::compile(config.clone(), 3).unwrap();
        runtime.synchronize(&unrelated, now + Duration::from_secs(1), 9999999);
        assert_eq!(runtime.entries[0].next, now + RETRY_BUSY);
        runtime.synchronize(&unrelated, now + Duration::from_secs(2), 0);
        assert_eq!(runtime.entries[0].next, now + RETRY_BUSY);
        config.filter_sources[0].download = Some(DownloadStamp {
            retrieved_at: 1000,
            sha256: downloads::sha256(b"ads.test\n"),
            bytes: 9,
        });
        let retrieved = PolicySnapshot::compile(config.clone(), 4).unwrap();
        runtime.synchronize(&retrieved, now, 1000);
        assert_eq!(runtime.entries[0].next, now + Duration::from_secs(300));
        runtime.queued = Some(Queued {
            generation: 4,
            source: 0,
        });
        runtime.synchronize(&original, now + Duration::from_secs(1), 9999999);
        assert_eq!(runtime.generation, 4);
        assert_eq!(runtime.queued.unwrap().generation, 4);
        assert_eq!(runtime.entries[0].next, now + Duration::from_secs(300));
        let mut restarted = Runtime::default();
        restarted.synchronize(&retrieved, now, 0); // Future stamp is capped to one interval.
        assert_eq!(restarted.entries[0].next, now + Duration::from_secs(300));
        let mut overdue = Runtime::default();
        overdue.synchronize(&retrieved, now, 1300);
        assert_eq!(overdue.entries[0].next, now);
    }
    #[test]
    fn retired_job_preserves_a_newly_published_download_deadline() {
        let mut config = config();
        let snapshot = Arc::new(PolicySnapshot::compile(config.clone(), 1).unwrap());
        let refresher = Arc::new(Refresher::default());
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let mut job = refresher.begin(snapshot, &semaphore).unwrap().unwrap();
        config.filter_sources[0].download = Some(DownloadStamp {
            retrieved_at: wall_now(),
            bytes: 9,
            sha256: downloads::sha256(b"ads.test\n"),
        });
        let fresh = PolicySnapshot::compile(config, 2).unwrap();
        refresher.status(&fresh).unwrap();
        let deadline = refresher.inner.lock().unwrap().entries[0].next;
        job.finish(Outcome::Deferred, Some("configuration changed".into()));
        assert!(refresher.inner.lock().unwrap().entries[0].next >= deadline);
        assert_eq!(
            refresher.status(&fresh).unwrap().entries[0].checked_generation,
            Some(1)
        );
        drop(job);
        assert_eq!(semaphore.available_permits(), 1);
    }
    #[test]
    fn one_slot_manual_contention_cancellation_and_retired_queue_are_bounded() {
        let config = config();
        let snapshot = Arc::new(PolicySnapshot::compile(config.clone(), 1).unwrap());
        let refresher = Arc::new(Refresher::default());
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let manual = semaphore.clone().try_acquire_owned().unwrap();
        assert!(
            refresher
                .begin(snapshot.clone(), &semaphore)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            refresher.status(&snapshot).unwrap().entries[0].outcome,
            Outcome::Deferred
        );
        drop(manual);
        refresher.enqueue(&snapshot, 0).unwrap();
        assert!(refresher.enqueue(&snapshot, 0).is_err());
        let job = refresher
            .begin(snapshot.clone(), &semaphore)
            .unwrap()
            .unwrap();
        assert_eq!(semaphore.available_permits(), 0);
        assert!(refresher.enqueue(&snapshot, 0).is_err());
        drop(job);
        assert_eq!(semaphore.available_permits(), 1);
        let status = refresher.status(&snapshot).unwrap();
        assert!(status.running.is_none());
        assert_eq!(status.entries[0].outcome, Outcome::Cancelled);
        assert_eq!(status.entries[0].checked_generation, Some(1));
        refresher.enqueue(&snapshot, 0).unwrap();
        refresher.discard_queued().unwrap();
        assert!(refresher.status(&snapshot).unwrap().queued.is_none());
        refresher.enqueue(&snapshot, 0).unwrap();
        let next = PolicySnapshot::compile(config, 2).unwrap();
        assert!(refresher.status(&next).unwrap().queued.is_none());
        refresher.enqueue(&next, 0).unwrap();
        assert_eq!(refresher.status(&snapshot).unwrap().generation, 2);
        assert!(refresher.enqueue(&snapshot, 0).is_err());
        assert!(refresher.begin(snapshot, &semaphore).unwrap().is_none());
        assert_eq!(
            refresher.status(&next).unwrap().queued.unwrap().generation,
            2
        );
    }
    #[test]
    fn queued_manual_check_survives_download_contention() {
        let snapshot = Arc::new(PolicySnapshot::compile(config(), 1).unwrap());
        let refresher = Arc::new(Refresher::default());
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        // Not yet due on its own schedule: only the manual request can start it.
        refresher.status(&snapshot).unwrap();
        refresher.inner.lock().unwrap().entries[0].next = Instant::now() + RETRY_BUSY;
        refresher.enqueue(&snapshot, 0).unwrap();
        let preview = semaphore.clone().try_acquire_owned().unwrap();
        assert!(
            refresher
                .begin(snapshot.clone(), &semaphore)
                .unwrap()
                .is_none()
        );
        let status = refresher.status(&snapshot).unwrap();
        assert_eq!(status.entries[0].outcome, Outcome::Deferred);
        assert_eq!(status.queued.unwrap().source, 0);
        drop(preview);
        let job = refresher.begin(snapshot.clone(), &semaphore).unwrap();
        assert_eq!(job.unwrap().index, 0);
        assert!(refresher.status(&snapshot).unwrap().queued.is_none());
    }
    #[test]
    fn processing_failures_are_recorded_as_failed_not_cancelled() {
        let snapshot = Arc::new(PolicySnapshot::compile(config(), 1).unwrap());
        let refresher = Arc::new(Refresher::default());
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let fetched = || {
            Ok(downloads::Fetch::Modified {
                text: "new.test\n".into(),
                stamp: DownloadStamp {
                    retrieved_at: 1,
                    sha256: downloads::sha256(b"new.test\n"),
                    bytes: 9,
                },
                validators: downloads::Validators::default(),
            })
        };
        let outcome = |refresher: &Refresher| {
            let status = refresher.status(&snapshot).unwrap();
            (status.entries[0].outcome, status.entries[0].error.clone())
        };
        let start = || {
            refresher.enqueue(&snapshot, 0).unwrap();
            refresher
                .begin(snapshot.clone(), &semaphore)
                .unwrap()
                .unwrap()
        };
        // The compared target vanished: previously `?` dropped the job unfinished.
        let mut job = start();
        let mut renamed = config();
        renamed.policies[0].lists[0].name = "renamed".into();
        renamed.filter_sources.clear();
        job.snapshot = Arc::new(PolicySnapshot::compile(renamed, 1).unwrap());
        assert!(job.receive(fetched(), 1, false).is_none());
        drop(job);
        assert_eq!(
            outcome(&refresher),
            (
                Outcome::Failed,
                Some("scheduled source target missing".into())
            )
        );
        // The list still exists but its source entry is gone.
        let mut job = start();
        let mut sourceless = config();
        sourceless.filter_sources.clear();
        job.snapshot = Arc::new(PolicySnapshot::compile(sourceless, 1).unwrap());
        let (text, stamp) = job.receive(fetched(), 1, false).unwrap();
        let candidate = job.candidate(text, stamp);
        assert!(job.ok_or_fail(candidate).is_none());
        drop(job);
        assert_eq!(
            outcome(&refresher),
            (Outcome::Failed, Some("scheduled source missing".into()))
        );
        // Changed live state still defers, and real cancellation still cancels.
        let mut job = start();
        assert!(job.receive(fetched(), 2, false).is_none());
        drop(job);
        assert_eq!(outcome(&refresher).0, Outcome::Deferred);
        // A deferred source waits RETRY_BUSY; a manual request starts it now.
        drop(start());
        assert_eq!(outcome(&refresher).0, Outcome::Cancelled);
    }
}
