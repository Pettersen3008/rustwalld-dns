//! Generation-bound monotonic deadlines and bounded manual admission.
use super::{
    RETRY_BUSY,
    job::Job,
    types::{EntryStatus, Outcome, Queued, Running, Status},
};
use crate::downloads;
use rustwalld_dns_policy::{FilterSource, PolicySnapshot};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Notify;

#[derive(Clone)]
pub(super) struct Cached {
    // Last live generation validated against this fingerprint; None for staged bytes.
    pub(super) generation: Option<u64>,
    pub(super) sha256: String,
    pub(super) bytes: usize,
    pub(super) validators: downloads::Validators,
}
pub(super) struct Entry {
    pub(super) index: usize,
    pub(super) source: FilterSource,
    pub(super) next: Instant,
    pub(super) last_checked: Option<u64>,
    pub(super) checked_generation: Option<u64>,
    pub(super) outcome: Outcome,
    pub(super) error: Option<String>,
    pub(super) transfer: Option<(u16, usize)>,
    pub(super) cached: Option<Cached>,
}
#[derive(Default)]
pub(super) struct Runtime {
    pub(super) generation: u64,
    pub(super) entries: Vec<Entry>,
    pub(super) running: Option<Running>,
    pub(super) queued: Option<Queued>,
}
/// Schedule state for scheduled list checks; checks never promote.
#[derive(Default)]
pub struct Refresher {
    pub(super) inner: Mutex<Runtime>,
    pub(super) wake: Notify,
}
pub(super) fn wall_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.as_secs())
}
pub(super) fn same_source(a: &FilterSource, b: &FilterSource) -> bool {
    a.policy == b.policy
        && a.list == b.list
        && a.url == b.url
        && a.bootstrap_ips == b.bootstrap_ips
        && a.ca_pem == b.ca_pem
        && a.refresh_interval_secs == b.refresh_interval_secs
}
impl Runtime {
    pub(super) fn synchronize(&mut self, snapshot: &PolicySnapshot, now: Instant, wall: u64) {
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
    pub(super) fn discard_queued(&self) -> Result<(), String> {
        self.inner
            .lock()
            .map_err(|_| "refresh state unavailable")?
            .queued = None;
        Ok(())
    }
    /// Schedule and results for `snapshot`'s sources.
    ///
    /// # Errors
    ///
    /// When the schedule state is poisoned.
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
    /// Queue an immediate check of source `index`.
    ///
    /// # Errors
    ///
    /// When a check is already queued or running, or the source has no schedule.
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
    pub(super) fn begin(
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
