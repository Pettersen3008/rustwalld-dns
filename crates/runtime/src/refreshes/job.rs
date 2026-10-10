//! Admitted job lifetime, content validators and completion accounting.
use super::{
    Outcome, RETRY_BUSY, Refresher,
    schedule::{Cached, same_source, wall_now},
};
use crate::downloads;
use rustwalld_dns_policy::{DownloadStamp, FilterSource, PolicyConfigSet, PolicySnapshot};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::OwnedSemaphorePermit;

pub(super) struct Job {
    pub(super) refresher: Arc<Refresher>,
    pub(super) snapshot: Arc<PolicySnapshot>,
    pub(super) source: FilterSource,
    pub(super) index: usize,
    pub(super) _permit: OwnedSemaphorePermit,
    pub(super) finished: bool,
    pub(super) cached: Option<Cached>,
    pub(super) transfer: Option<(u16, usize)>,
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
    pub(super) fn conditions(&mut self) -> Result<Option<downloads::Validators>, String> {
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
    pub(super) fn finish(&mut self, outcome: Outcome, error: Option<String>) {
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
    pub(super) fn ok_or_fail<T>(&mut self, result: Result<T, String>) -> Option<T> {
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
    pub(super) fn receive(
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
    pub(super) fn candidate(
        &self,
        text: String,
        stamp: DownloadStamp,
    ) -> Result<PolicyConfigSet, String> {
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
