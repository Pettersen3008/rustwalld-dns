#![allow(clippy::unwrap_used)]
use super::{
    schedule::{Cached, Runtime, wall_now},
    *,
};
use crate::downloads;
use rustwalld_dns_policy::{DownloadStamp, PolicyConfigSet};
use rustwalld_dns_policy::{FilterSource, PolicySnapshot};
use std::{sync::Arc, time::Instant};
fn config() -> PolicyConfigSet {
    let mut config = PolicyConfigSet::default();
    config.policies[0].lists = vec![rustwalld_dns_filter::ListInput {
        syntax: Default::default(),
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
