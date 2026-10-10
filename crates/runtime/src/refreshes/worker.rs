//! Async conditional fetch and assertion-gated shadow staging.
use super::{Outcome, job::Job};
use crate::{ControlService, downloads};
use rustwalld_dns_policy::DownloadStamp;
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

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

/// Run scheduled checks until `stop`; changed content is staged as a shadow.
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
