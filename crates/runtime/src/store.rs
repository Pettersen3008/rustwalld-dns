//! A dedicated SQLite thread with bounded commands and bounded telemetry batches.
mod history;
mod metrics;
mod revisions;
mod schema;
mod types;
mod worker;

use history::History;
pub use metrics::{StoreMetrics, StoreMetricsSnapshot};
use rustwalld_dns_core::telemetry::QueryEvent;
use schema::open;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
pub use types::{
    Bootstrap, ClearShadowReport, CommitReport, HistoryEntry, Revision, RevisionMode,
    RevisionSummary, StoreError,
};
use worker::{Command, Operation, Reply, Worker};

/// Database schema version written by this release.
pub const SCHEMA_VERSION: i64 = 2;
/// Revisions kept besides the live active/shadow ones.
const RETAINED_REVISIONS: i64 = 32;
/// Maximum history events written in one transaction.
const HISTORY_BATCH: usize = 256;
/// Longest time a queued history event waits for more events to batch with.
const HISTORY_FLUSH: Duration = Duration::from_millis(10);

/// Handle to the single SQLite worker thread; cheap to clone.
#[derive(Clone)]
pub struct Store {
    sender: mpsc::Sender<Command>,
    /// History persistence counters.
    pub metrics: Arc<StoreMetrics>,
}
impl Store {
    /// Open (creating a private 0600 file if absent) and start the worker.
    /// The worker owns the `queries` table; its retained row count is kept in
    /// memory, so external writes to that table need a restart to be counted.
    pub async fn start(
        path: PathBuf,
        history_rows: usize,
        events: mpsc::Receiver<QueryEvent>,
        cancel: CancellationToken,
    ) -> Result<(Self, oneshot::Receiver<()>), StoreError> {
        let (sender, commands) = mpsc::channel::<Command>(32);
        let (ready_tx, ready_rx) = oneshot::channel();
        let (done_tx, done_rx) = oneshot::channel();
        let metrics = Arc::new(StoreMetrics::default());
        let counts = metrics.clone();
        std::thread::Builder::new()
            .name("dns-sqlite".into())
            .spawn(move || {
                let opened = open(&path).and_then(|connection| {
                    let history = History::open(&connection, history_rows)?;
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_time()
                        .build()
                        .map_err(StoreError::Spawn)?;
                    Ok((connection, history, runtime))
                });
                match opened {
                    Ok((connection, history, runtime)) => {
                        let _ = ready_tx.send(Ok(()));
                        let worker = Worker {
                            connection,
                            history,
                            counts,
                        };
                        runtime.block_on(worker.run(commands, events, cancel));
                    }
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                    }
                }
                let _ = done_tx.send(());
            })
            .map_err(StoreError::Spawn)?;
        ready_rx.await.map_err(|_| StoreError::WorkerStopped)??;
        Ok((Self { sender, metrics }, done_rx))
    }
    async fn request(&self, operation: Operation) -> Result<Reply, StoreError> {
        let (reply, receiver) = oneshot::channel();
        self.sender
            .try_send(Command { operation, reply })
            .map_err(|_| StoreError::QueueUnavailable)?;
        // Requests are bounded by queue admission and the SQLite busy timeout,
        // not by a deadline here. Mutations are deliberately awaited to
        // completion: a timed-out commit must not become durable unpublished.
        receiver.await.map_err(|_| StoreError::WorkerStopped)?
    }
    /// Durable active/shadow pointers, or `None` for a store never bootstrapped.
    pub async fn load(&self) -> Result<Option<Bootstrap>, StoreError> {
        match self.request(Operation::Load).await? {
            Reply::Load(v) => Ok(v),
            _ => Err(StoreError::Response),
        }
    }
    /// Store `config` as revision 1 only when no active pointer exists;
    /// otherwise return the durable active/shadow pointers unchanged. Revision
    /// identifiers are never reused, including identifiers removed by retention.
    pub async fn bootstrap(&self, config: String) -> Result<Bootstrap, StoreError> {
        match self.request(Operation::Bootstrap { config }).await? {
            Reply::Bootstrap(v) => Ok(v),
            _ => Err(StoreError::Response),
        }
    }
    /// Read newest history rows with the existing 1..1000 limit clamp.
    pub async fn queries(&self, limit: usize) -> Result<Vec<HistoryEntry>, StoreError> {
        match self.request(Operation::Queries { limit }).await? {
            Reply::Queries(v) => Ok(v),
            _ => Err(StoreError::Response),
        }
    }
    /// Revision summaries, newest first.
    ///
    /// # Errors
    ///
    /// Queue, worker or SQLite failures.
    pub async fn revisions(&self) -> Result<Vec<RevisionSummary>, StoreError> {
        match self.request(Operation::Revisions).await? {
            Reply::Revisions(v) => Ok(v),
            _ => Err(StoreError::Response),
        }
    }
    /// Revision `id`, or `None` when absent.
    ///
    /// # Errors
    ///
    /// Queue, worker or SQLite failures, or [`StoreError::CorruptRevision`].
    pub async fn revision(&self, id: u64) -> Result<Option<Revision>, StoreError> {
        match self.request(Operation::Revision { id }).await? {
            Reply::Revision(v) => Ok(v),
            _ => Err(StoreError::Response),
        }
    }
    /// Low-level durable write used by `ControlService`. It neither reserves a
    /// generation nor publishes; hosts with a control service must stage
    /// revisions through it instead.
    pub async fn commit(
        &self,
        id: u64,
        config: String,
        mode: RevisionMode,
        actor: String,
        diff: String,
    ) -> Result<CommitReport, StoreError> {
        match self
            .request(Operation::Commit {
                id,
                config,
                mode,
                actor,
                diff,
            })
            .await?
        {
            Reply::Commit(v) => Ok(v),
            _ => Err(StoreError::Response),
        }
    }
    /// Durably remove the shadow pointer. Publication belongs to the caller.
    ///
    /// # Errors
    ///
    /// Queue, worker or SQLite failures.
    pub async fn clear_shadow(&self) -> Result<ClearShadowReport, StoreError> {
        match self.request(Operation::ClearShadow).await? {
            Reply::ClearShadow(v) => Ok(v),
            _ => Err(StoreError::Response),
        }
    }
}

#[cfg(test)]
mod tests;
