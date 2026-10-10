//! Bounded command admission, priority and history batch scheduling.
use super::{
    Bootstrap, ClearShadowReport, CommitReport, HISTORY_BATCH, HISTORY_FLUSH, HistoryEntry,
    Revision, RevisionMode, RevisionSummary, StoreError, StoreMetrics,
    history::{History, queries},
    revisions::{bootstrap, commit, pointers, revision, revisions},
    schema::durable,
};
use rusqlite::Connection;
use rustwalld_dns_core::telemetry::QueryEvent;
use std::sync::{Arc, atomic::Ordering};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

pub(super) enum Operation {
    Load,
    Bootstrap {
        config: String,
    },
    Queries {
        limit: usize,
    },
    Revisions,
    Revision {
        id: u64,
    },
    Commit {
        id: u64,
        config: String,
        mode: RevisionMode,
        actor: String,
        diff: String,
    },
    ClearShadow,
}
pub(super) enum Reply {
    Load(Option<Bootstrap>),
    Bootstrap(Bootstrap),
    Queries(Vec<HistoryEntry>),
    Revisions(Vec<RevisionSummary>),
    Revision(Option<Revision>),
    Commit(CommitReport),
    ClearShadow(ClearShadowReport),
}
pub(super) struct Command {
    pub(super) operation: Operation,
    pub(super) reply: oneshot::Sender<Result<Reply, StoreError>>,
}

pub(super) struct Worker {
    pub(super) connection: Connection,
    pub(super) history: History,
    pub(super) counts: Arc<StoreMetrics>,
}
impl Worker {
    /// Block on commands and events instead of polling. Commands take priority;
    /// a history batch is written when full or `HISTORY_FLUSH` after its first
    /// event. Cancellation persists what is already queued, then stops.
    pub(super) async fn run(
        mut self,
        mut commands: mpsc::Receiver<Command>,
        mut events: mpsc::Receiver<QueryEvent>,
        cancel: CancellationToken,
    ) {
        let mut batch = Vec::with_capacity(HISTORY_BATCH);
        let flush = tokio::time::sleep(HISTORY_FLUSH);
        tokio::pin!(flush);
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                Some(command) = commands.recv() => self.serve(command),
                Some(event) = events.recv(), if batch.len() < HISTORY_BATCH => {
                    if batch.is_empty() {
                        flush.as_mut().reset(tokio::time::Instant::now() + HISTORY_FLUSH);
                    }
                    batch.push(event);
                    if batch.len() == HISTORY_BATCH {
                        self.persist(&mut batch);
                    }
                }
                () = &mut flush, if !batch.is_empty() => self.persist(&mut batch),
                else => break,
            }
        }
        while let Ok(command) = commands.try_recv() {
            self.serve(command);
        }
        loop {
            while batch.len() < HISTORY_BATCH {
                match events.try_recv() {
                    Ok(event) => batch.push(event),
                    Err(_) => break,
                }
            }
            if batch.is_empty() {
                break;
            }
            self.persist(&mut batch);
        }
    }
    fn serve(&mut self, command: Command) {
        let _ = command
            .reply
            .send(execute(&mut self.connection, command.operation));
    }
    fn persist(&mut self, batch: &mut Vec<QueryEvent>) {
        let count = u64::try_from(batch.len()).unwrap_or(u64::MAX);
        match self.history.write(&mut self.connection, batch) {
            Ok(()) => {
                self.counts
                    .persisted_events
                    .fetch_add(count, Ordering::Relaxed);
            }
            Err(error) => {
                self.counts
                    .write_failures
                    .fetch_add(count, Ordering::Relaxed);
                tracing::warn!(%error, "query history batch dropped");
            }
        }
        batch.clear();
    }
}

pub(super) fn execute(
    connection: &mut Connection,
    operation: Operation,
) -> Result<Reply, StoreError> {
    match operation {
        Operation::Load => {
            let tx = connection.transaction()?;
            let pointers = pointers(&tx)?;
            tx.commit()?;
            Ok(Reply::Load(pointers))
        }
        Operation::Bootstrap { config } => {
            durable(connection, |connection| bootstrap(connection, config)).map(Reply::Bootstrap)
        }
        Operation::Queries { limit } => queries(connection, limit).map(Reply::Queries),
        Operation::Revisions => revisions(connection).map(Reply::Revisions),
        Operation::Revision { id } => revision(connection, id).map(Reply::Revision),
        Operation::Commit {
            id,
            config,
            mode,
            actor,
            diff,
        } => durable(connection, |connection| {
            commit(connection, id, &config, mode, &actor, &diff)
        })
        .map(Reply::Commit),
        Operation::ClearShadow => durable(connection, |connection| {
            connection.execute("DELETE FROM runtime WHERE key='shadow'", [])?;
            Ok(ClearShadowReport { shadow: None })
        })
        .map(Reply::ClearShadow),
    }
}
