//! A dedicated SQLite thread with bounded commands and bounded telemetry batches.
use rusqlite::{Connection, OptionalExtension, params};
use rustwalld_dns_core::telemetry::QueryEvent;
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

pub const SCHEMA_VERSION: i64 = 2;
/// Revisions kept besides the live active/shadow ones.
const RETAINED_REVISIONS: i64 = 32;
/// Maximum history events written in one transaction.
const HISTORY_BATCH: usize = 256;
/// Longest time a queued history event waits for more events to batch with.
const HISTORY_FLUSH: Duration = Duration::from_millis(10);

/// Persisted revision state, serialized with the existing schema vocabulary.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RevisionMode {
    Promoted,
    Shadow,
}
impl RevisionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Promoted => "promoted",
            Self::Shadow => "shadow",
        }
    }
}
/// Durable runtime pointers and source policy content.
#[derive(Debug, Serialize)]
pub struct Bootstrap {
    pub active: u64,
    pub next: u64,
    pub config: String,
    pub shadow: Option<u64>,
}
/// A successful durable revision commit.
#[derive(Debug, Serialize)]
pub struct CommitReport {
    pub generation: u64,
    pub state: RevisionMode,
}
/// A successful durable shadow removal.
#[derive(Debug, Serialize)]
pub struct ClearShadowReport {
    pub shadow: Option<u64>,
}
/// Historical revision content. Malformed stored JSON is an explicit
/// [`StoreError::CorruptRevision`], never `null`.
#[derive(Serialize)]
pub struct Revision {
    pub id: u64,
    pub config: Value,
}
#[derive(Debug, Serialize)]
pub struct RevisionSummary {
    pub id: u64,
    pub timestamp: String,
    pub actor: String,
    pub state: String,
    pub diff: String,
}
#[derive(Debug, Serialize)]
pub struct HistoryEntry {
    pub id: u64,
    pub timestamp: String,
    pub client: String,
    pub domain: String,
    pub qtype: u16,
    pub generation: u64,
    pub policy_id: i64,
    pub action: String,
    pub rule_id: Option<u32>,
    pub decision_cached: bool,
    pub response_code: u16,
    pub source: String,
    pub latency_us: i64,
    pub shadow: Option<Value>,
    pub temporary_exception: Option<u16>,
}
/// Bounded store admission and worker failures; never returned by DNS queries.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    #[error("database command queue unavailable")]
    QueueUnavailable,
    #[error("database worker stopped")]
    WorkerStopped,
    /// SQLite failure, including lock contention and constraint violations.
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    /// Stored revision content is not JSON; it is never replaced by `null`.
    #[error("stored revision {id} is not valid JSON")]
    CorruptRevision {
        id: u64,
        #[source]
        source: serde_json::Error,
    },
    /// A runtime pointer names a revision that no longer exists.
    #[error("runtime {pointer} pointer refers to missing revision {id}")]
    DanglingPointer { pointer: &'static str, id: u64 },
    /// Revisions exist without an active pointer; bootstrapping would reuse IDs.
    #[error("database has revisions but no active runtime pointer")]
    MissingActive,
    #[error("unsupported database schema {found}; expected {SCHEMA_VERSION}")]
    Schema { found: i64 },
    /// Concurrent writers and crash recovery require write-ahead logging.
    #[error("database journal mode is {0:?}; write-ahead logging is required")]
    JournalMode(String),
    #[error("database file could not be created")]
    Create(#[source] std::io::Error),
    #[error("unexpected database worker response")]
    Response,
    #[error("database worker could not start")]
    Spawn(#[source] std::io::Error),
}
enum Operation {
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
enum Reply {
    Load(Option<Bootstrap>),
    Bootstrap(Bootstrap),
    Queries(Vec<HistoryEntry>),
    Revisions(Vec<RevisionSummary>),
    Revision(Option<Revision>),
    Commit(CommitReport),
    ClearShadow(ClearShadowReport),
}
struct Command {
    operation: Operation,
    reply: oneshot::Sender<Result<Reply, StoreError>>,
}
#[derive(Default)]
pub struct StoreMetrics {
    pub write_failures: AtomicU64,
    pub persisted_events: AtomicU64,
}
#[derive(Clone)]
pub struct Store {
    sender: mpsc::Sender<Command>,
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
    pub async fn revisions(&self) -> Result<Vec<RevisionSummary>, StoreError> {
        match self.request(Operation::Revisions).await? {
            Reply::Revisions(v) => Ok(v),
            _ => Err(StoreError::Response),
        }
    }
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
    pub async fn clear_shadow(&self) -> Result<ClearShadowReport, StoreError> {
        match self.request(Operation::ClearShadow).await? {
            Reply::ClearShadow(v) => Ok(v),
            _ => Err(StoreError::Response),
        }
    }
}

struct Worker {
    connection: Connection,
    history: History,
    counts: Arc<StoreMetrics>,
}
impl Worker {
    /// Block on commands and events instead of polling. Commands take priority;
    /// a history batch is written when full or `HISTORY_FLUSH` after its first
    /// event. Cancellation persists what is already queued, then stops.
    async fn run(
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

/// Bounded best-effort history. The retained row count lives in memory, so a
/// batch never scans the table (a `COUNT(*)` per batch is O(rows)).
struct History {
    limit: u64,
    rows: u64,
}
impl History {
    fn open(connection: &Connection, limit: usize) -> Result<Self, StoreError> {
        Ok(Self {
            limit: u64::try_from(limit).unwrap_or(u64::MAX),
            rows: Self::count(connection)?,
        })
    }
    fn count(connection: &Connection) -> Result<u64, StoreError> {
        let rows: i64 = connection.query_row("SELECT COUNT(*) FROM queries", [], |r| r.get(0))?;
        Ok(from_sql_id(rows)?)
    }
    /// Insert one atomic batch and evict only the oldest excess rows.
    /// History favors throughput over durability (`synchronous=NORMAL`): a
    /// power loss may drop recent batches but never corrupts the database.
    fn write(
        &mut self,
        connection: &mut Connection,
        batch: &[QueryEvent],
    ) -> Result<(), StoreError> {
        let tx = connection.transaction()?;
        {
            let mut stmt=tx.prepare_cached("INSERT INTO queries(client,domain,qtype,generation,policy,action,rule,decision_cached,rcode,source,latency_us,shadow,temporary_exception) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)")?;
            for event in batch {
                let shadow = event.shadow.as_ref().map(|s| {
                    json!({
                        "generation": s.generation,
                        "policy_id": s.policy,
                        "decision": s.decision,
                        "rewrite": s.rewrite,
                        "differs": s.differs,
                        "temporary_exception": s.temporary_exception,
                    })
                    .to_string()
                });
                stmt.execute(params![
                    event.client.to_string(),
                    event.domain,
                    event.qtype,
                    sql_id(event.generation)?,
                    i64::try_from(event.policy)
                        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?,
                    if event.decision.action == rustwalld_dns_filter::Action::Block {
                        "block"
                    } else {
                        "allow"
                    },
                    event.decision.rule,
                    event.decision_cached,
                    event.response_code,
                    event.source.as_str(),
                    i64::try_from(event.latency_us).unwrap_or(i64::MAX),
                    shadow,
                    event.temporary_exception
                ])?;
            }
        }
        let rows = self
            .rows
            .saturating_add(u64::try_from(batch.len()).unwrap_or(u64::MAX));
        let mut evicted = 0;
        if let Some(excess) = rows.checked_sub(self.limit).filter(|excess| *excess > 0) {
            evicted = tx.execute(
                "DELETE FROM queries WHERE id <= (SELECT id FROM queries ORDER BY id ASC LIMIT 1 OFFSET ?1)",
                [sql_id(excess - 1)?],
            )?;
        }
        tx.commit()?;
        self.rows = rows.saturating_sub(u64::try_from(evicted).unwrap_or(u64::MAX));
        Ok(())
    }
}

/// Create the database privately: it holds client addresses and domains.
/// SQLite gives its WAL/SHM sidecars the database file's permissions.
fn create_private(path: &Path) -> Result<(), StoreError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    match options.open(path) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(StoreError::Create(error)),
    }
}
fn open(path: &Path) -> Result<Connection, StoreError> {
    create_private(path)?;
    let mut connection = Connection::open(path)?;
    connection.busy_timeout(Duration::from_millis(250))?;
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if !(0..=SCHEMA_VERSION).contains(&version) {
        return Err(StoreError::Schema { found: version });
    }
    let mode: String = connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(StoreError::JournalMode(mode));
    }
    // History batches run at NORMAL; revision/pointer commits switch to FULL.
    connection.pragma_update(None, "synchronous", "NORMAL")?;
    let tx = connection.transaction()?;
    tx.execute_batch("
        CREATE TABLE IF NOT EXISTS revisions(id INTEGER PRIMARY KEY,created TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),actor TEXT NOT NULL,state TEXT NOT NULL,diff TEXT NOT NULL,config TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS runtime(key TEXT PRIMARY KEY,value INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS queries(id INTEGER PRIMARY KEY,created TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),client TEXT NOT NULL,domain TEXT NOT NULL,qtype INTEGER NOT NULL,generation INTEGER NOT NULL,policy INTEGER NOT NULL,action TEXT NOT NULL,rule INTEGER,decision_cached INTEGER NOT NULL,rcode INTEGER NOT NULL,source TEXT NOT NULL,latency_us INTEGER NOT NULL,shadow TEXT,temporary_exception INTEGER);
        -- Nothing reads by creation time and retention no longer counts rows,
        -- so this index only cost a B-tree update per history insert.
        DROP INDEX IF EXISTS queries_created;")?;
    if version == 1 {
        tx.execute_batch("ALTER TABLE queries ADD COLUMN temporary_exception INTEGER;")?;
    }
    tx.prepare("SELECT temporary_exception FROM queries LIMIT 0")?;
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    tx.commit()?;
    Ok(connection)
}
/// Revision and pointer changes are fsynced on commit (`synchronous=FULL`);
/// the pragma is switched between transactions and restored afterwards.
fn durable<T>(
    connection: &mut Connection,
    operation: impl FnOnce(&mut Connection) -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    connection.pragma_update(None, "synchronous", "FULL")?;
    let result = operation(connection);
    // Never turn a committed revision into an error: the caller would skip
    // publication. Staying at FULL is only slower.
    if let Err(error) = connection.pragma_update(None, "synchronous", "NORMAL") {
        tracing::warn!(%error, "history synchronous mode could not be restored");
    }
    result
}
/// Read durable pointers inside one transaction, if the store was bootstrapped.
fn pointers(tx: &rusqlite::Transaction<'_>) -> Result<Option<Bootstrap>, StoreError> {
    let pointer = |key: &str| {
        tx.query_row("SELECT value FROM runtime WHERE key=?1", [key], |r| {
            r.get::<_, i64>(0)
        })
        .optional()?
        .map(from_sql_id)
        .transpose()
    };
    let Some(active) = pointer("active")? else {
        return Ok(None);
    };
    let shadow = pointer("shadow")?;
    let config: String = tx
        .query_row(
            "SELECT config FROM revisions WHERE id=?1",
            [sql_id(active)?],
            |r| r.get(0),
        )
        .optional()?
        .ok_or(StoreError::DanglingPointer {
            pointer: "active",
            id: active,
        })?;
    // Retention always keeps the newest revision, so this never decreases.
    let next: i64 = tx.query_row("SELECT MAX(id)+1 FROM revisions", [], |r| r.get(0))?;
    Ok(Some(Bootstrap {
        active,
        next: from_sql_id(next)?,
        config,
        shadow,
    }))
}
fn execute(connection: &mut Connection, operation: Operation) -> Result<Reply, StoreError> {
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
fn bootstrap(connection: &mut Connection, config: String) -> Result<Bootstrap, StoreError> {
    let tx = connection.transaction()?;
    if let Some(existing) = pointers(&tx)? {
        tx.commit()?;
        return Ok(existing);
    }
    // Never resurrect a retention-pruned ID with different content.
    let revisions: i64 = tx.query_row("SELECT COUNT(*) FROM revisions", [], |r| r.get(0))?;
    if revisions != 0 {
        return Err(StoreError::MissingActive);
    }
    tx.execute("INSERT INTO revisions(id,actor,state,diff,config) VALUES(1,'startup','promoted','initial configuration',?1)",[config])?;
    tx.execute("INSERT INTO runtime(key,value) VALUES('active',1)", [])?;
    let bootstrap = pointers(&tx)?.ok_or(StoreError::MissingActive)?;
    tx.commit()?;
    Ok(bootstrap)
}
fn queries(connection: &Connection, limit: usize) -> Result<Vec<HistoryEntry>, StoreError> {
    let mut stmt=connection.prepare("SELECT id,created,client,domain,qtype,generation,policy,action,rule,decision_cached,rcode,source,latency_us,shadow,temporary_exception FROM queries ORDER BY id DESC LIMIT ?1")?;
    let limit = i64::try_from(limit.clamp(1, 1000)).unwrap_or(1000);
    let rows = stmt.query_map([limit], |r| {
        Ok(HistoryEntry {
            id: from_sql_id(r.get(0)?)?,
            timestamp: r.get(1)?,
            client: r.get(2)?,
            domain: r.get(3)?,
            qtype: r.get(4)?,
            generation: from_sql_id(r.get(5)?)?,
            policy_id: r.get(6)?,
            action: r.get(7)?,
            rule_id: r.get(8)?,
            decision_cached: r.get(9)?,
            response_code: r.get(10)?,
            source: r.get(11)?,
            latency_us: r.get(12)?,
            shadow: r
                .get::<_, Option<String>>(13)?
                .and_then(|s| serde_json::from_str::<Value>(&s).ok()),
            temporary_exception: r.get(14)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}
fn revisions(connection: &Connection) -> Result<Vec<RevisionSummary>, StoreError> {
    let mut stmt =
        connection.prepare("SELECT id,created,actor,state,diff FROM revisions ORDER BY id DESC")?;
    let rows = stmt.query_map([], |r| {
        Ok(RevisionSummary {
            id: from_sql_id(r.get(0)?)?,
            timestamp: r.get(1)?,
            actor: r.get(2)?,
            state: r.get(3)?,
            diff: r.get(4)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}
fn revision(connection: &Connection, id: u64) -> Result<Option<Revision>, StoreError> {
    let text: Option<String> = connection
        .query_row(
            "SELECT config FROM revisions WHERE id=?1",
            [sql_id(id)?],
            |r| r.get(0),
        )
        .optional()?;
    text.map(|text| {
        serde_json::from_str(&text)
            .map(|config| Revision { id, config })
            .map_err(|source| StoreError::CorruptRevision { id, source })
    })
    .transpose()
}
fn commit(
    connection: &mut Connection,
    id: u64,
    config: &str,
    mode: RevisionMode,
    actor: &str,
    diff: &str,
) -> Result<CommitReport, StoreError> {
    let tx = connection.transaction()?;
    tx.execute(
        "INSERT INTO revisions(id,actor,state,diff,config) VALUES(?1,?2,?3,?4,?5)",
        params![sql_id(id)?, actor, mode.as_str(), diff, config],
    )?;
    let key = match mode {
        RevisionMode::Shadow => "shadow",
        RevisionMode::Promoted => "active",
    };
    tx.execute("INSERT INTO runtime(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",params![key,sql_id(id)?])?;
    if matches!(mode, RevisionMode::Promoted) {
        tx.execute("DELETE FROM runtime WHERE key='shadow'", [])?;
    }
    // Retain recent revisions and any currently active/shadow generation.
    tx.execute("DELETE FROM revisions WHERE id NOT IN (SELECT id FROM revisions ORDER BY id DESC LIMIT ?1) AND id NOT IN (SELECT value FROM runtime)",[RETAINED_REVISIONS])?;
    tx.commit()?;
    Ok(CommitReport {
        generation: id,
        state: mode,
    })
}

fn from_sql_id(id: i64) -> rusqlite::Result<u64> {
    u64::try_from(id).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Integer, Box::new(e))
    })
}
fn sql_id(id: u64) -> rusqlite::Result<i64> {
    i64::try_from(id).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use rustwalld_dns_core::telemetry::QuerySource;
    fn event() -> QueryEvent {
        QueryEvent {
            client: "127.0.0.1".parse().unwrap(),
            domain: "cache.example".into(),
            qtype: 1,
            generation: 1,
            policy: 0,
            decision: rustwalld_dns_filter::Decision::ALLOW,
            decision_cached: true,
            response_code: 0,
            source: QuerySource::Cache,
            latency_us: 1,
            shadow: None,
            temporary_exception: None,
        }
    }
    fn ids(connection: &Connection) -> Vec<i64> {
        connection
            .prepare("SELECT id FROM queries ORDER BY id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    }
    fn database() -> (tempfile::TempDir, Connection) {
        let directory = tempfile::tempdir().unwrap();
        let connection = open(&directory.path().join("dns.sqlite")).unwrap();
        (directory, connection)
    }
    fn write(
        connection: &mut Connection,
        batch: &[QueryEvent],
        limit: u64,
    ) -> Result<(), StoreError> {
        let mut history = History::open(connection, 0).unwrap();
        history.limit = limit;
        history.write(connection, batch)
    }
    #[test]
    fn history_retains_newest_rows_with_sparse_ids_and_changing_limits() {
        let (_directory, mut connection) = database();
        write(&mut connection, &vec![event(); 10], 12).unwrap();
        assert_eq!(ids(&connection).len(), 10);
        connection
            .execute_batch("UPDATE queries SET id=-id; UPDATE queries SET id=-id*10; DELETE FROM queries WHERE id IN(40,70)")
            .unwrap();
        write(&mut connection, &[event()], 4).unwrap();
        assert_eq!(ids(&connection), vec![80, 90, 100, 101]);
        write(&mut connection, &vec![event(); 6], 4).unwrap();
        assert_eq!(ids(&connection), vec![104, 105, 106, 107]);
        write(&mut connection, &[event()], 1).unwrap();
        assert_eq!(ids(&connection), vec![108]);
    }
    #[test]
    fn failed_history_batch_cannot_insert_or_trim_partial_state() {
        let (_directory, mut connection) = database();
        write(&mut connection, &[event(), event()], 2).unwrap();
        let mut invalid = event();
        invalid.generation = u64::MAX;
        assert!(write(&mut connection, &[event(), invalid], 1).is_err());
        assert_eq!(ids(&connection), vec![1, 2]);
        write(&mut connection, &[event()], 2).unwrap();
        assert_eq!(ids(&connection), vec![2, 3]);
    }
    #[test]
    fn retained_row_count_tracks_inserts_evictions_and_failed_batches() {
        let (_directory, mut connection) = database();
        let mut history = History::open(&connection, 5).unwrap();
        history.write(&mut connection, &vec![event(); 3]).unwrap();
        assert_eq!(history.rows, 3);
        history.write(&mut connection, &vec![event(); 4]).unwrap();
        assert_eq!(history.rows, 5);
        let mut invalid = event();
        invalid.generation = u64::MAX;
        assert!(history.write(&mut connection, &[invalid]).is_err());
        assert_eq!(history.rows, 5);
        assert_eq!(History::count(&connection).unwrap(), 5);
        // A reopened store starts from the durable count, not from zero.
        assert_eq!(History::open(&connection, 5).unwrap().rows, 5);
        // The creation-time index is gone; retention never needed it.
        let indexes: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE type='index' AND name='queries_created'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(indexes, 0);
    }
    #[test]
    fn revision_commits_are_full_sync_and_history_stays_normal() {
        let (_directory, mut connection) = database();
        let synchronous = |connection: &Connection| {
            connection
                .query_row("PRAGMA synchronous", [], |r| r.get::<_, i64>(0))
                .unwrap()
        };
        // 1 = NORMAL, 2 = FULL.
        assert_eq!(synchronous(&connection), 1);
        let seen = durable(&mut connection, |connection| Ok(synchronous(connection))).unwrap();
        assert_eq!(seen, 2);
        assert_eq!(synchronous(&connection), 1);
        assert!(durable(&mut connection, |_| Err::<(), _>(StoreError::Response)).is_err());
        assert_eq!(synchronous(&connection), 1);
        let mode: String = connection
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
    }
    #[cfg(unix)]
    #[test]
    fn new_databases_are_private_files() {
        use std::os::unix::fs::PermissionsExt;
        let (directory, _connection) = database();
        let mode = std::fs::metadata(directory.path().join("dns.sqlite"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let wal = std::fs::metadata(directory.path().join("dns.sqlite-wal"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(wal & 0o077, 0);
    }
    #[tokio::test]
    async fn worker_blocks_until_work_and_flushes_partial_batches() {
        let directory = tempfile::tempdir().unwrap();
        let (sender, events) = mpsc::channel(16);
        let cancel = CancellationToken::new();
        let (store, done) = Store::start(
            directory.path().join("dns.sqlite"),
            10,
            events,
            cancel.clone(),
        )
        .await
        .unwrap();
        sender.send(event()).await.unwrap();
        // One event, far below a full batch, is persisted after the flush interval.
        tokio::time::timeout(Duration::from_secs(2), async {
            while store.metrics.persisted_events.load(Ordering::Relaxed) == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(store.queries(10).await.unwrap().len(), 1);
        for _ in 0..3 {
            sender.send(event()).await.unwrap();
        }
        cancel.cancel();
        done.await.unwrap();
        assert_eq!(store.metrics.persisted_events.load(Ordering::Relaxed), 4);
    }
    fn bootstrap(connection: &mut Connection, config: &str) -> Result<Bootstrap, StoreError> {
        match execute(
            connection,
            Operation::Bootstrap {
                config: config.into(),
            },
        )? {
            Reply::Bootstrap(bootstrap) => Ok(bootstrap),
            _ => Err(StoreError::Response),
        }
    }
    fn commit(connection: &mut Connection, id: u64, mode: RevisionMode) {
        execute(
            connection,
            Operation::Commit {
                id,
                config: format!("{{\"revision\":{id}}}"),
                mode,
                actor: "test".into(),
                diff: "policies".into(),
            },
        )
        .unwrap();
    }
    #[test]
    fn restart_after_retention_never_resurrects_revision_one() {
        let (_directory, mut connection) = database();
        assert!(matches!(
            execute(&mut connection, Operation::Load).unwrap(),
            Reply::Load(None)
        ));
        let first = bootstrap(&mut connection, "{\"file\":1}").unwrap();
        assert_eq!((first.active, first.next), (1, 2));
        for id in 2..=40 {
            commit(&mut connection, id, RevisionMode::Promoted);
        }
        let pruned = |connection: &Connection| {
            connection
                .query_row("SELECT COUNT(*) FROM revisions WHERE id=1", [], |r| {
                    r.get::<_, i64>(0)
                })
                .unwrap()
                == 0
        };
        assert!(pruned(&connection));
        // A restart passes today's file content; it must not become revision 1.
        let restarted = bootstrap(&mut connection, "{\"file\":2}").unwrap();
        assert!(pruned(&connection));
        assert_eq!(restarted.active, 40);
        assert_eq!(restarted.next, 41);
        assert_eq!(restarted.config, "{\"revision\":40}");
        // Revisions without an active pointer are never silently re-seeded.
        connection
            .execute("DELETE FROM runtime WHERE key='active'", [])
            .unwrap();
        assert!(matches!(
            bootstrap(&mut connection, "{}"),
            Err(StoreError::MissingActive)
        ));
        assert!(pruned(&connection));
    }
    #[test]
    fn pointer_and_revision_corruption_is_reported_not_hidden() {
        let (_directory, mut connection) = database();
        bootstrap(&mut connection, "{}").unwrap();
        commit(&mut connection, 2, RevisionMode::Shadow);
        // A real read error is not "no shadow".
        connection
            .execute("UPDATE runtime SET value='two' WHERE key='shadow'", [])
            .unwrap();
        assert!(matches!(
            bootstrap(&mut connection, "{}"),
            Err(StoreError::Sqlite(_))
        ));
        connection
            .execute("UPDATE runtime SET value=99 WHERE key='active'", [])
            .unwrap();
        connection
            .execute("UPDATE runtime SET value=2 WHERE key='shadow'", [])
            .unwrap();
        assert_eq!(
            bootstrap(&mut connection, "{}").unwrap_err().to_string(),
            "runtime active pointer refers to missing revision 99"
        );
        connection
            .execute("UPDATE revisions SET config='{' WHERE id=2", [])
            .unwrap();
        let error = execute(&mut connection, Operation::Revision { id: 2 })
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "stored revision 2 is not valid JSON");
        assert!(std::error::Error::source(&error).is_some());
        assert!(matches!(
            execute(&mut connection, Operation::Revision { id: 3 }).unwrap(),
            Reply::Revision(None)
        ));
    }
}
