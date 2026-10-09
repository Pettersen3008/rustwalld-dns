//! A dedicated SQLite thread with bounded commands and bounded telemetry batches.
use rusqlite::{Connection, OptionalExtension, params};
use rustwalld_dns_core::telemetry::QueryEvent;
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

pub const SCHEMA_VERSION: i64 = 2;

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
    pub id: i64,
    pub timestamp: String,
    pub actor: String,
    pub state: String,
    pub diff: String,
}
#[derive(Debug, Serialize)]
pub struct HistoryEntry {
    pub id: i64,
    pub timestamp: String,
    pub client: String,
    pub domain: String,
    pub qtype: u16,
    pub generation: i64,
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
    pub async fn start(
        path: PathBuf,
        history_rows: usize,
        mut events: mpsc::Receiver<QueryEvent>,
        cancel: CancellationToken,
    ) -> Result<(Self, oneshot::Receiver<()>), StoreError> {
        let (sender, mut commands) = mpsc::channel::<Command>(32);
        let (ready_tx, ready_rx) = oneshot::channel();
        let (done_tx, done_rx) = oneshot::channel();
        let metrics = Arc::new(StoreMetrics::default());
        let counts = metrics.clone();
        std::thread::Builder::new()
            .name("dns-sqlite".into())
            .spawn(move || {
                let mut connection = match open(path) {
                    Ok(c) => {
                        let _ = ready_tx.send(Ok(()));
                        c
                    }
                    Err(error) => {
                        let _ = ready_tx.send(Err(StoreError::Sqlite(error)));
                        let _ = done_tx.send(());
                        return;
                    }
                };
                loop {
                    for _ in 0..8 {
                        match commands.try_recv() {
                            Ok(command) => {
                                let result = execute(&mut connection, command.operation);
                                let _ = command.reply.send(result);
                            }
                            Err(_) => break,
                        }
                    }
                    let mut batch = Vec::with_capacity(256);
                    while batch.len() < 256 {
                        match events.try_recv() {
                            Ok(event) => batch.push(event),
                            Err(_) => break,
                        }
                    }
                    if !batch.is_empty() {
                        match write_events(&mut connection, &batch, history_rows) {
                            Ok(()) => {
                                counts
                                    .persisted_events
                                    .fetch_add(batch.len() as u64, Ordering::Relaxed);
                            }
                            Err(error) => {
                                counts
                                    .write_failures
                                    .fetch_add(batch.len() as u64, Ordering::Relaxed);
                                tracing::warn!(%error,"query history batch dropped");
                            }
                        }
                    }
                    if cancel.is_cancelled() && events.is_empty() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
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
        // Reads may time out. Mutations are deliberately awaited to completion:
        // a timed-out commit must not become durable without atomic promotion.
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
    /// Commit the unchanged schema transaction; live publication belongs to control.
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
fn open(path: PathBuf) -> rusqlite::Result<Connection> {
    let mut connection = Connection::open(path)?;
    connection.busy_timeout(Duration::from_millis(250))?;
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if !(0..=SCHEMA_VERSION).contains(&version) {
        return Err(rusqlite::Error::InvalidParameterName(format!(
            "unsupported database schema {version}; expected {SCHEMA_VERSION}"
        )));
    }
    connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;
    let tx = connection.transaction()?;
    tx.execute_batch("
        CREATE TABLE IF NOT EXISTS revisions(id INTEGER PRIMARY KEY,created TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),actor TEXT NOT NULL,state TEXT NOT NULL,diff TEXT NOT NULL,config TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS runtime(key TEXT PRIMARY KEY,value INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS queries(id INTEGER PRIMARY KEY,created TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),client TEXT NOT NULL,domain TEXT NOT NULL,qtype INTEGER NOT NULL,generation INTEGER NOT NULL,policy INTEGER NOT NULL,action TEXT NOT NULL,rule INTEGER,decision_cached INTEGER NOT NULL,rcode INTEGER NOT NULL,source TEXT NOT NULL,latency_us INTEGER NOT NULL,shadow TEXT,temporary_exception INTEGER);
        CREATE INDEX IF NOT EXISTS queries_created ON queries(created);")?;
    if version == 1 {
        tx.execute_batch("ALTER TABLE queries ADD COLUMN temporary_exception INTEGER;")?;
    }
    tx.prepare("SELECT temporary_exception FROM queries LIMIT 0")?;
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    tx.commit()?;
    Ok(connection)
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
            let tx = connection.transaction()?;
            if let Some(existing) = pointers(&tx)? {
                tx.commit()?;
                return Ok(Reply::Bootstrap(existing));
            }
            // Never resurrect a retention-pruned ID with different content.
            let revisions: i64 =
                tx.query_row("SELECT COUNT(*) FROM revisions", [], |r| r.get(0))?;
            if revisions != 0 {
                return Err(StoreError::MissingActive);
            }
            tx.execute("INSERT INTO revisions(id,actor,state,diff,config) VALUES(1,'startup','promoted','initial configuration',?1)",[config])?;
            tx.execute("INSERT INTO runtime(key,value) VALUES('active',1)", [])?;
            let bootstrap = pointers(&tx)?.ok_or(StoreError::MissingActive)?;
            tx.commit()?;
            Ok(Reply::Bootstrap(bootstrap))
        }
        Operation::Queries { limit } => {
            let mut stmt=connection.prepare("SELECT id,created,client,domain,qtype,generation,policy,action,rule,decision_cached,rcode,source,latency_us,shadow,temporary_exception FROM queries ORDER BY id DESC LIMIT ?1")?;
            let rows = stmt.query_map([limit.clamp(1, 1000) as i64], |r| {
                Ok(HistoryEntry {
                    id: r.get(0)?,
                    timestamp: r.get(1)?,
                    client: r.get(2)?,
                    domain: r.get(3)?,
                    qtype: r.get(4)?,
                    generation: r.get(5)?,
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
            Ok(Reply::Queries(rows.collect::<rusqlite::Result<Vec<_>>>()?))
        }
        Operation::Revisions => {
            let mut stmt = connection
                .prepare("SELECT id,created,actor,state,diff FROM revisions ORDER BY id DESC")?;
            let rows = stmt.query_map([], |r| {
                Ok(RevisionSummary {
                    id: r.get(0)?,
                    timestamp: r.get(1)?,
                    actor: r.get(2)?,
                    state: r.get(3)?,
                    diff: r.get(4)?,
                })
            })?;
            Ok(Reply::Revisions(
                rows.collect::<rusqlite::Result<Vec<_>>>()?,
            ))
        }
        Operation::Revision { id } => {
            let text: Option<String> = connection
                .query_row(
                    "SELECT config FROM revisions WHERE id=?1",
                    [sql_id(id)?],
                    |r| r.get(0),
                )
                .optional()?;
            let revision = text
                .map(|text| {
                    serde_json::from_str(&text)
                        .map(|config| Revision { id, config })
                        .map_err(|source| StoreError::CorruptRevision { id, source })
                })
                .transpose()?;
            Ok(Reply::Revision(revision))
        }
        Operation::Commit {
            id,
            config,
            mode,
            actor,
            diff,
        } => {
            let tx = connection.transaction()?;
            tx.execute(
                "INSERT INTO revisions(id,actor,state,diff,config) VALUES(?1,?2,?3,?4,?5)",
                params![sql_id(id)?, actor, mode.as_str(), diff, config],
            )?;
            let key = if matches!(mode, RevisionMode::Shadow) {
                "shadow"
            } else {
                "active"
            };
            tx.execute("INSERT INTO runtime(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",params![key,sql_id(id)?])?;
            if !matches!(mode, RevisionMode::Shadow) {
                tx.execute("DELETE FROM runtime WHERE key='shadow'", [])?;
            }
            // Retain recent revisions and any currently active/shadow generation.
            tx.execute("DELETE FROM revisions WHERE id NOT IN (SELECT id FROM revisions ORDER BY id DESC LIMIT 32) AND id NOT IN (SELECT value FROM runtime)",[])?;
            tx.commit()?;
            Ok(Reply::Commit(CommitReport {
                generation: id,
                state: mode,
            }))
        }
        Operation::ClearShadow => {
            connection.execute("DELETE FROM runtime WHERE key='shadow'", [])?;
            Ok(Reply::ClearShadow(ClearShadowReport { shadow: None }))
        }
    }
}
fn write_events(
    connection: &mut Connection,
    batch: &[QueryEvent],
    limit: usize,
) -> rusqlite::Result<()> {
    let tx = connection.transaction()?;
    {
        let mut stmt=tx.prepare_cached("INSERT INTO queries(client,domain,qtype,generation,policy,action,rule,decision_cached,rcode,source,latency_us,shadow,temporary_exception) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)")?;
        for event in batch {
            let shadow=event.shadow.as_ref().map(|s|json!({"generation":s.generation,"policy_id":s.policy,"decision":s.decision,"rewrite":s.rewrite,"differs":s.differs,"temporary_exception":s.temporary_exception}).to_string());
            stmt.execute(params![
                event.client.to_string(),
                event.domain,
                event.qtype,
                sql_id(event.generation)?,
                event.policy as i64,
                if event.decision.action == rustwalld_dns_filter::Action::Block {
                    "block"
                } else {
                    "allow"
                },
                event.decision.rule,
                event.decision_cached,
                event.response_code,
                event.source.as_str(),
                event.latency_us.min(i64::MAX as u64) as i64,
                shadow,
                event.temporary_exception
            ])?;
        }
    }
    // Count using SQLite's compact covering index; scan only the rows to evict.
    // Walking `limit` newest rows on every small batch competes with DNS for CPU.
    let rows: i64 = tx.query_row("SELECT COUNT(*) FROM queries", [], |row| row.get(0))?;
    let excess = rows - limit.min(i64::MAX as usize) as i64;
    if excess > 0 {
        tx.execute("DELETE FROM queries WHERE id <= (SELECT id FROM queries ORDER BY id ASC LIMIT 1 OFFSET ?1)", [excess - 1])?;
    }
    tx.commit()
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
    #[test]
    fn history_retains_newest_rows_with_sparse_ids_and_changing_limits() {
        let mut connection = open(PathBuf::from(":memory:")).unwrap();
        write_events(&mut connection, &vec![event(); 10], 12).unwrap();
        assert_eq!(ids(&connection).len(), 10);
        connection
            .execute_batch("UPDATE queries SET id=-id; UPDATE queries SET id=-id*10; DELETE FROM queries WHERE id IN(40,70)")
            .unwrap();
        write_events(&mut connection, &[event()], 4).unwrap();
        assert_eq!(ids(&connection), vec![80, 90, 100, 101]);
        write_events(&mut connection, &vec![event(); 6], 4).unwrap();
        assert_eq!(ids(&connection), vec![104, 105, 106, 107]);
        write_events(&mut connection, &[event()], 1).unwrap();
        assert_eq!(ids(&connection), vec![108]);
    }
    #[test]
    fn failed_history_batch_cannot_insert_or_trim_partial_state() {
        let mut connection = open(PathBuf::from(":memory:")).unwrap();
        write_events(&mut connection, &[event(), event()], 2).unwrap();
        let mut invalid = event();
        invalid.generation = u64::MAX;
        assert!(write_events(&mut connection, &[event(), invalid], 1).is_err());
        assert_eq!(ids(&connection), vec![1, 2]);
        write_events(&mut connection, &[event()], 2).unwrap();
        assert_eq!(ids(&connection), vec![2, 3]);
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
        let mut connection = open(PathBuf::from(":memory:")).unwrap();
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
        let mut connection = open(PathBuf::from(":memory:")).unwrap();
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
