//! A dedicated SQLite thread with bounded commands and bounded telemetry batches.
use dns_core::telemetry::QueryEvent;
use rusqlite::{Connection, OptionalExtension, params};
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

pub enum Operation {
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
        mode: String,
        actor: String,
        diff: String,
    },
    ClearShadow,
}
struct Command {
    operation: Operation,
    reply: oneshot::Sender<Result<Value, String>>,
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
    ) -> Result<(Self, oneshot::Receiver<()>), String> {
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
                    Err(e) => {
                        let _ = ready_tx.send(Err(e.to_string()));
                        let _ = done_tx.send(());
                        return;
                    }
                };
                loop {
                    for _ in 0..8 {
                        match commands.try_recv() {
                            Ok(command) => {
                                let result = execute(&mut connection, command.operation)
                                    .map_err(|e| e.to_string());
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
            .map_err(|e| e.to_string())?;
        ready_rx.await.map_err(|e| e.to_string())??;
        Ok((Self { sender, metrics }, done_rx))
    }
    pub async fn call(&self, operation: Operation) -> Result<Value, String> {
        let (reply, receiver) = oneshot::channel();
        self.sender
            .try_send(Command { operation, reply })
            .map_err(|_| "database command queue unavailable".to_string())?;
        // Reads may time out. Mutations are deliberately awaited to completion:
        // a timed-out commit must not become durable without atomic promotion.
        receiver
            .await
            .map_err(|_| "database worker stopped".to_string())?
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
fn execute(connection: &mut Connection, operation: Operation) -> rusqlite::Result<Value> {
    match operation {
        Operation::Bootstrap { config } => {
            let tx = connection.transaction()?;
            tx.execute("INSERT OR IGNORE INTO revisions(id,actor,state,diff,config) VALUES(1,'startup','promoted','initial configuration',?1)",[config])?;
            tx.execute(
                "INSERT OR IGNORE INTO runtime(key,value) VALUES('active',1)",
                [],
            )?;
            let active: i64 =
                tx.query_row("SELECT value FROM runtime WHERE key='active'", [], |r| {
                    r.get(0)
                })?;
            let next: i64 = tx.query_row("SELECT MAX(id)+1 FROM revisions", [], |r| r.get(0))?;
            let config: String =
                tx.query_row("SELECT config FROM revisions WHERE id=?1", [active], |r| {
                    r.get(0)
                })?;
            let shadow: Option<i64> = tx
                .query_row("SELECT value FROM runtime WHERE key='shadow'", [], |r| {
                    r.get(0)
                })
                .ok();
            tx.commit()?;
            Ok(json!({"active":active,"next":next,"config":config,"shadow":shadow}))
        }
        Operation::Queries { limit } => {
            let mut stmt=connection.prepare("SELECT id,created,client,domain,qtype,generation,policy,action,rule,decision_cached,rcode,source,latency_us,shadow,temporary_exception FROM queries ORDER BY id DESC LIMIT ?1")?;
            let rows=stmt.query_map([limit.clamp(1,1000) as i64],|r|Ok(json!({"id":r.get::<_,i64>(0)?,"timestamp":r.get::<_,String>(1)?,"client":r.get::<_,String>(2)?,"domain":r.get::<_,String>(3)?,"qtype":r.get::<_,u16>(4)?,"generation":r.get::<_,i64>(5)?,"policy_id":r.get::<_,i64>(6)?,"action":r.get::<_,String>(7)?,"rule_id":r.get::<_,Option<u32>>(8)?,"decision_cached":r.get::<_,bool>(9)?,"response_code":r.get::<_,u16>(10)?,"source":r.get::<_,String>(11)?,"latency_us":r.get::<_,i64>(12)?,"shadow":r.get::<_,Option<String>>(13)?.and_then(|s|serde_json::from_str::<Value>(&s).ok()),"temporary_exception":r.get::<_,Option<u16>>(14)?})))?;
            Ok(Value::Array(rows.collect::<rusqlite::Result<Vec<_>>>()?))
        }
        Operation::Revisions => {
            let mut stmt = connection
                .prepare("SELECT id,created,actor,state,diff FROM revisions ORDER BY id DESC")?;
            let rows=stmt.query_map([],|r|Ok(json!({"id":r.get::<_,i64>(0)?,"timestamp":r.get::<_,String>(1)?,"actor":r.get::<_,String>(2)?,"state":r.get::<_,String>(3)?,"diff":r.get::<_,String>(4)?})))?;
            Ok(Value::Array(rows.collect::<rusqlite::Result<Vec<_>>>()?))
        }
        Operation::Revision { id } => {
            let text: Option<String> = connection
                .query_row(
                    "SELECT config FROM revisions WHERE id=?1",
                    [sql_id(id)?],
                    |r| r.get(0),
                )
                .optional()?;
            match text {
                Some(text) => Ok(
                    json!({"id":id,"config":serde_json::from_str::<Value>(&text).unwrap_or(Value::Null)}),
                ),
                None => Ok(Value::Null),
            }
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
                params![sql_id(id)?, actor, mode, diff, config],
            )?;
            let key = if mode == "shadow" { "shadow" } else { "active" };
            tx.execute("INSERT INTO runtime(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",params![key,sql_id(id)?])?;
            if mode != "shadow" {
                tx.execute("DELETE FROM runtime WHERE key='shadow'", [])?;
            }
            // Retain recent revisions and any currently active/shadow generation.
            tx.execute("DELETE FROM revisions WHERE id NOT IN (SELECT id FROM revisions ORDER BY id DESC LIMIT 32) AND id NOT IN (SELECT value FROM runtime)",[])?;
            tx.commit()?;
            Ok(json!({"generation":id,"state":mode}))
        }
        Operation::ClearShadow => {
            connection.execute("DELETE FROM runtime WHERE key='shadow'", [])?;
            Ok(json!({"shadow":null}))
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
                if event.decision.action == filtering::Action::Block {
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

fn sql_id(id: u64) -> rusqlite::Result<i64> {
    i64::try_from(id).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use dns_core::telemetry::QuerySource;
    fn event() -> QueryEvent {
        QueryEvent {
            client: "127.0.0.1".parse().unwrap(),
            domain: "cache.example".into(),
            qtype: 1,
            generation: 1,
            policy: 0,
            decision: filtering::Decision::ALLOW,
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
}
