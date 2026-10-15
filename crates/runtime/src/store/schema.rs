//! Private files, schema migration, WAL and revision durability boundaries.
use super::{SCHEMA_VERSION, StoreError};
use rusqlite::Connection;
use std::{path::Path, time::Duration};

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
pub(super) fn open(path: &Path) -> Result<Connection, StoreError> {
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
        CREATE TABLE IF NOT EXISTS privacy(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL CHECK(revision>0),mode INTEGER NOT NULL CHECK(mode BETWEEN 0 AND 2),retention_rows INTEGER NOT NULL CHECK(retention_rows BETWEEN 0 AND 1000000),next_query_id INTEGER NOT NULL CHECK(next_query_id>0));
        CREATE TABLE IF NOT EXISTS queries(id INTEGER PRIMARY KEY,created TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),client TEXT NOT NULL,domain TEXT NOT NULL,qtype INTEGER NOT NULL,generation INTEGER NOT NULL,policy INTEGER NOT NULL,action TEXT NOT NULL,rule INTEGER,decision_cached INTEGER NOT NULL,rcode INTEGER NOT NULL,source TEXT NOT NULL,latency_us INTEGER NOT NULL,shadow TEXT,temporary_exception INTEGER,matched_domain TEXT,matched_type INTEGER CHECK(matched_type BETWEEN 1 AND 65535),service_schedule INTEGER CHECK(service_schedule IN (0,1,2)));
        -- Nothing reads by creation time and retention no longer counts rows,
        -- so this index only cost a B-tree update per history insert.
        DROP INDEX IF EXISTS queries_created;")?;
    if version == 1 {
        tx.execute_batch("ALTER TABLE queries ADD COLUMN temporary_exception INTEGER;")?;
    }
    if matches!(version, 1 | 2) {
        tx.execute_batch("ALTER TABLE queries ADD COLUMN matched_domain TEXT;")?;
    }
    if (1..=4).contains(&version) {
        tx.execute_batch("ALTER TABLE queries ADD COLUMN service_schedule INTEGER CHECK(service_schedule IN (0,1,2));")?;
    }
    if (1..=5).contains(&version) {
        tx.execute_batch("ALTER TABLE queries ADD COLUMN matched_type INTEGER CHECK(matched_type BETWEEN 1 AND 65535); UPDATE queries SET matched_type=5 WHERE matched_domain IS NOT NULL;")?;
    }
    tx.prepare("SELECT temporary_exception,matched_domain,matched_type,service_schedule FROM queries LIMIT 0")?;
    tx.prepare("SELECT id,revision,mode,retention_rows,next_query_id FROM privacy LIMIT 0")?;
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    tx.commit()?;
    Ok(connection)
}
/// Revision and pointer changes are fsynced on commit (`synchronous=FULL`);
/// the pragma is switched between transactions and restored afterwards.
pub(super) fn durable<T>(
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

pub(super) fn from_sql_id(id: i64) -> rusqlite::Result<u64> {
    u64::try_from(id).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Integer, Box::new(e))
    })
}
pub(super) fn sql_id(id: u64) -> rusqlite::Result<i64> {
    i64::try_from(id).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
}
