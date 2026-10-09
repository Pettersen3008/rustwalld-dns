//! Standalone maintenance: no daemon runtime, API token or DNS executor involved.
use crate::store::SCHEMA_VERSION;
use rusqlite::{
    Connection, OpenFlags, OptionalExtension,
    backup::{Backup, StepResult},
};
use rustwalld_dns_policy::{PolicyConfigSet, PolicySnapshot};
use serde::Serialize;
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
/// Summary of a verified database.
#[derive(Debug, Serialize)]
pub struct Report {
    /// Schema version.
    pub schema: i64,
    /// Active revision.
    pub active_generation: u64,
    /// Shadow revision, if staged.
    pub shadow_generation: Option<u64>,
    /// Stored revisions.
    pub revisions: u64,
    /// Stored query history rows.
    pub history_rows: u64,
}
fn read_only(path: &Path) -> Result<Connection> {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    connection.busy_timeout(Duration::from_millis(100))?;
    connection.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA query_only=ON;")?;
    Ok(connection)
}
/// Open `path` read-only and check its schema, pointers and revisions.
///
/// # Errors
///
/// When the database is unreadable, has an unsupported schema, unsafe
/// objects, or dangling pointers.
pub fn verify(path: &Path) -> Result<Report> {
    let mut connection = read_only(path)?;
    // One read transaction keeps the runtime pointers and revision content consistent.
    let tx = connection.transaction()?;
    let version: i64 = tx.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if !(1..=SCHEMA_VERSION).contains(&version) {
        return Err(
            format!("unsupported database schema {version}; expected {SCHEMA_VERSION}").into(),
        );
    }
    let integrity: String = tx.query_row("PRAGMA integrity_check(1)", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(format!("database integrity check failed: {integrity}").into());
    }
    let tables = {
        let mut stmt = tx.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")?;
        stmt.query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    if tables != ["queries", "revisions", "runtime"] {
        return Err("unrecognized database tables".into());
    }
    let executable: i64 = tx.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE type IN ('trigger','view')",
        [],
        |row| row.get(0),
    )?;
    if executable != 0 {
        return Err("backup must not contain triggers or views".into());
    }
    // Preparing these queries verifies all columns required on the next daemon boot.
    tx.prepare("SELECT id,created,actor,state,diff,config FROM revisions LIMIT 0")?;
    tx.prepare("SELECT id,created,client,domain,qtype,generation,policy,action,rule,decision_cached,rcode,source,latency_us,shadow FROM queries LIMIT 0")?;
    if version >= 2 {
        tx.prepare("SELECT temporary_exception FROM queries LIMIT 0")?;
    }
    let mut active = None;
    let mut shadow = None;
    {
        let mut statement = tx.prepare("SELECT key,value FROM runtime")?;
        for row in statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })? {
            let (key, generation) = row?;
            let generation = u64::try_from(generation)?;
            if generation == 0 {
                return Err("zero runtime generation".into());
            }
            match key.as_str() {
                "active" if active.is_none() => active = Some(generation),
                "shadow" if shadow.is_none() => shadow = Some(generation),
                _ => return Err("invalid runtime revision pointer".into()),
            }
            let id = i64::try_from(generation)?;
            let size: i64 = tx
                .query_row(
                    "SELECT length(CAST(config AS BLOB)) FROM revisions WHERE id=?1",
                    [id],
                    |row| row.get(0),
                )
                .optional()?
                .ok_or_else(|| {
                    format!("runtime {key} pointer refers to missing revision {generation}")
                })?;
            if !(1..=512 * 1024 * 1024).contains(&size) {
                return Err("stored policy content exceeds maintenance limit".into());
            }
            let text: String =
                tx.query_row("SELECT config FROM revisions WHERE id=?1", [id], |row| {
                    row.get(0)
                })?;
            let config: PolicyConfigSet = serde_json::from_str(&text)?;
            crate::downloads::validate_config(&config).map_err(crate::config::invalid)?;
            PolicySnapshot::compile(config, generation)?;
        }
    }
    let active_generation = active.ok_or("missing active revision")?;
    let revisions: i64 = tx.query_row("SELECT count(*) FROM revisions", [], |row| row.get(0))?;
    let history_rows: i64 = tx.query_row("SELECT count(*) FROM queries", [], |row| row.get(0))?;
    tx.commit()?;
    Ok(Report {
        schema: version,
        active_generation,
        shadow_generation: shadow,
        revisions: u64::try_from(revisions)?,
        history_rows: u64::try_from(history_rows)?,
    })
}
fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}
/// Copy a live database (including WAL content) to a new private file,
/// verify it and publish it without clobbering an existing file.
///
/// # Errors
///
/// When the copy cannot complete within 30 seconds, verification fails, or
/// `output` exists.
pub fn snapshot(source: &Path, output: &Path) -> Result<Report> {
    for path in [
        output.to_path_buf(),
        sidecar(output, "-wal"),
        sidecar(output, "-shm"),
        sidecar(output, "-journal"),
    ] {
        if fs::symlink_metadata(&path).is_ok() {
            return Err(format!(
                "destination exists: {} (stop service and use a new path)",
                path.display()
            )
            .into());
        }
    }
    let source = read_only(source)?;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(parent)?.permissions().mode() & 0o022 != 0 {
            return Err("backup destination directory must not be group/world writable".into());
        }
    }
    let temporary = tempfile::Builder::new()
        .prefix(".rustwalld-backup-")
        .tempfile_in(parent)?;
    let mut destination = Connection::open(temporary.path())?;
    destination.busy_timeout(Duration::from_millis(100))?;
    {
        let backup = Backup::new(&source, &mut destination)?;
        let deadline = Instant::now() + Duration::from_secs(30);
        // Copy every page in one step under a single WAL read transaction, which
        // never blocks the daemon's writers. Incremental steps restart whenever
        // another connection writes, so under traffic they may never finish.
        loop {
            match backup.step(-1)? {
                StepResult::Done => break,
                StepResult::More | StepResult::Busy | StepResult::Locked
                    if Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10))
                }
                StepResult::More | StepResult::Busy | StepResult::Locked => {
                    return Err(
                        "backup copy exceeded 30-second deadline; retry during quieter traffic"
                            .into(),
                    );
                }
                _ => return Err("unrecognized SQLite backup state".into()),
            }
        }
    }
    // The delivered snapshot is one standalone file, never a main/WAL file pair.
    destination.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;")?;
    destination.close().map_err(|(_, error)| error)?;
    let report = verify(temporary.path())?;
    temporary.as_file().sync_all()?;
    temporary.persist_noclobber(output)?;
    // Make the no-clobber publication durable as well as the file content.
    #[cfg(unix)]
    if let Err(error) = fs::File::open(parent).and_then(|directory| directory.sync_all()) {
        return Err(format!(
            "snapshot published at {} but directory synchronization failed: {error}; verify the target before use",
            output.display()
        ).into());
    }
    Ok(report)
}
