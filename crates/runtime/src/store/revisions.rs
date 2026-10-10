//! Durable policy pointers, content, commits and revision retention.
use super::{
    Bootstrap, CommitReport, RETAINED_REVISIONS, Revision, RevisionMode, RevisionSummary,
    StoreError,
    schema::{from_sql_id, sql_id},
};
use rusqlite::{Connection, OptionalExtension, params};

/// Read durable pointers inside one transaction, if the store was bootstrapped.
pub(super) fn pointers(tx: &rusqlite::Transaction<'_>) -> Result<Option<Bootstrap>, StoreError> {
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

pub(super) fn bootstrap(
    connection: &mut Connection,
    config: String,
) -> Result<Bootstrap, StoreError> {
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

pub(super) fn revisions(connection: &Connection) -> Result<Vec<RevisionSummary>, StoreError> {
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
pub(super) fn revision(connection: &Connection, id: u64) -> Result<Option<Revision>, StoreError> {
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
pub(super) fn commit(
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
