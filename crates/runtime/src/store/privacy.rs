//! One durable, bounded preference row; independent of policy revisions.
use super::{
    StoreError,
    schema::{durable, from_sql_id, sql_id},
};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
/// What retained query history contains.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryMode {
    /// Source addresses and query names.
    Full,
    /// Query names/policy provenance, with source identity replaced by anonymous.
    NoClientIdentity,
    /// No new query-history writes; live aggregate metrics remain active.
    Disabled,
}
impl HistoryMode {
    pub(super) fn sql(self) -> u8 {
        match self {
            Self::Full => 0,
            Self::NoClientIdentity => 1,
            Self::Disabled => 2,
        }
    }
    pub(super) fn from_sql(value: u8) -> rusqlite::Result<Self> {
        match value {
            0 => Ok(Self::Full),
            1 => Ok(Self::NoClientIdentity),
            2 => Ok(Self::Disabled),
            _ => Err(rusqlite::Error::InvalidQuery),
        }
    }
}
/// Persisted privacy settings and current retained-row count.
#[derive(Clone, Debug, Serialize)]
pub struct Privacy {
    /// Independent monotonically increasing revision.
    pub revision: u64,
    /// Logging mode.
    pub mode: HistoryMode,
    /// Maximum retained rows, at most one million.
    pub retention_rows: usize,
    /// Actually retained rows; queued events are excluded.
    pub retained_rows: u64,
}
/// A reviewed preference change, compared with its own current revision.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivacyChange {
    /// Mode to publish after durable commit.
    pub mode: HistoryMode,
    /// New row limit, at most one million.
    pub retention_rows: usize,
    /// Explicitly remove retained query rows in the same update.
    pub clear_history: bool,
}
impl PrivacyChange {
    /// Validate bounds before database admission.
    pub fn validate(&self) -> Result<(), String> {
        if self.retention_rows > 1000000
            || (self.retention_rows == 0 && self.mode != HistoryMode::Disabled)
        {
            return Err(
                "history retention must be 1..1000000 rows, or zero with logging disabled".into(),
            );
        }
        Ok(())
    }
}
pub(super) fn read(connection: &Connection) -> Result<Option<Privacy>, StoreError> {
    Ok(connection
        .query_row(
            "SELECT revision,mode,retention_rows FROM privacy WHERE id=1",
            [],
            |row| {
                Ok(Privacy {
                    revision: from_sql_id(row.get(0)?)?,
                    mode: HistoryMode::from_sql(row.get(1)?)?,
                    retention_rows: usize::try_from(row.get::<_, u32>(2)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    retained_rows: 0,
                })
            },
        )
        .optional()?)
}
pub(super) fn initialize(connection: &mut Connection, rows: usize) -> Result<Privacy, StoreError> {
    if let Some(value) = read(connection)? {
        validate(&value)?;
        return Ok(value);
    }
    durable(connection, |connection| {
        connection.execute(
            "INSERT INTO privacy(id,revision,mode,retention_rows,next_query_id) VALUES(1,1,?1,?2,(SELECT COALESCE(MAX(id),0)+1 FROM queries))",
            (
                if rows == 0 { 2 } else { 0 },
                i64::try_from(rows).unwrap_or(1000000),
            ),
        )?;
        Ok(())
    })?;
    read(connection)?.ok_or(StoreError::Response)
}
fn validate(value: &Privacy) -> Result<(), StoreError> {
    if value.revision == 0
        || (PrivacyChange {
            mode: value.mode,
            retention_rows: value.retention_rows,
            clear_history: false,
        })
        .validate()
        .is_err()
    {
        return Err(StoreError::Response);
    }
    Ok(())
}
pub(super) fn change(
    connection: &mut Connection,
    current: &Privacy,
    input: &PrivacyChange,
) -> Result<Privacy, StoreError> {
    let revision = current
        .revision
        .checked_add(1)
        .ok_or(StoreError::Response)?;
    durable(connection, |connection| {
        let tx = connection.transaction()?;
        let updated = tx.execute(
            "UPDATE privacy SET revision=?1,mode=?2,retention_rows=?3 WHERE id=1 AND revision=?4",
            (
                sql_id(revision)?,
                input.mode.sql(),
                i64::try_from(input.retention_rows).unwrap_or(1000000),
                sql_id(current.revision)?,
            ),
        )?;
        if updated != 1 {
            return Err(StoreError::Response);
        }
        if input.clear_history || input.retention_rows == 0 {
            tx.execute("DELETE FROM queries", [])?;
        } else {
            tx.execute("DELETE FROM queries WHERE id < COALESCE((SELECT id FROM queries ORDER BY id DESC LIMIT 1 OFFSET ?1),0)",[i64::try_from(input.retention_rows-1).unwrap_or(999999)])?;
        }
        let retained_rows = super::history::History::count(&tx)?;
        tx.commit()?;
        Ok(Privacy {
            revision,
            mode: input.mode,
            retention_rows: input.retention_rows,
            retained_rows,
        })
    })
}
