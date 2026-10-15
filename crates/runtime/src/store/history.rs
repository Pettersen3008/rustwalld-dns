//! Atomic query batches, retained row accounting and history reads.
use super::{
    HistoryEntry, StoreError,
    schema::{from_sql_id, sql_id},
};
use rusqlite::OptionalExtension;
use rusqlite::{Connection, params};
use rustwalld_dns_core::telemetry::QueryEvent;
use serde_json::{Value, json};

/// Bounded best-effort history. The retained row count lives in memory, so a
/// batch never scans the table (a `COUNT(*)` per batch is O(rows)).
pub(super) struct History {
    pub(super) limit: u64,
    pub(super) rows: u64,
    pub(super) mode: super::HistoryMode,
    next_id: u64,
}
impl History {
    pub(super) fn open(
        connection: &Connection,
        privacy: &super::Privacy,
    ) -> Result<Self, StoreError> {
        Ok(Self {
            limit: u64::try_from(privacy.retention_rows).unwrap_or(u64::MAX),
            rows: Self::count(connection)?,
            mode: privacy.mode,
            next_id:from_sql_id(connection.query_row("SELECT MAX(next_query_id,(SELECT COALESCE(MAX(id),0)+1 FROM queries)) FROM privacy WHERE id=1",[],|row|row.get(0))?)?,
        })
    }
    pub(super) fn count(connection: &Connection) -> Result<u64, StoreError> {
        let rows: i64 = connection.query_row("SELECT COUNT(*) FROM queries", [], |r| r.get(0))?;
        Ok(from_sql_id(rows)?)
    }
    /// Insert one atomic batch and evict only the oldest excess rows.
    /// History favors throughput over durability (`synchronous=NORMAL`): a
    /// power loss may drop recent batches but never corrupts the database.
    pub(super) fn write(
        &mut self,
        connection: &mut Connection,
        batch: &[QueryEvent],
    ) -> Result<(), StoreError> {
        if self.mode == super::HistoryMode::Disabled {
            return Ok(());
        }
        let tx = connection.transaction()?;
        let mut next_id = self.next_id;
        {
            let mut stmt=tx.prepare_cached("INSERT INTO queries(client,domain,qtype,generation,policy,action,rule,decision_cached,rcode,source,latency_us,shadow,temporary_exception,matched_domain,matched_type,service_schedule,id) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)")?;
            for event in batch {
                let shadow = event.shadow.as_ref().map(|s| {
                    json!({
                        "generation": s.generation,
                        "policy_id": s.policy,
                        "decision": s.decision,
                        "rewrite": s.rewrite,
                        "differs": s.differs,
                        "temporary_exception": s.temporary_exception,
                        "service_schedule": s.service_schedule,
                    })
                    .to_string()
                });
                stmt.execute(params![
                    if self.mode == super::HistoryMode::NoClientIdentity {
                        "anonymous".into()
                    } else {
                        event.client.to_string()
                    },
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
                    event.temporary_exception,
                    event.matched_domain,
                    event.matched_type,
                    event.service_schedule.map(|state| state.code()),
                    sql_id(next_id)?
                ])?;
                next_id = next_id.checked_add(1).ok_or(StoreError::Response)?;
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
        if tx.execute(
            "UPDATE privacy SET next_query_id=?1 WHERE id=1",
            [sql_id(next_id)?],
        )? != 1
        {
            return Err(StoreError::Response);
        }
        tx.commit()?;
        self.next_id = next_id;
        self.rows = rows.saturating_sub(u64::try_from(evicted).unwrap_or(u64::MAX));
        Ok(())
    }
}

pub(super) fn queries(
    connection: &Connection,
    limit: usize,
) -> Result<Vec<HistoryEntry>, StoreError> {
    let mut stmt=connection.prepare("SELECT id,created,client,domain,qtype,generation,policy,action,rule,decision_cached,rcode,source,latency_us,shadow,temporary_exception,matched_domain,service_schedule,matched_type FROM queries ORDER BY id DESC LIMIT ?1")?;
    let limit = i64::try_from(limit.clamp(1, 1000)).unwrap_or(1000);
    let rows = stmt.query_map([limit], entry)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}
pub(super) fn query(connection: &Connection, id: u64) -> Result<Option<HistoryEntry>, StoreError> {
    let Ok(id) = i64::try_from(id) else {
        return Ok(None);
    };
    Ok(connection.query_row("SELECT id,created,client,domain,qtype,generation,policy,action,rule,decision_cached,rcode,source,latency_us,shadow,temporary_exception,matched_domain,service_schedule,matched_type FROM queries WHERE id=?1",[id],entry).optional()?)
}
fn entry(r: &rusqlite::Row<'_>) -> rusqlite::Result<HistoryEntry> {
    Ok(HistoryEntry {
        id: from_sql_id(r.get(0)?)?,
        timestamp: r.get(1)?,
        client: r.get(2)?,
        client_masked: r.get::<_, String>(2)? == "anonymous",
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
        matched_domain: r.get(15)?,
        matched_type: r.get(17)?,
        service_schedule: r
            .get::<_, Option<u8>>(16)?
            .map(|code| {
                rustwalld_dns_policy::ServiceScheduleState::from_code(code).ok_or(
                    rusqlite::Error::IntegralValueOutOfRange(16, i64::from(code)),
                )
            })
            .transpose()?,
    })
}
