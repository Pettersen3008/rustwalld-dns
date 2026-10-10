//! Atomic query batches, retained row accounting and history reads.
use super::{
    HistoryEntry, StoreError,
    schema::{from_sql_id, sql_id},
};
use rusqlite::{Connection, params};
use rustwalld_dns_core::telemetry::QueryEvent;
use serde_json::{Value, json};

/// Bounded best-effort history. The retained row count lives in memory, so a
/// batch never scans the table (a `COUNT(*)` per batch is O(rows)).
pub(super) struct History {
    pub(super) limit: u64,
    pub(super) rows: u64,
}
impl History {
    pub(super) fn open(connection: &Connection, limit: usize) -> Result<Self, StoreError> {
        Ok(Self {
            limit: u64::try_from(limit).unwrap_or(u64::MAX),
            rows: Self::count(connection)?,
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

pub(super) fn queries(
    connection: &Connection,
    limit: usize,
) -> Result<Vec<HistoryEntry>, StoreError> {
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
