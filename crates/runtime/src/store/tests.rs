#![allow(clippy::unwrap_used)]
use super::{schema::durable, worker::execute, *};
use rusqlite::Connection;
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
fn write(connection: &mut Connection, batch: &[QueryEvent], limit: u64) -> Result<(), StoreError> {
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
        while store.metrics.snapshot().persisted_events == 0 {
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
    assert_eq!(store.metrics.snapshot().persisted_events, 4);
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
