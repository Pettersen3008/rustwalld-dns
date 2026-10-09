#![allow(clippy::unwrap_used)]
use rusqlite::Connection;
use rustwalld_dns::{
    maintenance,
    store::{RevisionMode, Store},
};
use rustwalld_dns_core::telemetry::Telemetry;
use rustwalld_dns_policy::PolicyConfigSet;
use std::{path::Path, time::Duration};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn schema_one_backup_restores_and_migrates_history_without_changing_revision_content() {
    let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let old = dir.path().join("old.sqlite");
    let database = Connection::open(&old).unwrap();
    database.execute_batch("CREATE TABLE revisions(id INTEGER PRIMARY KEY,created TEXT NOT NULL DEFAULT 'old',actor TEXT NOT NULL,state TEXT NOT NULL,diff TEXT NOT NULL,config TEXT NOT NULL);
        CREATE TABLE runtime(key TEXT PRIMARY KEY,value INTEGER NOT NULL);
        CREATE TABLE queries(id INTEGER PRIMARY KEY,created TEXT NOT NULL,client TEXT NOT NULL,domain TEXT NOT NULL,qtype INTEGER NOT NULL,generation INTEGER NOT NULL,policy INTEGER NOT NULL,action TEXT NOT NULL,rule INTEGER,decision_cached INTEGER NOT NULL,rcode INTEGER NOT NULL,source TEXT NOT NULL,latency_us INTEGER NOT NULL,shadow TEXT);
        INSERT INTO runtime VALUES('active',7);
        INSERT INTO queries VALUES(10,'old','127.0.0.1','legacy.test',1,7,0,'block',0,1,3,'blocked',25,NULL);
        PRAGMA user_version=1;").unwrap();
    let config = serde_json::to_string(&PolicyConfigSet::default()).unwrap();
    database.execute("INSERT INTO revisions(id,actor,state,diff,config) VALUES(7,'old','promoted','legacy',?1)", [&config]).unwrap();
    drop(database);
    let original = std::fs::read(&old).unwrap();
    assert_eq!(maintenance::verify(&old).unwrap().schema, 1);
    let restored = dir.path().join("restored.sqlite");
    assert_eq!(maintenance::snapshot(&old, &restored).unwrap().schema, 1);
    assert_eq!(std::fs::read(&old).unwrap(), original);
    let (store, cancel, done) = initialize(&restored).await;
    let boot = store.bootstrap("{}".into()).await.unwrap();
    assert_eq!(boot.active, 7);
    assert_eq!(boot.config, config);
    let queries = store.queries(10).await.unwrap();
    assert_eq!(queries[0].domain, "legacy.test");
    assert_eq!(queries[0].temporary_exception, None);
    assert_eq!(maintenance::verify(&restored).unwrap().schema, 2);
    cancel.cancel();
    done.await.unwrap();
    // Reopening a migrated store must not attempt the ALTER again.
    let (_, cancel, done) = initialize(&restored).await;
    cancel.cancel();
    done.await.unwrap();
}
async fn initialize(path: &Path) -> (Store, CancellationToken, tokio::sync::oneshot::Receiver<()>) {
    let (_telemetry, events) = Telemetry::channel(4);
    let cancel = CancellationToken::new();
    let (store, done) = Store::start(path.to_path_buf(), 100, events, cancel.clone())
        .await
        .unwrap();
    store
        .bootstrap(serde_json::to_string(&PolicyConfigSet::default()).unwrap())
        .await
        .unwrap();
    (store, cancel, done)
}
#[tokio::test]
async fn wal_snapshot_and_restore_preserve_runtime_revisions_without_clobbering() {
    let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let source = dir.path().join("live.sqlite");
    let (store, cancel, done) = initialize(&source).await;
    let mut config = PolicyConfigSet::default();
    config.policies[0]
        .lists
        .push(rustwalld_dns_filter::ListInput {
            name: "snapshot".into(),
            action: rustwalld_dns_filter::Action::Block,
            rules: "backup.test".into(),
        });
    for (id, mode) in [(2, RevisionMode::Promoted), (3, RevisionMode::Shadow)] {
        store
            .commit(
                id,
                serde_json::to_string(&config).unwrap(),
                mode,
                "test".into(),
                "policies".into(),
            )
            .await
            .unwrap();
    }
    assert!(
        std::fs::metadata(dir.path().join("live.sqlite-wal"))
            .unwrap()
            .len()
            > 0
    );
    let output = dir.path().join("backup.sqlite");
    let report = maintenance::snapshot(&source, &output).unwrap();
    assert_eq!(report.active_generation, 2);
    assert_eq!(report.shadow_generation, Some(3));
    assert_eq!(report.revisions, 3);
    assert!(!dir.path().join("backup.sqlite-wal").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let bytes = std::fs::read(&output).unwrap();
    assert!(maintenance::snapshot(&source, &output).is_err());
    assert_eq!(std::fs::read(&output).unwrap(), bytes);
    let restored = dir.path().join("restored.sqlite");
    maintenance::snapshot(&output, &restored).unwrap();
    let (restored_store, restored_stop, restored_done) = initialize(&restored).await;
    let bootstrap = restored_store.bootstrap("{}".into()).await.unwrap();
    assert_eq!(bootstrap.active, 2);
    assert_eq!(bootstrap.shadow, Some(3));
    assert_eq!(bootstrap.next, 4);
    restored_stop.cancel();
    restored_done.await.unwrap();
    cancel.cancel();
    done.await.unwrap();
}
#[tokio::test]
async fn corrupt_future_or_assertion_failing_sources_never_publish_a_backup() {
    let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let source = dir.path().join("source.sqlite");
    let (_, cancel, done) = initialize(&source).await;
    cancel.cancel();
    done.await.unwrap();
    let database = Connection::open(&source).unwrap();
    database.execute_batch("PRAGMA user_version=99").unwrap();
    let output = dir.path().join("bad.sqlite");
    assert!(maintenance::snapshot(&source, &output).is_err());
    assert!(!output.exists());
    let (_, events) = Telemetry::channel(1);
    assert!(
        Store::start(source.clone(), 100, events, CancellationToken::new())
            .await
            .is_err()
    );
    assert_eq!(
        database
            .query_row::<i64, _, _>("PRAGMA user_version", [], |r| r.get(0))
            .unwrap(),
        99
    );
    database
        .pragma_update(None, "user_version", rustwalld_dns::store::SCHEMA_VERSION)
        .unwrap();
    let mut config = PolicyConfigSet::default();
    config.assertions.push(rustwalld_dns_policy::Assertion {
        client: "127.0.0.1".parse().unwrap(),
        domain: "unblocked.test".into(),
        expected: rustwalld_dns_filter::Action::Block,
    });
    database
        .execute(
            "UPDATE revisions SET config=?1 WHERE id=1",
            [serde_json::to_string(&config).unwrap()],
        )
        .unwrap();
    let before = std::fs::read(&source).unwrap();
    assert!(maintenance::snapshot(&source, &output).is_err());
    assert!(!output.exists());
    assert_eq!(std::fs::read(&source).unwrap(), before);
    drop(database);
    std::fs::write(&source, b"not a sqlite database").unwrap();
    assert!(maintenance::verify(&source).is_err());
    assert!(maintenance::snapshot(&source, &output).is_err());
    assert!(!output.exists());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}
#[tokio::test]
async fn cli_rejects_missing_input_target_sidecars_and_mixed_serving_flags() {
    let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let source = dir.path().join("source.sqlite");
    let (_, cancel, done) = initialize(&source).await;
    cancel.cancel();
    done.await.unwrap();
    let output = dir.path().join("restore.sqlite");
    std::fs::write(dir.path().join("restore.sqlite-wal"), b"keep").unwrap();
    assert!(maintenance::snapshot(&source, &output).is_err());
    assert!(!output.exists());
    let missing = dir.path().join("missing.sqlite");
    assert!(maintenance::snapshot(&missing, &output).is_err());
    assert!(!missing.exists());
    let binary = env!("CARGO_BIN_EXE_rustwalld-dns");
    let result = std::process::Command::new(binary)
        .args(["verify-backup", "--database"])
        .arg(&source)
        .env_remove("RUSTWALLD_API_TOKEN")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&result.stdout).unwrap()["active_generation"],
        1
    );
    let result = std::process::Command::new(binary)
        .args(["--check-config", "verify-backup", "--database"])
        .arg(&source)
        .output()
        .unwrap();
    assert!(!result.status.success());
    // No leaked worker makes this test wait for a global runtime shutdown.
    tokio::time::sleep(Duration::from_millis(1)).await;
}

#[cfg(unix)]
#[tokio::test]
async fn untrusted_destination_directory_and_executable_schema_are_rejected() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let source = dir.path().join("source.sqlite");
    let (_, cancel, done) = initialize(&source).await;
    cancel.cancel();
    done.await.unwrap();
    let writable = dir.path().join("writable");
    std::fs::create_dir(&writable).unwrap();
    std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(maintenance::snapshot(&source, &writable.join("backup.sqlite")).is_err());
    assert_eq!(std::fs::read_dir(&writable).unwrap().count(), 0);
    let database = Connection::open(&source).unwrap();
    database
        .execute_batch(
            "CREATE TRIGGER unexpected AFTER INSERT ON queries BEGIN DELETE FROM runtime; END;",
        )
        .unwrap();
    let output = dir.path().join("backup.sqlite");
    assert!(maintenance::snapshot(&source, &output).is_err());
    assert!(!output.exists());
    database
        .execute_batch("DROP TRIGGER unexpected; UPDATE runtime SET value=999 WHERE key='active';")
        .unwrap();
    assert_eq!(
        maintenance::verify(&source).unwrap_err().to_string(),
        "runtime active pointer refers to missing revision 999"
    );
}
