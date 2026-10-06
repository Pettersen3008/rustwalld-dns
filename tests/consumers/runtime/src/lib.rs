//! Durable integration without importing the standalone app or HTTP server.
#[cfg(test)]
mod tests {
    use rustwalld_dns_core::{
        Action, Engine, EngineConfig, ListInput, PolicySnapshot, PublicationTarget, Telemetry,
    };
    use rustwalld_dns_runtime::{
        Candidate, ControlError, ControlService, Runtime, RuntimeConfig, maintenance,
    };
    use std::time::Duration;
    use tokio::time::timeout;
    use tokio_util::sync::CancellationToken;
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn caller_cancellation_cannot_split_commit_from_publication_and_shutdown_drains() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = RuntimeConfig {
            database: directory.path().join("dns.sqlite"),
            dns_listen: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        config.policy.upstreams[0].addresses = vec!["127.0.0.1:9".parse().unwrap()];
        let runtime = Runtime::start(config.clone(), tokio::runtime::Handle::current())
            .await
            .unwrap();
        let control = runtime.control().clone();
        assert_ne!(runtime.local_addr().unwrap().port(), 0);
        // A durable service must reject unrelated publication capabilities and reused IDs.
        let policy = config.policy.clone();
        let snapshot = tokio::task::spawn_blocking(move || PolicySnapshot::compile(policy, 1))
            .await
            .unwrap()
            .unwrap();
        let (telemetry, _) = Telemetry::channel(1);
        let (foreign_engine, foreign_controller) =
            Engine::controlled(snapshot, EngineConfig::default(), telemetry);
        assert!(matches!(
            ControlService::new(
                control.engine.clone(),
                foreign_controller.clone(),
                control.store.clone(),
                control.listen,
                2
            ),
            Err(ControlError::Invalid(_))
        ));
        assert!(matches!(
            ControlService::new(
                std::sync::Arc::new(foreign_engine),
                foreign_controller,
                control.store.clone(),
                control.listen,
                1
            ),
            Err(ControlError::Invalid(_))
        ));

        let stop = CancellationToken::new();
        let serving = tokio::spawn(runtime.run(stop.clone()));
        let database = rusqlite::Connection::open(&config.database).unwrap();
        database.execute_batch("BEGIN IMMEDIATE").unwrap();
        let mut candidate = control.engine.snapshot().config().clone();
        candidate.policies[0].lists.push(ListInput {
            name: "test".into(),
            action: Action::Block,
            rules: "ads.test".into(),
        });
        let expected = control.version();
        let publisher = control.clone();
        let request = tokio::spawn(async move {
            publisher
                .stage(
                    Candidate::Config(candidate),
                    Some(expected),
                    PublicationTarget::Active,
                    "consumer",
                )
                .await
        });
        timeout(Duration::from_secs(2), async {
            while control.mutation.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        stop.cancel();
        database.execute_batch("ROLLBACK").unwrap();
        drop(database);
        timeout(Duration::from_secs(8), serving)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(control.engine.active().generation(), 2);
        assert!(matches!(
            control.clear_shadow(None).await,
            Err(ControlError::Unavailable(_))
        ));
        let backup = directory.path().join("backup.sqlite");
        let report = maintenance::snapshot(&config.database, &backup).unwrap();
        assert_eq!(report.active_generation, 2);
        let restarted = Runtime::start(config, tokio::runtime::Handle::current())
            .await
            .unwrap();
        assert_eq!(restarted.control().engine.active().generation(), 2);
        let stop = CancellationToken::new();
        stop.cancel();
        restarted.run(stop).await.unwrap();
    }
}
