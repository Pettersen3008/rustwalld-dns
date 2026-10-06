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
        cancellation_and_shutdown(0).await;
    }
    #[cfg(feature = "parallel")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn owned_parallel_compiler_preserves_durable_cancellation_restore_and_drain() {
        cancellation_and_shutdown(2).await;
    }
    async fn start(config: RuntimeConfig, workers: usize) -> Runtime {
        #[cfg(feature = "parallel")]
        if workers != 0 {
            return Runtime::start_with_compiler(
                config,
                tokio::runtime::Handle::current(),
                std::sync::Arc::new(rustwalld_dns_filter::ParallelCompiler::new(workers).unwrap()),
            )
            .await
            .unwrap();
        }
        assert_eq!(workers, 0);
        Runtime::start(config, tokio::runtime::Handle::current())
            .await
            .unwrap()
    }
    async fn cancellation_and_shutdown(workers: usize) {
        let directory = tempfile::tempdir().unwrap();
        let mut config = RuntimeConfig {
            database: directory.path().join("dns.sqlite"),
            dns_listen: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        config.policy.upstreams[0].addresses = vec!["127.0.0.1:9".parse().unwrap()];
        if workers != 0 {
            config.policy.policies[0].lists.push(ListInput {
                name: "large".into(),
                action: Action::Block,
                rules: (0..40000).map(|i| format!("=rule{i}.test\n")).collect(),
            });
        }
        let runtime = start(config.clone(), workers).await;
        let control = runtime.control().clone();
        assert_ne!(runtime.local_addr().unwrap().port(), 0);
        if workers != 0 {
            let mut bad = config.policy.clone();
            bad.assertions.push(rustwalld_dns_core::Assertion {
                client: "127.0.0.1".parse().unwrap(),
                domain: "allowed.test".into(),
                expected: Action::Block,
            });
            let report = control.test(bad).await.unwrap();
            assert!(!report.valid);
            assert_eq!(report.failed, 1);
            assert_eq!(control.engine.snapshot().generation(), 1);
        }
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
        let restarted = start(config, workers).await;
        assert_eq!(restarted.control().engine.active().generation(), 2);
        let stop = CancellationToken::new();
        stop.cancel();
        restarted.run(stop).await.unwrap();
    }
    #[cfg(feature = "parallel")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn parallel_failed_assertions_shadow_restore_promotion_and_rollback_keep_generation_contracts()
     {
        let directory = tempfile::tempdir().unwrap();
        let compiler = std::sync::Arc::new(rustwalld_dns_filter::ParallelCompiler::new(2).unwrap());
        let mut config = RuntimeConfig {
            database: directory.path().join("dns.sqlite"),
            dns_listen: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        config.policy.upstreams[0].addresses = vec!["127.0.0.1:9".parse().unwrap()];
        config.policy.policies[0].lists.push(ListInput {
            name: "base".into(),
            action: Action::Block,
            rules: (0..40000).map(|i| format!("=rule{i}.test\n")).collect(),
        });
        let runtime = Runtime::start_with_compiler(
            config.clone(),
            tokio::runtime::Handle::current(),
            compiler.clone(),
        )
        .await
        .unwrap();
        let control = runtime.control().clone();
        let mut failed = config.policy.clone();
        failed.assertions.push(rustwalld_dns_core::Assertion {
            client: "127.0.0.1".parse().unwrap(),
            domain: "allowed.test".into(),
            expected: Action::Block,
        });
        assert!(matches!(
            control
                .stage(
                    Candidate::Config(failed),
                    Some(control.version()),
                    PublicationTarget::Active,
                    "consumer"
                )
                .await,
            Err(ControlError::Invalid(_))
        ));
        assert_eq!(control.engine.snapshot().generation(), 1);
        assert!(control.engine.shadow_snapshot().is_none());
        assert_eq!(control.next_generation(), 3);
        let mut shadow = config.policy.clone();
        shadow.policies[0].lists.push(ListInput {
            name: "shadow".into(),
            action: Action::Block,
            rules: "shadow.test".into(),
        });
        control
            .stage(
                Candidate::Config(shadow),
                Some(control.version()),
                PublicationTarget::Shadow,
                "consumer",
            )
            .await
            .unwrap();
        assert_eq!(control.engine.shadow_snapshot().unwrap().generation(), 3);
        let stop = CancellationToken::new();
        stop.cancel();
        runtime.run(stop).await.unwrap();
        drop(control);
        let restarted =
            Runtime::start_with_compiler(config, tokio::runtime::Handle::current(), compiler)
                .await
                .unwrap();
        let control = restarted.control();
        assert_eq!(control.version().active, 1);
        assert_eq!(control.version().shadow, Some(3));
        let client = "127.0.0.1".parse().unwrap();
        assert_eq!(
            control
                .engine
                .snapshot()
                .explain(client, "shadow.test")
                .unwrap()
                .decision
                .action,
            Action::Allow
        );
        assert_eq!(
            control
                .engine
                .shadow_snapshot()
                .unwrap()
                .explain(client, "shadow.test")
                .unwrap()
                .decision
                .action,
            Action::Block
        );
        control
            .stage(
                Candidate::Shadow,
                Some(control.version()),
                PublicationTarget::Active,
                "consumer",
            )
            .await
            .unwrap();
        assert_eq!(control.version().active, 4);
        assert_eq!(control.version().shadow, None);
        assert_eq!(
            control
                .engine
                .snapshot()
                .explain(client, "shadow.test")
                .unwrap()
                .decision
                .action,
            Action::Block
        );
        let historical = control.revision(1).await.unwrap();
        let config = serde_json::from_value(historical.config).unwrap();
        control
            .stage(
                Candidate::Config(config),
                Some(control.version()),
                PublicationTarget::Active,
                "consumer",
            )
            .await
            .unwrap();
        assert_eq!(control.version().active, 5);
        assert_eq!(
            control
                .engine
                .snapshot()
                .explain(client, "shadow.test")
                .unwrap()
                .decision
                .action,
            Action::Allow
        );
        assert_eq!(
            control
                .engine
                .snapshot()
                .explain(client, "rule39999.test")
                .unwrap()
                .rule
                .unwrap()
                .sources[0]
                .line,
            40000
        );
        let stop = CancellationToken::new();
        stop.cancel();
        restarted.run(stop).await.unwrap();
    }
}
