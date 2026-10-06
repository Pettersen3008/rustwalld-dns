pub mod api;
pub mod config;
pub mod downloads;
pub mod listener;
pub mod maintenance;
pub mod policy_check;
pub mod refreshes;
pub mod store;
use config::Config;
use dns_core::{Engine, Server, telemetry::Telemetry};
use policy::{PolicyConfigSet, PolicySnapshot};
use std::{
    error::Error,
    sync::{Arc, atomic::AtomicU64},
};
use store::{Operation, Store};
use tokio::{net::TcpListener, sync::Semaphore};
use tokio_util::sync::CancellationToken;

pub async fn run(
    config: Config,
    token: String,
    dns_runtime: tokio::runtime::Handle,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    config.validate().map_err(config::invalid)?;
    if token.len() < 16 || token.len() > 1024 {
        return Err("RUSTWALLD_API_TOKEN must contain 16..1024 bytes".into());
    }
    // Compile before creating a database revision; invalid initial data is never stored.
    let initial = config.policy.clone();
    let initial =
        tokio::task::spawn_blocking(move || PolicySnapshot::compile(initial, 1)).await??;
    let (telemetry, receiver) = Telemetry::channel(config.event_queue);
    let db_cancel = CancellationToken::new();
    let (store, done) = Store::start(
        config.database.clone(),
        config.history_rows,
        receiver,
        db_cancel.clone(),
    )
    .await?;
    let result = run_with_store(config, token, dns_runtime, telemetry, store, initial).await;
    db_cancel.cancel();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), done).await;
    result
}
async fn run_with_store(
    config: Config,
    token: String,
    dns_runtime: tokio::runtime::Handle,
    telemetry: Telemetry,
    store: Store,
    initial: PolicySnapshot,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let bootstrap = store
        .call(Operation::Bootstrap {
            config: serde_json::to_string(&initial.config)?,
        })
        .await?;
    drop(initial); // The initial compiled filters are no longer needed after bootstrap.
    let policy: PolicyConfigSet = serde_json::from_str(
        bootstrap["config"]
            .as_str()
            .ok_or("invalid stored configuration")?,
    )?;
    config::validate_policy(&policy, config.dns_listen).map_err(config::invalid)?;
    let generation = bootstrap["active"].as_u64().ok_or("invalid generation")?;
    let snapshot =
        tokio::task::spawn_blocking(move || PolicySnapshot::compile(policy, generation)).await??;
    let engine = Arc::new(Engine::new(
        snapshot,
        config.dns_cache_entries,
        config.decision_cache_entries,
        config.max_inflight,
        telemetry,
    ));
    if let Some(id) = bootstrap["shadow"].as_u64() {
        let revision = store.call(Operation::Revision { id }).await?;
        let candidate: PolicyConfigSet = serde_json::from_value(revision["config"].clone())?;
        config::validate_policy(&candidate, config.dns_listen).map_err(config::invalid)?;
        let shadow =
            tokio::task::spawn_blocking(move || PolicySnapshot::compile(candidate, id)).await??;
        engine.shadow.store(Some(Arc::new(shadow)));
    }
    let settings = config.server();
    let dns_engine = engine.clone();
    let server = dns_runtime
        .spawn(async move { Server::bind(settings, dns_engine).await })
        .await??;
    let listener = TcpListener::bind(config.api_listen).await?;
    let state = Arc::new(api::AppState {
        engine,
        store,
        listen: config.dns_listen,
        next_generation: AtomicU64::new(
            bootstrap["next"]
                .as_u64()
                .ok_or("invalid next generation")?,
        ),
        mutation: Arc::new(Semaphore::new(1)),
        api_slots: Arc::new(Semaphore::new(32)),
        downloads: Arc::new(Semaphore::new(1)),
        refreshes: Arc::new(refreshes::Refresher::default()),
        token,
    });
    let stop = CancellationToken::new();
    let refresh_task = tokio::spawn(refreshes::run(state.clone(), stop.clone()));
    let mut dns_task = dns_runtime.spawn(server.run(stop.clone()));
    let api_stop = stop.clone();
    let mut api_task = tokio::spawn(async move {
        axum::serve(
            listener::ManagementListener::new(listener, 128, std::time::Duration::from_secs(30)),
            api::router_with_ui(state, config.web_root.clone()),
        )
        .with_graceful_shutdown(api_stop.cancelled_owned())
        .await
    });
    tracing::info!(dns=%config.dns_listen,api=%config.api_listen,"DNS engine ready");
    let result = tokio::select! {
        signal=shutdown_signal()=>signal,
        result=&mut dns_task=>{stop.cancel();if tokio::time::timeout(std::time::Duration::from_secs(5),&mut api_task).await.is_err() {api_task.abort();}let _=refresh_task.await;return result?.map_err(Into::into);},
        result=&mut api_task=>{stop.cancel();let _=dns_task.await;let _=refresh_task.await;return result?.map_err(Into::into);},
    };
    stop.cancel();
    let _ = refresh_task.await;
    dns_task.await??;
    if tokio::time::timeout(std::time::Duration::from_secs(5), &mut api_task)
        .await
        .is_err()
    {
        api_task.abort();
    }
    result?;
    Ok(())
}
async fn shutdown_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {result=tokio::signal::ctrl_c()=>result,_=terminate.recv()=>Ok(())}
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}
