//! Standalone HTTP/CLI adapters. Embed rustwalld-dns-core or rustwalld-dns-runtime directly.
pub mod api;
pub mod config;
pub mod listener;
pub mod policy_check;
use config::Config;
use rustwalld_dns_runtime::Runtime;
pub use rustwalld_dns_runtime::{downloads, maintenance, refreshes, store};
use std::{error::Error, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::Semaphore};
use tokio_util::sync::CancellationToken;

/// Run the standalone HTTP adapter and durable DNS runtime on caller-owned executors.
/// The caller owns process signals, global tracing and cancellation.
pub async fn run(
    config: Config,
    token: String,
    dns_runtime: tokio::runtime::Handle,
    stop: CancellationToken,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let _cancel = CancelOnDrop(stop.clone());
    config.validate().map_err(config::invalid)?;
    if token.len() < 16 || token.len() > 1024 {
        return Err("RUSTWALLD_API_TOKEN must contain 16..1024 bytes".into());
    }
    let api_listen = config.api_listen;
    let dns_listen = config.dns_listen;
    let web_root = config.web_root.clone();
    #[cfg(not(feature = "parallel-compilation"))]
    let runtime = Runtime::start(config.into_runtime(), dns_runtime).await?;
    #[cfg(feature = "parallel-compilation")]
    let runtime = Runtime::start_with_compiler(
        config.into_runtime(),
        dns_runtime,
        Arc::new(rustwalld_dns_filter::ParallelCompiler::new(2)?),
    )
    .await?;
    let state = Arc::new(api::AppState {
        control: runtime.control().clone(),
        api_slots: Arc::new(Semaphore::new(32)),
        token,
    });
    let listener = TcpListener::bind(api_listen).await?;
    let api_stop = stop.clone();
    let mut api_task = tokio::spawn(async move {
        axum::serve(
            listener::ManagementListener::new(listener, 128, Duration::from_secs(30)),
            api::router_with_ui(state, web_root),
        )
        .with_graceful_shutdown(api_stop.cancelled_owned())
        .await
    });
    tracing::info!(dns=%dns_listen,api=%api_listen,"DNS engine ready");
    let mut dns_task = tokio::spawn(runtime.run(stop.clone()));
    let result = tokio::select! {
        result=&mut dns_task=>{stop.cancel();result?},
        result=&mut api_task=>{stop.cancel();dns_task.await??;return result?.map_err(Into::into);},
    };
    stop.cancel();
    if tokio::time::timeout(Duration::from_secs(5), &mut api_task)
        .await
        .is_err()
    {
        api_task.abort();
    }
    result
}

struct CancelOnDrop(CancellationToken);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
