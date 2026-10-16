//! Standalone HTTP/CLI adapters. Embed rustwalld-dns-core or rustwalld-dns-runtime directly.
pub mod api;
pub mod auth;
pub mod config;
pub mod integrations;
pub mod listener;
pub mod migration;
pub mod policy_check;
pub mod secure_dns;
pub mod tls;
use config::Config;
use rustwalld_dns_runtime::Runtime;
pub use rustwalld_dns_runtime::{downloads, maintenance, refreshes, store};
use std::{error::Error, sync::Arc, time::Duration};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// Run the standalone HTTP adapter and durable DNS runtime on caller-owned executors.
/// The caller owns process signals, global tracing and cancellation.
pub async fn run(
    config: Config,
    token: String,
    dns_runtime: tokio::runtime::Handle,
    stop: CancellationToken,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut token = zeroize::Zeroizing::new(token);
    let _cancel = CancelOnDrop(stop.clone());
    config.validate_settings().map_err(config::invalid)?;
    if token.len() < 16 || token.len() > 1024 {
        return Err("RUSTWALLD_API_TOKEN must contain 16..1024 bytes".into());
    }
    let setup = api::Setup::from_config(&config);
    let integrations = config.integrations.clone();
    let integrations = tokio::task::spawn_blocking(move || {
        integrations
            .into_iter()
            .map(integrations::Adapter::load)
            .map(|adapter| adapter.map(Arc::new))
            .collect::<Result<Vec<_>, _>>()
    })
    .await?
    .map_err(config::invalid)?;
    let api_listen = config.api_listen;
    let dns_listen = config.dns_listen;
    let web_root = config.web_root.clone();
    let api_hosts = config
        .api_tls
        .as_ref()
        .map_or_else(Vec::new, |cert| cert.hostnames.clone());
    let requests = config.max_inflight;
    let dot_config = config.dot.clone();
    let doh_config = config.doh.clone();
    let certificates = (
        config.api_tls.clone(),
        config.dot.clone(),
        config.doh.clone(),
    );
    let auth_file = config.auth_file.clone();
    let identity = tokio::task::spawn_blocking(move || {
        auth_file
            .map(auth::Identity::load)
            .transpose()
            .map(|identity| identity.map(Arc::new))
    })
    .await?
    .map_err(config::invalid)?;
    let (api_tls, dot_tls, doh_tls) = tokio::task::spawn_blocking(move || {
        Ok::<_, String>((
            certificates.0.map(|cert| cert.load(true)).transpose()?,
            certificates
                .1
                .map(|listener| listener.certificate.load(false))
                .transpose()?,
            certificates
                .2
                .map(|listener| listener.certificate.load(true))
                .transpose()?,
        ))
    })
    .await?
    .map_err(config::invalid)?;
    let secure_executor = dns_runtime.clone();
    #[cfg(not(feature = "parallel-compilation"))]
    let runtime = Runtime::start(config.into_runtime(), dns_runtime).await?;
    #[cfg(feature = "parallel-compilation")]
    let runtime = Runtime::start_with_compiler(
        config.into_runtime(),
        dns_runtime,
        Arc::new(rustwalld_dns_filter::ParallelCompiler::new(2)?),
    )
    .await?;
    let state = Arc::new(
        api::AppState::new(runtime.control().clone(), &token)
            .with_hostnames(api_hosts)
            .with_identity(identity)
            .with_shutdown(stop.clone())
            .with_setup(setup)
            .with_integrations(integrations),
    );
    use zeroize::Zeroize;
    token.zeroize();
    let listener = TcpListener::bind(api_listen).await?;
    let mut services = tokio::task::JoinSet::new();
    let secure_state = secure_dns::SecureDns::new(
        runtime.control().engine().clone(),
        secure_executor,
        requests,
        vec![],
    );
    let engine = runtime.control().engine().clone();
    let admission: tls::Admission = Arc::new(move |peer| engine.active().permits(peer));
    if let (Some(config), Some(acceptor)) = (dot_config, dot_tls) {
        let listener = tls::SecureListener::new(
            TcpListener::bind(config.listen).await?,
            acceptor,
            config.max_connections,
        )
        .with_admission(admission.clone());
        let state = secure_state
            .clone()
            .with_hostnames(config.certificate.hostnames);
        services.spawn(secure_dns::run_dot(listener, state, stop.clone()));
    }
    if let (Some(config), Some(acceptor)) = (doh_config, doh_tls) {
        let listener = tls::SecureListener::new(
            TcpListener::bind(config.listen).await?,
            acceptor,
            config.max_connections,
        )
        .with_admission(admission);
        let state = secure_state
            .clone()
            .with_hostnames(config.certificate.hostnames);
        let cancel = stop.clone();
        services.spawn(async move {
            axum::serve(
                listener,
                secure_dns::doh_router(state)
                    .into_make_service_with_connect_info::<listener::Activity>(),
            )
            .with_graceful_shutdown(cancel.cancelled_owned())
            .await
        });
    }
    let api_stop = stop.clone();
    let mut api_task = tokio::spawn(async move {
        let router = api::router_with_ui(state, web_root)
            .into_make_service_with_connect_info::<listener::Activity>();
        if let Some(acceptor) = api_tls {
            axum::serve(tls::SecureListener::new(listener, acceptor, 128), router)
                .with_graceful_shutdown(api_stop.cancelled_owned())
                .await
        } else {
            axum::serve(
                listener::ManagementListener::new(listener, 128, Duration::from_secs(30)),
                router,
            )
            .with_graceful_shutdown(api_stop.cancelled_owned())
            .await
        }
    });
    tracing::info!(dns=%dns_listen,api=%api_listen,"DNS engine ready");
    let mut dns_task = tokio::spawn(runtime.run(stop.clone()));
    let result = tokio::select! {
        result=&mut dns_task=>{stop.cancel();result?},
        result=&mut api_task=>{stop.cancel();dns_task.await??;return result?.map_err(Into::into);},
        result=services.join_next(),if !services.is_empty()=>{stop.cancel();dns_task.await??;if let Some(result)=result {result??;}return Err("encrypted listener stopped unexpectedly".into());},
    };
    stop.cancel();
    if tokio::time::timeout(Duration::from_secs(5), async {
        while services.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        services.abort_all();
    }
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
