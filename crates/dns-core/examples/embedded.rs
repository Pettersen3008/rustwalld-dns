//! Bind a local DNS engine for three seconds; no upstream traffic unless queried.
//! Optional first argument is an explicitly chosen upstream socket address.
use rustwalld_dns_core::{
    Action, Engine, EngineConfig, ListInput, PolicyConfigSet, PolicySnapshot, Server, ServerConfig,
    Telemetry,
};
use std::{error::Error, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let upstream = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:9".into())
        .parse()?;
    let dns = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()?;
    let control = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()?;
    control.block_on(async {
        let mut policy = PolicyConfigSet::default();
        policy.upstreams[0].addresses = vec![upstream];
        policy.policies[0].lists.push(ListInput {
            name: "example".into(),
            action: Action::Block,
            rules: "ads.test".into(),
        });
        let snapshot =
            tokio::task::spawn_blocking(move || PolicySnapshot::compile(policy, 1)).await??;
        let (telemetry, mut events) = Telemetry::channel(128);
        let (engine, _controller) =
            Engine::controlled(snapshot, EngineConfig::default(), telemetry);
        let stop = CancellationToken::new();
        let server = dns
            .spawn(async move {
                Server::bind(
                    ServerConfig {
                        listen: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
                        ..Default::default()
                    },
                    Arc::new(engine),
                )
                .await
            })
            .await??;
        println!("DNS bound at {}; ads.test is blocked", server.local_addr()?);
        let serving = dns.spawn(server.run(stop.clone()));
        // The host can replace this deadline with its own lifecycle cancellation.
        let deadline = tokio::time::sleep(Duration::from_secs(3));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => break,
                event = events.recv() => if let Some(event) = event {
                    println!("generation {}: {}", event.generation, event.domain);
                } else { break; }
            }
        }
        stop.cancel();
        serving.await??;
        Ok(())
    })
}
