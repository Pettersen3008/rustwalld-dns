//! Explicit application lifecycle; the embedding host owns signals and executors.
use crate::{ControlService, config, store::Store};
use rustwalld_dns_core::{Engine, EngineConfig, Server, ServerConfig, telemetry::Telemetry};
use rustwalld_dns_policy::PolicyConfigSet;
use std::{error::Error, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::{runtime::Handle, sync::oneshot};
use tokio_util::sync::CancellationToken;

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
/// Resolved configuration values. File loading and HTTP settings belong to hosts.
#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub dns_listen: SocketAddr,
    pub database: PathBuf,
    pub dns_cache_entries: usize,
    pub decision_cache_entries: usize,
    pub max_inflight: usize,
    pub max_udp_queries: usize,
    pub max_tcp_connections: usize,
    pub event_queue: usize,
    pub history_rows: usize,
    pub policy: PolicyConfigSet,
}
impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            dns_listen: SocketAddr::from(([127, 0, 0, 1], 5353)),
            database: PathBuf::from("rustwalld.sqlite"),
            dns_cache_entries: 4096,
            decision_cache_entries: 16384,
            max_inflight: 256,
            max_udp_queries: 512,
            max_tcp_connections: 128,
            event_queue: 4096,
            history_rows: 100000,
            policy: PolicyConfigSet::default(),
        }
    }
}
impl RuntimeConfig {
    pub fn validate(&self) -> std::result::Result<(), String> {
        self.validate_limits()?;
        config::validate_policy(&self.policy, self.dns_listen)
    }
    /// Validate numeric bounds independently of policy compilation.
    pub fn validate_limits(&self) -> std::result::Result<(), String> {
        for (name, value, max) in [
            ("DNS cache", self.dns_cache_entries, 1000000),
            ("decision cache", self.decision_cache_entries, 1000000),
            ("inflight", self.max_inflight, 4096),
            ("UDP admission", self.max_udp_queries, 16384),
            ("TCP admission", self.max_tcp_connections, 4096),
            ("event queue", self.event_queue, 65536),
            ("history rows", self.history_rows, 1000000),
        ] {
            if value == 0 || value > max {
                return Err(format!("{name} must be between 1 and {max}"));
            }
        }
        Ok(())
    }
}
struct DatabaseWorker {
    cancel: CancellationToken,
    done: Option<oneshot::Receiver<()>>,
}
impl Drop for DatabaseWorker {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Bound DNS server and durable control service. `start` binds without serving;
/// `run` supervises tasks until cancellation and drains admitted mutations.
/// Dropping the runtime cancels background work; await `run` for graceful drain.
pub struct Runtime {
    control: Arc<ControlService>,
    server: Option<Server>,
    dns_runtime: Handle,
    stop: CancellationToken,
    database: DatabaseWorker,
}
impl Runtime {
    /// Compile and restore durable state before binding DNS on the supplied executor.
    pub async fn start(config: RuntimeConfig, dns_runtime: Handle) -> Result<Self> {
        Self::start_using(config, dns_runtime, crate::compiler::Compiler::Sequential).await
    }
    /// Use one explicit, owned pool for startup, restored revisions and admitted edits.
    /// `run` drains admitted compilation/publication during graceful shutdown.
    #[cfg(feature = "parallel-compilation")]
    pub async fn start_with_compiler(
        config: RuntimeConfig,
        dns_runtime: Handle,
        compiler: Arc<rustwalld_dns_filter::ParallelCompiler>,
    ) -> Result<Self> {
        Self::start_using(
            config,
            dns_runtime,
            crate::compiler::Compiler::Parallel(compiler),
        )
        .await
    }
    async fn start_using(
        config: RuntimeConfig,
        dns_runtime: Handle,
        compiler: crate::compiler::Compiler,
    ) -> Result<Self> {
        config.validate().map_err(config::invalid)?;
        let initial_config = config.policy;
        let initial_compiler = compiler.clone();
        let initial =
            tokio::task::spawn_blocking(move || initial_compiler.compile(initial_config, 1))
                .await??;
        let (telemetry, events) = Telemetry::channel(config.event_queue);
        let db_cancel = CancellationToken::new();
        let (store, done) = Store::start(
            config.database.clone(),
            config.history_rows,
            events,
            db_cancel.clone(),
        )
        .await?;
        let database = DatabaseWorker {
            cancel: db_cancel,
            done: Some(done),
        };
        let bootstrap = store
            .bootstrap(serde_json::to_string(initial.config())?)
            .await?;
        drop(initial);
        let policy: PolicyConfigSet = serde_json::from_str(&bootstrap.config)?;
        config::validate_policy(&policy, config.dns_listen).map_err(config::invalid)?;
        let generation = bootstrap.active;
        let next = bootstrap.next;
        let active_compiler = compiler.clone();
        let snapshot =
            tokio::task::spawn_blocking(move || active_compiler.compile(policy, generation))
                .await??;
        let shadow = if let Some(id) = bootstrap.shadow {
            let revision = store
                .revision(id)
                .await?
                .ok_or("invalid stored shadow revision")?;
            let candidate: PolicyConfigSet = serde_json::from_value(revision.config)?;
            config::validate_policy(&candidate, config.dns_listen).map_err(config::invalid)?;
            let shadow_compiler = compiler.clone();
            Some(
                tokio::task::spawn_blocking(move || shadow_compiler.compile(candidate, id))
                    .await??,
            )
        } else {
            None
        };
        let (engine, controller) = Engine::restore(
            snapshot,
            shadow,
            next.checked_sub(1).ok_or("invalid next generation")?,
            EngineConfig {
                cache_entries: config.dns_cache_entries,
                decision_entries: config.decision_cache_entries,
                max_inflight: config.max_inflight,
            },
            telemetry,
        )?;
        let engine = Arc::new(engine);
        let settings = ServerConfig {
            listen: config.dns_listen,
            max_udp_queries: config.max_udp_queries,
            max_tcp_connections: config.max_tcp_connections,
            ..Default::default()
        };
        let dns_engine = engine.clone();
        let server = dns_runtime
            .spawn(async move { Server::bind(settings, dns_engine).await })
            .await??;
        let listen = if config.dns_listen.port() == 0 {
            server.local_addr()?
        } else {
            config.dns_listen
        };
        if config.dns_listen.port() == 0 {
            // The selected port is known only after bind. Recheck loop prevention.
            config::validate_policy(engine.active().config(), listen).map_err(config::invalid)?;
            if let Some(shadow) = engine.shadow_snapshot() {
                config::validate_policy(shadow.config(), listen).map_err(config::invalid)?;
            }
        }
        let control = Arc::new(
            ControlService::new(engine, controller, store, listen, next)?.with_compiler(compiler),
        );
        Ok(Self {
            control,
            server: Some(server),
            dns_runtime,
            stop: CancellationToken::new(),
            database,
        })
    }
    /// Shared management operations and read-only engine access.
    pub fn control(&self) -> &Arc<ControlService> {
        &self.control
    }
    /// Actual bound address, including an OS-selected ephemeral port.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self
            .server
            .as_ref()
            .ok_or("runtime already serving")?
            .local_addr()?)
    }
    /// Serve until cancellation or DNS failure, then retire networking, drain
    /// compilation/publication and stop history persistence in that order.
    pub async fn run(mut self, cancel: CancellationToken) -> Result<()> {
        let server = self.server.take().ok_or("runtime already serving")?;
        let refresh = tokio::spawn(crate::refreshes::run(
            self.control.clone(),
            self.stop.clone(),
        ));
        let mut dns = self.dns_runtime.spawn(server.run(self.stop.clone()));
        let result = tokio::select! { result=&mut dns=>result, _=cancel.cancelled()=>{self.stop.cancel();dns.await} };
        self.stop.cancel();
        self.control.stop_admission();
        let _ = refresh.await;
        // A semaphore is admission, not a mutex held across network I/O.
        // Once it is acquired every admitted durable mutation has completed.
        let _ = self.control.mutation.acquire().await;
        self.database.cancel.cancel();
        if let Some(done) = self.database.done.take() {
            let _ = tokio::time::timeout(Duration::from_secs(3), done).await;
        }
        result??;
        Ok(())
    }
}
impl Drop for Runtime {
    fn drop(&mut self) {
        self.stop.cancel();
        self.control.stop_admission();
        self.control.engine.resolver().shutdown();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use rustwalld_dns_policy::TemporaryException;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn config(directory: &std::path::Path) -> RuntimeConfig {
        let mut config = RuntimeConfig {
            database: directory.join("dns.sqlite"),
            dns_listen: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        config.policy.upstreams[0].addresses = vec!["127.0.0.1:9".parse().unwrap()];
        config
    }
    async fn stop(runtime: Runtime) {
        let stop = CancellationToken::new();
        stop.cancel();
        runtime.run(stop).await.unwrap();
    }
    fn store_active(config: &RuntimeConfig, id: i64, policy: &PolicyConfigSet) {
        let database = rusqlite::Connection::open(&config.database).unwrap();
        database
            .execute(
                "INSERT INTO revisions(id,actor,state,diff,config) VALUES(?1,'api','promoted','policies',?2)",
                rusqlite::params![id, serde_json::to_string(policy).unwrap()],
            )
            .unwrap();
        database
            .execute("UPDATE runtime SET value=?1 WHERE key='active'", [id])
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stored_exception_restored_on_a_lagging_clock_still_starts_dns() {
        let directory = tempfile::tempdir().unwrap();
        let config = config(directory.path());
        stop(
            Runtime::start(config.clone(), Handle::current())
                .await
                .unwrap(),
        )
        .await;
        // Accepted with a correct clock; this boot's clock lags by 30 days.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut stored = config.policy.clone();
        stored.policies[0].temporary_exceptions = vec![TemporaryException {
            name: "repair".into(),
            domain: "ads.test".into(),
            expires_at: now + 30 * 86400,
        }];
        store_active(&config, 2, &stored);
        let runtime = Runtime::start(config, Handle::current()).await.unwrap();
        let active = runtime.control().engine.snapshot();
        assert_eq!(active.generation(), 2);
        let allowed = active.policies()[0]
            .temporary_allow("ads.test", std::time::Instant::now())
            .unwrap();
        assert!(
            allowed.remaining_ttl(std::time::Instant::now()).unwrap()
                <= u32::try_from(rustwalld_dns_policy::MAX_EXCEPTION_REMAINING.as_secs()).unwrap()
        );
        stop(runtime).await;
    }
}
