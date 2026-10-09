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
    /// DNS listen address (UDP and TCP); port 0 selects one.
    pub dns_listen: SocketAddr,
    /// SQLite database path; created 0600 when absent.
    pub database: PathBuf,
    /// Response-cache entries.
    pub dns_cache_entries: usize,
    /// Decision-cache entries.
    pub decision_cache_entries: usize,
    /// Distinct upstream lookups in flight.
    pub max_inflight: usize,
    /// UDP queries in local processing at once.
    pub max_udp_queries: usize,
    /// UDP cache misses that may wait on upstreams at once; see
    /// [`ServerConfig::max_udp_upstream_waits`].
    pub max_udp_upstream_waits: usize,
    /// Concurrent DNS TCP connections.
    pub max_tcp_connections: usize,
    /// Query events buffered for history persistence.
    pub event_queue: usize,
    /// Query history rows retained.
    pub history_rows: usize,
    /// Policy that seeds a new database (ignored once one exists).
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
            max_udp_upstream_waits: 1024,
            max_tcp_connections: 128,
            event_queue: 4096,
            history_rows: 100000,
            policy: PolicyConfigSet::default(),
        }
    }
}
impl RuntimeConfig {
    /// Validate limits and the seed policy.
    ///
    /// # Errors
    ///
    /// A description of the first violated bound or rule.
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
            ("UDP upstream waits", self.max_udp_upstream_waits, 65536),
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
        let mut config = config;
        config.validate_limits().map_err(config::invalid)?;
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
        let listen = config.dns_listen;
        // The configuration file seeds only a new database. A restored store
        // never compiles it, so a broken file cannot block a valid revision.
        let (snapshot, next, stored_shadow) = match store.load().await? {
            Some(bootstrap) => {
                let compiler = compiler.clone();
                let (generation, text) = (bootstrap.active, bootstrap.config);
                let snapshot = tokio::task::spawn_blocking(move || {
                    restore(&compiler, generation, &text, listen)
                })
                .await??;
                (snapshot, bootstrap.next, bootstrap.shadow)
            }
            None => {
                config::validate_policy(&config.policy, listen).map_err(config::invalid)?;
                let policy = std::mem::take(&mut config.policy);
                let compiler = compiler.clone();
                let (initial, content) = tokio::task::spawn_blocking(move || {
                    let initial = compiler.compile(policy, 1)?;
                    let content = serde_json::to_string(initial.config())?;
                    Ok::<_, Box<dyn Error + Send + Sync>>((initial, content))
                })
                .await??;
                let bootstrap = store.bootstrap(content).await?;
                if bootstrap.active != initial.generation() || bootstrap.shadow.is_some() {
                    return Err("database was bootstrapped concurrently".into());
                }
                // The compiled file is exactly revision 1; no second compilation.
                (initial, bootstrap.next, None)
            }
        };
        let shadow = match stored_shadow {
            Some(id) => restore_shadow(&store, &compiler, id, listen).await?,
            None => None,
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
            max_udp_upstream_waits: config.max_udp_upstream_waits,
            max_tcp_connections: config.max_tcp_connections,
            ..Default::default()
        };
        let dns_engine = engine.clone();
        let server = dns_runtime
            .spawn(async move { Server::bind(settings, dns_engine).await })
            .await??;
        let listen = if listen.port() == 0 {
            server.local_addr()?
        } else {
            listen
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
        self.control.drain_mutations().await;
        self.database.cancel.cancel();
        if let Some(done) = self.database.done.take() {
            let _ = tokio::time::timeout(Duration::from_secs(3), done).await;
        }
        result??;
        Ok(())
    }
}
/// Parse, validate and compile a stored revision on a blocking thread.
fn restore(
    compiler: &crate::compiler::Compiler,
    generation: u64,
    text: &str,
    listen: SocketAddr,
) -> Result<rustwalld_dns_policy::PolicySnapshot> {
    let policy: PolicyConfigSet = serde_json::from_str(text)?;
    config::validate_policy(&policy, listen).map_err(config::invalid)?;
    Ok(compiler.compile(policy, generation)?)
}
/// A shadow is optional review state. If it cannot be restored, durably clear
/// the pointer and serve the active revision instead of refusing to start DNS.
/// Storage failures other than unreadable content remain fatal.
async fn restore_shadow(
    store: &Store,
    compiler: &crate::compiler::Compiler,
    id: u64,
    listen: SocketAddr,
) -> Result<Option<rustwalld_dns_policy::PolicySnapshot>> {
    let compiled: Result<rustwalld_dns_policy::PolicySnapshot> = match store.revision(id).await {
        Ok(Some(revision)) => {
            let compiler = compiler.clone();
            tokio::task::spawn_blocking(move || {
                let policy: PolicyConfigSet = serde_json::from_value(revision.config)?;
                config::validate_policy(&policy, listen).map_err(config::invalid)?;
                Ok(compiler.compile(policy, id)?)
            })
            .await?
        }
        Ok(None) => Err("revision is missing".into()),
        Err(error @ crate::store::StoreError::CorruptRevision { .. }) => Err(error.into()),
        Err(error) => return Err(error.into()),
    };
    match compiled {
        Ok(snapshot) => Ok(Some(snapshot)),
        Err(error) => {
            tracing::warn!(
                generation = id,
                %error,
                "stored shadow revision cannot be restored; clearing it and serving the active revision"
            );
            store.clear_shadow().await?;
            Ok(None)
        }
    }
}
impl Drop for Runtime {
    fn drop(&mut self) {
        self.stop.cancel();
        self.control.stop_admission();
        self.control.engine().resolver().shutdown();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use rusqlite::OptionalExtension;
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
        let active = runtime.control().engine().snapshot();
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

    fn shadow_pointer(config: &RuntimeConfig) -> Option<i64> {
        rusqlite::Connection::open(&config.database)
            .unwrap()
            .query_row("SELECT value FROM runtime WHERE key='shadow'", [], |r| {
                r.get(0)
            })
            .optional()
            .unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unrestorable_shadow_is_cleared_and_dns_starts_with_active() {
        let directory = tempfile::tempdir().unwrap();
        let config = config(directory.path());
        stop(
            Runtime::start(config.clone(), Handle::current())
                .await
                .unwrap(),
        )
        .await;
        let mut failing = config.policy.clone();
        failing.assertions.push(rustwalld_dns_policy::Assertion {
            client: "127.0.0.1".parse().unwrap(),
            domain: "allowed.test".into(),
            expected: rustwalld_dns_filter::Action::Block,
        });
        for (id, content) in [
            (2, serde_json::to_string(&failing).unwrap()),
            (3, "{\"not\":\"a policy\"}".into()),
            (4, "{".into()),
        ] {
            let database = rusqlite::Connection::open(&config.database).unwrap();
            database
                .execute(
                    "INSERT INTO revisions(id,actor,state,diff,config) VALUES(?1,'api','shadow','policies',?2)",
                    rusqlite::params![id, content],
                )
                .unwrap();
            database
                .execute(
                    "INSERT INTO runtime(key,value) VALUES('shadow',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    [id],
                )
                .unwrap();
            drop(database);
            let runtime = Runtime::start(config.clone(), Handle::current())
                .await
                .unwrap();
            assert_eq!(runtime.control().engine().active().generation(), 1);
            assert!(runtime.control().engine().shadow_snapshot().is_none());
            // The pointer is durably cleared; the identifier is never reused.
            assert_eq!(shadow_pointer(&config), None);
            assert_eq!(runtime.control().next_generation(), id as u64 + 1);
            stop(runtime).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn configuration_file_seeds_only_a_new_database() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = config(directory.path());
        stop(
            Runtime::start(config.clone(), Handle::current())
                .await
                .unwrap(),
        )
        .await;
        // A file policy that cannot compile no longer blocks the stored revision.
        config
            .policy
            .assertions
            .push(rustwalld_dns_policy::Assertion {
                client: "127.0.0.1".parse().unwrap(),
                domain: "allowed.test".into(),
                expected: rustwalld_dns_filter::Action::Block,
            });
        let runtime = Runtime::start(config.clone(), Handle::current())
            .await
            .unwrap();
        assert_eq!(runtime.control().engine().active().generation(), 1);
        assert!(
            runtime
                .control()
                .engine()
                .active()
                .config()
                .assertions
                .is_empty()
        );
        stop(runtime).await;
        // A new database still compiles and validates the file.
        config.database = directory.path().join("fresh.sqlite");
        assert!(Runtime::start(config, Handle::current()).await.is_err());
    }
}
