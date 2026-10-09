use rustwalld_dns_policy::PolicyConfigSet;
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub dns_listen: SocketAddr,
    pub api_listen: SocketAddr,
    pub database: PathBuf,
    pub web_root: Option<PathBuf>,
    pub dns_cache_entries: usize,
    pub decision_cache_entries: usize,
    pub max_inflight: usize,
    pub max_udp_queries: usize,
    pub max_udp_upstream_waits: usize,
    pub max_tcp_connections: usize,
    pub event_queue: usize,
    pub history_rows: usize,
    pub policy: PolicyConfigSet,
    pub filter_files: Vec<FilterFile>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilterFile {
    pub policy: String,
    pub name: String,
    pub action: rustwalld_dns_filter::Action,
    pub path: PathBuf,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            dns_listen: SocketAddr::from(([127, 0, 0, 1], 5353)),
            api_listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
            database: PathBuf::from("rustwalld.sqlite"),
            web_root: None,
            dns_cache_entries: 4096,
            decision_cache_entries: 16384,
            max_inflight: 256,
            max_udp_queries: 512,
            max_udp_upstream_waits: 1024,
            max_tcp_connections: 128,
            event_queue: 4096,
            history_rows: 100000,
            policy: PolicyConfigSet::default(),
            filter_files: vec![],
        }
    }
}
impl Config {
    pub fn read(path: &Path) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let read_error =
            |file: &Path, error: std::io::Error| format!("{}: {error}", file.display());
        let mut text = String::new();
        std::fs::File::open(path)
            .and_then(|file| file.take(16 * 1024 * 1024 + 1).read_to_string(&mut text))
            .map_err(|error| read_error(path, error))?;
        if text.len() > 16 * 1024 * 1024 {
            return Err(format!("{}: config exceeds 16 MiB", path.display()).into());
        }
        let mut config: Self = toml::from_str(&text)?;
        if let Some(root) = &mut config.web_root
            && root.is_relative()
        {
            *root = path.parent().unwrap_or(Path::new(".")).join(&*root);
        }
        for input in &config.filter_files {
            let file_path = if input.path.is_absolute() {
                input.path.clone()
            } else {
                path.parent().unwrap_or(Path::new(".")).join(&input.path)
            };
            let mut rules = String::new();
            std::fs::File::open(&file_path)
                .and_then(|file| file.take(64 * 1024 * 1024 + 1).read_to_string(&mut rules))
                .map_err(|error| read_error(&file_path, error))?;
            if rules.len() > 64 * 1024 * 1024 {
                return Err(format!("{}: filter file exceeds 64 MiB", file_path.display()).into());
            }
            let policy = config
                .policy
                .policies
                .iter_mut()
                .find(|p| p.name == input.policy)
                .ok_or("filter file refers to missing policy")?;
            policy.lists.push(rustwalld_dns_filter::ListInput {
                name: input.name.clone(),
                action: input.action,
                rules,
            });
        }
        config.validate_settings()?;
        Ok(config)
    }
    /// Validate listeners, limits and the embedded policy (`--check-config`).
    pub fn validate(&self) -> Result<(), String> {
        self.validate_settings()?;
        validate_policy(&self.policy, self.dns_listen)
    }
    /// Validate everything except the policy. The file's policy seeds only a
    /// new database; the runtime validates and compiles it when bootstrapping,
    /// so a broken file cannot block a valid stored revision at startup.
    pub fn validate_settings(&self) -> Result<(), String> {
        if self
            .web_root
            .as_ref()
            .is_some_and(|root| !root.join("index.html").is_file())
        {
            return Err("web_root must contain a built index.html".into());
        }
        if !self.api_listen.ip().is_loopback() {
            return Err("management API must bind to loopback".into());
        }
        if self.dns_listen.port() == 0
            || self.api_listen.port() == 0
            || self.dns_listen == self.api_listen
        {
            return Err("listener ports must be nonzero and distinct".into());
        }
        rustwalld_dns_runtime::RuntimeConfig {
            dns_cache_entries: self.dns_cache_entries,
            decision_cache_entries: self.decision_cache_entries,
            max_inflight: self.max_inflight,
            max_udp_queries: self.max_udp_queries,
            max_udp_upstream_waits: self.max_udp_upstream_waits,
            max_tcp_connections: self.max_tcp_connections,
            event_queue: self.event_queue,
            history_rows: self.history_rows,
            ..Default::default()
        }
        .validate_limits()
    }
    /// Resolved values for the optional durable runtime; no file I/O here.
    pub fn into_runtime(self) -> rustwalld_dns_runtime::RuntimeConfig {
        rustwalld_dns_runtime::RuntimeConfig {
            dns_listen: self.dns_listen,
            database: self.database,
            dns_cache_entries: self.dns_cache_entries,
            decision_cache_entries: self.decision_cache_entries,
            max_inflight: self.max_inflight,
            max_udp_queries: self.max_udp_queries,
            max_udp_upstream_waits: self.max_udp_upstream_waits,
            max_tcp_connections: self.max_tcp_connections,
            event_queue: self.event_queue,
            history_rows: self.history_rows,
            policy: self.policy,
        }
    }
}
pub use rustwalld_dns_runtime::config::{invalid, validate_policy};
