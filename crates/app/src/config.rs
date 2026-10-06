use dns_core::ServerConfig;
use policy::PolicyConfigSet;
use serde::{Deserialize, Serialize};
use std::{
    io::{self, Read},
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
    pub action: filtering::Action,
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
        let mut file = std::fs::File::open(path)?.take(16 * 1024 * 1024 + 1);
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        if text.len() > 16 * 1024 * 1024 {
            return Err("config exceeds 16 MiB".into());
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
            std::fs::File::open(file_path)?
                .take(64 * 1024 * 1024 + 1)
                .read_to_string(&mut rules)?;
            if rules.len() > 64 * 1024 * 1024 {
                return Err("filter file exceeds 64 MiB".into());
            }
            let policy = config
                .policy
                .policies
                .iter_mut()
                .find(|p| p.name == input.policy)
                .ok_or("filter file refers to missing policy")?;
            policy.lists.push(filtering::ListInput {
                name: input.name.clone(),
                action: input.action,
                rules,
            });
        }
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<(), String> {
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
        validate_policy(&self.policy, self.dns_listen)
    }
    pub fn server(&self) -> ServerConfig {
        ServerConfig {
            listen: self.dns_listen,
            max_udp_queries: self.max_udp_queries,
            max_tcp_connections: self.max_tcp_connections,
            ..Default::default()
        }
    }
}
pub fn validate_policy(config: &PolicyConfigSet, listen: SocketAddr) -> Result<(), String> {
    crate::downloads::validate_config(config)?;
    for profile in &config.upstreams {
        for upstream in &profile.addresses {
            if upstream.port() == listen.port()
                && (listen.ip().is_unspecified()
                    || upstream.ip() == listen.ip()
                    || (listen.ip().is_loopback() && upstream.ip().is_loopback()))
            {
                return Err("upstream points at DNS listener".into());
            }
        }
    }
    // Broad client access must be explicit in PolicyConfigSet. Bindings do not grant access.
    if !listen.ip().is_loopback()
        && config
            .allowed_clients
            .iter()
            .all(|n| n.addr().is_loopback())
    {
        return Err("non-loopback DNS requires explicit allowed client CIDRs".into());
    }
    Ok(())
}
pub fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
