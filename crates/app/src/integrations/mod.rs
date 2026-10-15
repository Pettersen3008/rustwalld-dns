//! Optional bounded inventory and reviewed peer copying, outside DNS workers.
mod remote;
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    net::IpAddr,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
pub struct Work {
    _global: OwnedSemaphorePermit,
    _source: OwnedSemaphorePermit,
}
impl Work {
    pub fn new(global: OwnedSemaphorePermit, source: OwnedSemaphorePermit) -> Self {
        Self {
            _global: global,
            _source: source,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Integration {
    pub name: String,
    pub source: Source,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Source {
    Dnsmasq {
        lease_file: PathBuf,
    },
    Unifi {
        endpoint: Remote,
        site: String,
        #[serde(default)]
        controller: bool,
    },
    Opnsense {
        endpoint: Remote,
    },
    Peer {
        endpoint: Remote,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Remote {
    pub url: String,
    pub bootstrap_ips: Vec<IpAddr>,
    pub token_file: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_pem: Option<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Device {
    pub address: IpAddr,
    pub name: Option<String>,
    pub mac: Option<String>,
    pub expires_at: Option<u64>,
}
#[derive(Clone, Default, Serialize)]
pub struct Inventory {
    pub devices: Vec<Device>,
    pub refreshed_at: Option<u64>,
    pub error: Option<String>,
}
pub struct Adapter {
    pub name: String,
    source: Source,
    remote: Option<remote::Client>,
    pub slot: Arc<Semaphore>,
    pub inventory: ArcSwap<Inventory>,
}
impl Adapter {
    pub fn load(config: Integration) -> Result<Self, String> {
        if config.name.is_empty()
            || config.name.len() > 64
            || !config
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err("integration name must be 1..64 ASCII letters/digits/-/_".into());
        }
        let remote = match &config.source {
            Source::Dnsmasq { lease_file } => {
                if lease_file.as_os_str().is_empty() {
                    return Err("lease file path is empty".into());
                }
                None
            }
            Source::Unifi { endpoint, site, .. } => {
                if site.is_empty()
                    || site.len() > 64
                    || !site.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                {
                    return Err("invalid UniFi site identifier".into());
                }
                Some(remote::Client::load(endpoint, remote::Auth::ApiKey)?)
            }
            Source::Opnsense { endpoint } => {
                Some(remote::Client::load(endpoint, remote::Auth::Basic)?)
            }
            Source::Peer { endpoint } => {
                Some(remote::Client::load(endpoint, remote::Auth::Bearer)?)
            }
        };
        Ok(Self {
            name: config.name,
            source: config.source,
            remote,
            slot: Arc::new(Semaphore::new(1)),
            inventory: ArcSwap::from_pointee(Inventory::default()),
        })
    }
    pub fn peer(&self) -> bool {
        matches!(self.source, Source::Peer { .. })
    }
    pub fn kind(&self) -> &'static str {
        match self.source {
            Source::Dnsmasq { .. } => "dnsmasq",
            Source::Unifi { .. } => "unifi",
            Source::Opnsense { .. } => "opnsense",
            Source::Peer { .. } => "peer",
        }
    }
    pub async fn fetch(&self, work: Arc<Work>) -> Result<Vec<Device>, String> {
        let devices = match &self.source {
            Source::Dnsmasq { lease_file } => {
                let path = lease_file.clone();
                tokio::task::spawn_blocking(move || {
                    let _work = work;
                    read_leases(&path)
                })
                .await
                .map_err(|_| "lease reader stopped")??
            }
            Source::Unifi {
                site, controller, ..
            } => {
                let prefix = if *controller {
                    "/integration"
                } else {
                    "/proxy/network/integration"
                };
                let client = self
                    .remote
                    .as_ref()
                    .ok_or("integration transport missing")?;
                let mut devices = Vec::new();
                let mut offset = 0usize;
                for _ in 0..16 {
                    #[derive(Deserialize)]
                    struct Page {
                        #[serde(rename = "totalCount")]
                        total: usize,
                        data: Vec<UniClient>,
                    }
                    #[derive(Deserialize)]
                    #[serde(rename_all = "camelCase")]
                    struct UniClient {
                        ip_address: Option<IpAddr>,
                        name: Option<String>,
                        mac_address: Option<String>,
                    }
                    let bytes = client
                        .get(
                            &format!("{prefix}/v1/sites/{site}/clients?offset={offset}&limit=256"),
                            1024 * 1024,
                        )
                        .await?;
                    let page: Page = serde_json::from_slice(&bytes)
                        .map_err(|_| "invalid UniFi client response")?;
                    if page.total > 4096 || page.data.len() > 256 {
                        return Err("UniFi inventory exceeds 4096 devices/256 per page".into());
                    }
                    let count = page.data.len();
                    for entry in page.data {
                        if let Some(address) = entry.ip_address {
                            devices.push(Device {
                                address,
                                name: clean(entry.name)?,
                                mac: clean(entry.mac_address)?,
                                expires_at: None,
                            });
                        }
                    }
                    offset = offset
                        .checked_add(count)
                        .ok_or("inventory count overflow")?;
                    if offset >= page.total {
                        return Ok(devices);
                    }
                    if count == 0 {
                        return Err("incomplete UniFi pagination".into());
                    }
                }
                return Err("UniFi inventory exceeds sixteen pages".into());
            }
            Source::Opnsense { .. } => {
                #[derive(Deserialize)]
                struct Page {
                    total: usize,
                    rows: Vec<Lease>,
                }
                #[derive(Deserialize)]
                struct Lease {
                    address: IpAddr,
                    hostname: Option<String>,
                    hwaddr: Option<String>,
                    state: u8,
                }
                let client = self
                    .remote
                    .as_ref()
                    .ok_or("integration transport missing")?;
                let bytes = client
                    .get(
                        "/api/kea/leases4/search?rowCount=4096&current=1",
                        1024 * 1024,
                    )
                    .await?;
                let page: Page =
                    serde_json::from_slice(&bytes).map_err(|_| "invalid OPNsense Kea response")?;
                if page.total > 4096 || page.rows.len() > 4096 || page.total > page.rows.len() {
                    return Err("OPNsense inventory incomplete or exceeds 4096 leases".into());
                }
                let mut devices = Vec::new();
                for lease in page.rows {
                    if lease.state == 0 {
                        devices.push(Device {
                            address: lease.address,
                            name: clean(lease.hostname)?,
                            mac: clean(lease.hwaddr)?,
                            expires_at: None,
                        });
                    }
                }
                devices
            }
            Source::Peer { .. } => return Err("peer uses reviewed policy preview".into()),
        };
        Ok(devices)
    }
    pub async fn peer_config(&self) -> Result<Vec<u8>, String> {
        if !self.peer() {
            return Err("integration is not a policy peer".into());
        }
        self.remote
            .as_ref()
            .ok_or("integration transport missing")?
            .get("/api/v1/config", 16 * 1024 * 1024)
            .await
    }
}
fn clean(value: Option<String>) -> Result<Option<String>, String> {
    match value {
        Some(value) if value.len() > 256 || value.chars().any(char::is_control) => {
            Err("inventory label outside bounds".into())
        }
        Some(value) if value.is_empty() || value == "*" => Ok(None),
        value => Ok(value),
    }
}
pub fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| "clock before Unix epoch".into())
}
fn read_leases(path: &std::path::Path) -> Result<Vec<Device>, String> {
    let file = std::fs::File::open(path).map_err(|_| "lease file unavailable")?;
    if !file
        .metadata()
        .map_err(|_| "lease metadata unavailable")?
        .is_file()
    {
        return Err("lease source must be a regular file".into());
    }
    let mut text = String::new();
    file.take(1024 * 1024 + 1)
        .read_to_string(&mut text)
        .map_err(|_| "lease file is not UTF-8 or unreadable")?;
    if text.len() > 1024 * 1024 {
        return Err("lease file exceeds 1 MiB".into());
    }
    parse_leases(&text, now()?)
}
pub fn parse_leases(text: &str, now: u64) -> Result<Vec<Device>, String> {
    if text.len() > 1024 * 1024 {
        return Err("lease file exceeds 1 MiB".into());
    }
    let mut devices = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if index >= 4096 {
            return Err("lease file exceeds 4096 lines".into());
        }
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.is_empty() {
            continue;
        }
        if fields.len() != 5 {
            return Err("unsupported dnsmasq lease format (DHCPv4 only)".into());
        }
        let expires = fields[0]
            .parse::<u64>()
            .map_err(|_| "invalid lease expiry")?;
        let address = fields[2]
            .parse::<std::net::Ipv4Addr>()
            .map_err(|_| "invalid DHCPv4 address")?;
        if expires != 0 && expires <= now {
            continue;
        }
        devices.push(Device {
            address: address.into(),
            name: clean(Some(fields[3].into()))?,
            mac: clean(Some(fields[1].into()))?,
            expires_at: if expires == 0 { None } else { Some(expires) },
        });
    }
    Ok(devices)
}
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #[test]
    fn expired_and_unlimited_leases_never_become_admission() {
        let list=super::parse_leases("99 aa:bb:cc:dd:ee:ff 192.0.2.1 old *\n0 01:02:03:04:05:06 192.0.2.2 * *\n120 11:22:33:44:55:66 192.0.2.3 nas *",100).unwrap();
        assert_eq!(list.len(), 2);
        assert!(list[0].name.is_none());
        assert_eq!(list[1].expires_at, Some(120));
        assert!(super::parse_leases("0 a 192.0.2.3", 0).is_err());
        assert!(super::parse_leases(&"0 a 192.0.2.3 n *\n".repeat(4097), 0).is_err());
    }
}
