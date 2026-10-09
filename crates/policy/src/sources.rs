//! Control-plane metadata only. Fetching belongs to app; matchers use list text.
use crate::{PolicyConfigSet, PolicyError, config::validate_name};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::IpAddr};

/// Largest accepted downloaded list body.
pub const MAX_DOWNLOAD_BYTES: usize = 8 * 1024 * 1024;
/// Shortest scheduled refresh interval, in seconds.
pub const MIN_REFRESH_INTERVAL: u64 = 300;
/// Longest scheduled refresh interval, in seconds.
pub const MAX_REFRESH_INTERVAL: u64 = 30 * 86400;
/// Last representable second of 9999-12-31 UTC, shared by all absolute timestamps.
pub(crate) const MAX_UNIX_SECONDS: u64 = 253_402_300_799;

/// A remote HTTPS list that supplies one policy list's rules.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FilterSource {
    /// Policy owning the list.
    pub policy: String,
    /// List name within that policy.
    pub list: String,
    /// HTTPS URL of the list.
    pub url: String,
    /// Pinned server addresses (1..=8); no DNS lookup is performed.
    pub bootstrap_ips: Vec<IpAddr>,
    /// CA certificates replacing the bundled public roots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_pem: Option<String>,
    /// Fingerprint of the content currently in the list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download: Option<DownloadStamp>,
    /// Scheduled check interval; `None` disables scheduling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_interval_secs: Option<u64>,
}

/// Provenance of downloaded list content.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DownloadStamp {
    /// Retrieval time, in Unix seconds.
    pub retrieved_at: u64,
    /// Lowercase hex SHA-256 of the body.
    pub sha256: String,
    /// Body length in bytes.
    pub bytes: usize,
}

/// Whether `ip` may be pinned as a download destination. IPv4-mapped IPv6
/// addresses are judged as the IPv4 address they reach.
pub fn is_unicast_destination(ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    !(ip.is_unspecified() || ip.is_multicast() || matches!(ip, IpAddr::V4(ip) if ip.is_broadcast()))
}

pub(crate) fn validate(config: &PolicyConfigSet) -> Result<(), PolicyError> {
    PolicyError::check_count(
        || "filter_sources".into(),
        config.filter_sources.len(),
        0,
        64,
    )?;
    let mut targets = HashSet::new();
    for (index, source) in config.filter_sources.iter().enumerate() {
        let field = |name: &str| format!("filter_sources[{index}].{name}");
        let invalid = |name: &str, reason: &str| Err(PolicyError::field(field(name), reason));
        validate_name(&source.policy, || field("policy"))?;
        validate_name(&source.list, || field("list"))?;
        if !targets.insert((&source.policy, &source.list)) {
            return invalid("list", "another source already targets this policy/list");
        }
        if source.url.is_empty()
            || source.url.len() > 2048
            || source.url.chars().any(char::is_control)
        {
            return invalid(
                "url",
                "must be 1 through 2048 bytes without control characters",
            );
        }
        PolicyError::check_count(|| field("bootstrap_ips"), source.bootstrap_ips.len(), 1, 8)?;
        let mut ips = HashSet::new();
        for ip in &source.bootstrap_ips {
            if !is_unicast_destination(*ip) {
                return invalid("bootstrap_ips", &format!("{ip} is not a unicast address"));
            }
            if !ips.insert(ip.to_canonical()) {
                return invalid("bootstrap_ips", &format!("{ip} is listed more than once"));
            }
        }
        if source
            .ca_pem
            .as_ref()
            .is_some_and(|pem| pem.is_empty() || pem.len() > 65536)
        {
            return invalid("ca_pem", "must be 1 through 65536 bytes");
        }
        if source.refresh_interval_secs.is_some_and(|interval| {
            !(MIN_REFRESH_INTERVAL..=MAX_REFRESH_INTERVAL).contains(&interval)
        }) {
            return invalid(
                "refresh_interval_secs",
                "must be 300 seconds through 30 days",
            );
        }
        if !config.policies.iter().any(|policy| {
            policy.name == source.policy && policy.lists.iter().any(|list| list.name == source.list)
        }) {
            return invalid("list", "refers to a missing policy/list");
        }
        if let Some(stamp) = &source.download
            && (!(1..=MAX_UNIX_SECONDS).contains(&stamp.retrieved_at)
                || !(1..=MAX_DOWNLOAD_BYTES).contains(&stamp.bytes)
                || stamp.sha256.len() != 64
                || !stamp
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
        {
            return invalid(
                "download",
                "requires a retrieval time, 1 byte through 8 MiB and a lowercase SHA-256",
            );
        }
    }
    Ok(())
}
