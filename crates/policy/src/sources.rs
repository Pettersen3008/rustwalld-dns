//! Control-plane metadata only. Fetching belongs to app; matchers use list text.
use crate::{PolicyConfigSet, PolicyError, validate_name};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::IpAddr};

pub const MAX_DOWNLOAD_BYTES: usize = 8 * 1024 * 1024;
pub const MIN_REFRESH_INTERVAL: u64 = 300;
pub const MAX_REFRESH_INTERVAL: u64 = 30 * 86400;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FilterSource {
    pub policy: String,
    pub list: String,
    pub url: String,
    pub bootstrap_ips: Vec<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download: Option<DownloadStamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_interval_secs: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DownloadStamp {
    pub retrieved_at: u64,
    pub sha256: String,
    pub bytes: usize,
}

pub(crate) fn validate(config: &PolicyConfigSet) -> Result<(), PolicyError> {
    if config.filter_sources.len() > 64 {
        return Err(PolicyError::Invalid(
            "too many downloaded-list sources".into(),
        ));
    }
    let mut targets = HashSet::new();
    for source in &config.filter_sources {
        validate_name(&source.policy)?;
        validate_name(&source.list)?;
        let mut ips = HashSet::new();
        if !targets.insert((&source.policy, &source.list))
            || source.url.is_empty()
            || source.url.len() > 2048
            || source.url.chars().any(char::is_control)
            || !(1..=8).contains(&source.bootstrap_ips.len())
            || source.bootstrap_ips.iter().any(|ip| {
                let ip = ip.to_canonical();
                ip.is_unspecified()
                    || ip.is_multicast()
                    || matches!(ip, IpAddr::V4(ip) if ip.is_broadcast())
                    || !ips.insert(ip)
            })
            || source
                .ca_pem
                .as_ref()
                .is_some_and(|pem| pem.is_empty() || pem.len() > 65536)
            || source.refresh_interval_secs.is_some_and(|interval| {
                !(MIN_REFRESH_INTERVAL..=MAX_REFRESH_INTERVAL).contains(&interval)
            })
            || !config.policies.iter().any(|policy| {
                policy.name == source.policy
                    && policy.lists.iter().any(|list| list.name == source.list)
            })
            || source.download.as_ref().is_some_and(|stamp| {
                !(1..=253_402_300_799).contains(&stamp.retrieved_at)
                    || !(1..=MAX_DOWNLOAD_BYTES).contains(&stamp.bytes)
                    || stamp.sha256.len() != 64
                    || !stamp
                        .sha256
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
        {
            return Err(PolicyError::Invalid(
                "invalid/duplicate downloaded-list source".into(),
            ));
        }
    }
    Ok(())
}
