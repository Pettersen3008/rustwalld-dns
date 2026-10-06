//! Control-plane compilation; never run on the DNS executor.
use crate::{
    CompiledPolicy, PolicyConfigSet, PolicyError, PolicySnapshot, exceptions, metadata,
    snapshot::ClientBinding, sources,
};
use hickory_proto::rr::{
    Name, RData, Record,
    rdata::{A, AAAA},
};
use ipnet::IpNet;
use rustwalld_dns_filter::FilterSnapshot;
use rustwalld_dns_resolver::Forwarder;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::IpAddr,
    sync::Arc,
    time::Duration,
};
impl PolicySnapshot {
    pub fn compile(config: PolicyConfigSet, generation: u64) -> Result<Self, PolicyError> {
        let snapshot = Self::build(config, generation)?;
        snapshot.test_assertions()?;
        Ok(snapshot)
    }
    // Never expose a snapshot that has not passed required assertions.
    pub(crate) fn build(config: PolicyConfigSet, generation: u64) -> Result<Self, PolicyError> {
        sources::validate(&config)?;
        let clock = exceptions::Clock::now();
        if generation == 0
            || config.policies.is_empty()
            || config.policies.len() > 256
            || config.upstreams.is_empty()
            || config.upstreams.len() > 32
            || config.bindings.len() > 65536
            || config.allowed_clients.is_empty()
            || config.allowed_clients.len() > 256
            || config.assertions.len() > 10000
            || config
                .policies
                .iter()
                .map(|p| p.temporary_exceptions.len())
                .sum::<usize>()
                > 4096
        {
            return Err(PolicyError::Invalid(
                "counts/generation outside bounds".into(),
            ));
        }
        let mut profiles = HashMap::new();
        metadata::validate(&config.bindings)?;
        let mut upstreams = Vec::new();
        for profile in &config.upstreams {
            validate_name(&profile.name)?;
            if profiles
                .insert(profile.name.clone(), upstreams.len())
                .is_some()
                || !(10..=10000).contains(&profile.timeout_ms)
                || profile
                    .addresses
                    .iter()
                    .any(|a| a.port() == 0 || a.ip().is_unspecified() || a.ip().is_multicast())
            {
                return Err(PolicyError::Invalid("invalid upstream profile".into()));
            }
            upstreams.push(Arc::new(
                Forwarder::with_transport(
                    profile.addresses.clone(),
                    Duration::from_millis(profile.timeout_ms),
                    &profile.transport,
                )
                .map_err(|e| PolicyError::Invalid(e.to_string()))?,
            ));
        }
        let mut names = HashMap::new();
        let mut policies = Vec::new();
        let mut total_bytes = 0usize;
        for input in &config.policies {
            validate_name(&input.name)?;
            if names.insert(input.name.clone(), policies.len()).is_some() {
                return Err(PolicyError::Invalid("duplicate policy name".into()));
            }
            let upstream = *profiles
                .get(&input.upstream)
                .ok_or_else(|| PolicyError::Invalid("unknown upstream profile".into()))?;
            if input.lists.len() > 256
                || input.rewrites.len() > 10000
                || input.temporary_exceptions.len() > 1024
            {
                return Err(PolicyError::Invalid(
                    "too many lists/rewrites/exceptions".into(),
                ));
            }
            total_bytes = total_bytes
                .saturating_add(input.lists.iter().map(|l| l.rules.len()).sum::<usize>());
            if total_bytes > 256 * 1024 * 1024 {
                return Err(PolicyError::Invalid(
                    "combined filter data exceeds 256 MiB".into(),
                ));
            }
            let filters = FilterSnapshot::compile(&input.lists, 10_000_000, 256 * 1024 * 1024)?;
            if filters.stats.iter().any(|s| s.invalid > 0) {
                return Err(PolicyError::Invalid(format!(
                    "policy {} has invalid filter rules",
                    input.name
                )));
            }
            let mut rewrites = HashMap::new();
            for rewrite in &input.rewrites {
                let domain = rustwalld_dns_filter::normalize(&rewrite.domain)?;
                if rewrite.addresses.is_empty()
                    || rewrite.addresses.len() > 32
                    || rewrite.ttl > 86400
                    || rewrites.contains_key(&domain)
                {
                    return Err(PolicyError::Invalid("invalid/duplicate rewrite".into()));
                }
                let name = Name::from_ascii(format!("{domain}."))
                    .map_err(|_| PolicyError::Invalid("invalid rewrite name".into()))?;
                let records = rewrite
                    .addresses
                    .iter()
                    .map(|ip| {
                        Record::from_rdata(
                            name.clone(),
                            rewrite.ttl,
                            match ip {
                                IpAddr::V4(ip) => RData::A(A(*ip)),
                                IpAddr::V6(ip) => RData::AAAA(AAAA(*ip)),
                            },
                        )
                    })
                    .collect();
                rewrites.insert(domain, records);
            }
            policies.push(CompiledPolicy {
                id: policies.len(),
                name: input.name.clone(),
                upstream,
                filters,
                rewrites,
                exceptions: exceptions::Entries::compile(&input.temporary_exceptions, &clock)?,
            });
        }
        let default = *names
            .get(&config.default_policy)
            .ok_or_else(|| PolicyError::Invalid("default policy missing".into()))?;
        let mut ipv4 = BTreeMap::<u8, HashMap<u32, ClientBinding>>::new();
        let mut ipv6 = BTreeMap::<u8, HashMap<u128, ClientBinding>>::new();
        let mut seen = HashSet::new();
        let mut metadata = HashMap::new();
        for (index, binding) in config.bindings.iter().enumerate() {
            validate_name(&binding.name)?;
            let network = binding.network.trunc();
            if !seen.insert(network) {
                return Err(PolicyError::Invalid("duplicate client network".into()));
            }
            let policy = *names
                .get(&binding.policy)
                .ok_or_else(|| PolicyError::Invalid("binding refers to missing policy".into()))?;
            if binding.metadata.is_some() {
                metadata.insert(network, index);
            }
            let entry = ClientBinding {
                policy,
                name: binding.name.clone(),
                network,
            };
            match network {
                IpNet::V4(net) => {
                    ipv4.entry(net.prefix_len())
                        .or_default()
                        .insert(u32::from(net.network()), entry);
                }
                IpNet::V6(net) => {
                    ipv6.entry(net.prefix_len())
                        .or_default()
                        .insert(u128::from(net.network()), entry);
                }
            }
        }
        let snapshot = Self {
            generation,
            config,
            policies,
            upstreams,
            default,
            ipv4: ipv4.into_iter().rev().collect(),
            ipv6: ipv6.into_iter().rev().collect(),
            metadata,
        };
        Ok(snapshot)
    }
}
pub(crate) fn validate_name(name: &str) -> Result<(), PolicyError> {
    if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
        Err(PolicyError::Invalid("invalid name".into()))
    } else {
        Ok(())
    }
}
