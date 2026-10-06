//! Control-plane compilation and pure client-policy lookup.
mod assertions;
mod exceptions;
mod metadata;
mod sources;
pub use assertions::{AssertionFailure, AssertionResult, AssertionTrace, CheckReport, MatchedRule};
pub use exceptions::{MAX_EXCEPTION_REMAINING, TemporaryException, TemporaryMatch};
use filtering::{Action, Decision, FilterSnapshot, ListInput};
use hickory_proto::rr::{
    Name, RData, Record, RecordType,
    rdata::{A, AAAA},
};
use ipnet::IpNet;
pub use metadata::BindingMetadata;
use resolver::Forwarder;
pub use resolver::UpstreamTransport;
use serde::{Deserialize, Serialize};
pub use sources::{
    DownloadStamp, FilterSource, MAX_DOWNLOAD_BYTES, MAX_REFRESH_INTERVAL, MIN_REFRESH_INTERVAL,
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamProfile {
    pub name: String,
    pub addresses: Vec<SocketAddr>,
    pub timeout_ms: u64,
    #[serde(default, skip_serializing_if = "resolver::UpstreamTransport::is_udp")]
    pub transport: resolver::UpstreamTransport,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    pub name: String,
    pub upstream: String,
    #[serde(default)]
    pub lists: Vec<ListInput>,
    #[serde(default)]
    pub rewrites: Vec<Rewrite>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub temporary_exceptions: Vec<TemporaryException>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rewrite {
    pub domain: String,
    pub addresses: Vec<IpAddr>,
    #[serde(default = "rewrite_ttl")]
    pub ttl: u32,
}
fn rewrite_ttl() -> u32 {
    60
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub network: IpNet,
    pub policy: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<BindingMetadata>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assertion {
    pub client: IpAddr,
    pub domain: String,
    pub expected: Action,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfigSet {
    pub default_policy: String,
    pub policies: Vec<PolicyConfig>,
    pub upstreams: Vec<UpstreamProfile>,
    #[serde(default)]
    pub bindings: Vec<Binding>,
    pub allowed_clients: Vec<IpNet>,
    #[serde(default)]
    pub assertions: Vec<Assertion>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filter_sources: Vec<FilterSource>,
}
impl Default for PolicyConfigSet {
    fn default() -> Self {
        Self {
            default_policy: "default".into(),
            policies: vec![PolicyConfig {
                name: "default".into(),
                upstream: "default".into(),
                lists: vec![],
                rewrites: vec![],
                temporary_exceptions: vec![],
            }],
            upstreams: vec![UpstreamProfile {
                name: "default".into(),
                addresses: vec![
                    SocketAddr::from(([1, 1, 1, 1], 53)),
                    SocketAddr::from(([9, 9, 9, 9], 53)),
                ],
                timeout_ms: 1500,
                transport: resolver::UpstreamTransport::Udp,
            }],
            bindings: vec![],
            allowed_clients: vec![
                IpNet::from(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
                IpNet::from(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
            ],
            assertions: vec![],
            filter_sources: vec![],
        }
    }
}
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid configuration: {0}")]
    Invalid(String),
    #[error(transparent)]
    Filter(#[from] filtering::CompileError),
    #[error("required policy assertion failed: {0}")]
    Assertion(String),
}
pub struct CompiledPolicy {
    pub id: usize,
    pub name: String,
    pub upstream: usize,
    pub filters: FilterSnapshot,
    rewrites: HashMap<String, Vec<Record>>,
    exceptions: Option<exceptions::Entries>,
}
impl CompiledPolicy {
    pub fn rewrite(&self, domain: &str, kind: RecordType) -> Option<Vec<Record>> {
        let records = self.rewrites.get(domain)?;
        Some(
            records
                .iter()
                .filter(|record| record.data.record_type() == kind)
                .cloned()
                .collect(),
        )
    }
    pub fn has_rewrite(&self, domain: &str) -> bool {
        self.rewrites.contains_key(domain)
    }
}
struct ClientBinding {
    policy: usize,
    name: String,
    network: IpNet,
}
#[derive(Serialize)]
pub struct Explanation<'a> {
    pub generation: u64,
    pub client: IpAddr,
    pub client_name: Option<&'a str>,
    pub network: Option<IpNet>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding_metadata: Option<&'a BindingMetadata>,
    pub policy: &'a str,
    pub decision: Decision,
    pub rule: Option<&'a filtering::Rule>,
    pub rewrite: bool,
    pub upstream: &'a str,
    pub temporary_exception: Option<&'a TemporaryException>,
}
pub struct Selection<'a> {
    pub policy: &'a CompiledPolicy,
    pub client_name: Option<&'a str>,
    pub network: Option<IpNet>,
}
pub struct PolicySnapshot {
    pub generation: u64,
    pub config: PolicyConfigSet,
    pub policies: Vec<CompiledPolicy>,
    pub upstreams: Vec<Arc<Forwarder>>,
    default: usize,
    ipv4: Vec<(u8, HashMap<u32, ClientBinding>)>,
    ipv6: Vec<(u8, HashMap<u128, ClientBinding>)>,
    // Sparse control-only index into config. Selection never reads annotations.
    metadata: HashMap<IpNet, usize>,
}
impl PolicySnapshot {
    pub fn compile(config: PolicyConfigSet, generation: u64) -> Result<Self, PolicyError> {
        let snapshot = Self::build(config, generation)?;
        snapshot.test_assertions()?;
        Ok(snapshot)
    }
    // Never expose a snapshot that has not passed required assertions.
    fn build(config: PolicyConfigSet, generation: u64) -> Result<Self, PolicyError> {
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
                let domain = filtering::normalize(&rewrite.domain)?;
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
    pub fn permits(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.config
            .allowed_clients
            .iter()
            .any(|network| network.contains(&ip))
    }
    pub fn select(&self, ip: IpAddr) -> Selection<'_> {
        let ip = ip.to_canonical();
        let binding = match ip {
            IpAddr::V4(ip) => self.ipv4.iter().find_map(|(prefix, map)| {
                let mask = if *prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                map.get(&(u32::from(ip) & mask))
            }),
            IpAddr::V6(ip) => self.ipv6.iter().find_map(|(prefix, map)| {
                let mask = if *prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                map.get(&(u128::from(ip) & mask))
            }),
        };
        Selection {
            policy: &self.policies[binding.map_or(self.default, |b| b.policy)],
            client_name: binding.map(|b| b.name.as_str()),
            network: binding.map(|b| b.network),
        }
    }
    pub fn explain(&self, client: IpAddr, domain: &str) -> Result<Explanation<'_>, PolicyError> {
        let domain = filtering::normalize(domain)?;
        let mut explanation = self.explain_normalized(client, &domain);
        if !explanation.rewrite
            && let Some(found) = self
                .select(client)
                .policy
                .temporary_allow(&domain, Instant::now())
        {
            explanation.decision = Decision::ALLOW;
            explanation.rule = None;
            explanation.temporary_exception = Some(found.exception);
        }
        Ok(explanation)
    }
    fn explain_normalized(&self, client: IpAddr, domain: &str) -> Explanation<'_> {
        let selected = self.select(client);
        let policy = selected.policy;
        let rewrite = policy.has_rewrite(domain);
        let decision = if rewrite {
            Decision::ALLOW
        } else {
            policy.filters.evaluate(domain)
        };
        Explanation {
            generation: self.generation,
            client,
            client_name: selected.client_name,
            network: selected.network,
            binding_metadata: selected.network.and_then(|network| {
                self.metadata
                    .get(&network)
                    .and_then(|index| self.config.bindings[*index].metadata.as_ref())
            }),
            policy: &policy.name,
            decision,
            rule: decision.rule.and_then(|id| policy.filters.rule(id)),
            rewrite,
            upstream: &self.config.upstreams[policy.upstream].name,
            temporary_exception: None,
        }
    }
    pub fn test_assertions(&self) -> Result<(), PolicyError> {
        for assertion in &self.config.assertions {
            if !self.permits(assertion.client) {
                return Err(PolicyError::Assertion(format!(
                    "{} is outside allowed client networks",
                    assertion.client
                )));
            }
            let domain = filtering::normalize(&assertion.domain)?;
            let explanation = self.explain_normalized(assertion.client, &domain);
            if explanation.decision.action != assertion.expected {
                return Err(PolicyError::Assertion(format!(
                    "{} + {}: expected {:?}, got {:?}; policy {}, rule {:?}",
                    assertion.client,
                    assertion.domain,
                    assertion.expected,
                    explanation.decision.action,
                    explanation.policy,
                    explanation.rule
                )));
            }
        }
        Ok(())
    }
}
fn validate_name(name: &str) -> Result<(), PolicyError> {
    if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
        Err(PolicyError::Invalid("invalid name".into()))
    } else {
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn longest_prefix_ipv4_ipv6_and_assertions() {
        let mut config = PolicyConfigSet {
            allowed_clients: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
            ..Default::default()
        };
        config.policies.push(PolicyConfig {
            name: "iot".into(),
            upstream: "default".into(),
            lists: vec![ListInput {
                name: "deny".into(),
                action: Action::Block,
                rules: "ads.test".into(),
            }],
            rewrites: vec![],
            temporary_exceptions: vec![],
        });
        config.bindings = vec![
            Binding {
                network: "10.0.0.0/8".parse().unwrap(),
                policy: "iot".into(),
                name: "iot-net".into(),
                metadata: None,
            },
            Binding {
                network: "10.1.0.1/32".parse().unwrap(),
                policy: "default".into(),
                name: "exception".into(),
                metadata: None,
            },
            Binding {
                network: "2001:db8::/32".parse().unwrap(),
                policy: "iot".into(),
                name: "v6".into(),
                metadata: None,
            },
        ];
        config.assertions.push(Assertion {
            client: "10.0.1.1".parse().unwrap(),
            domain: "ads.test".into(),
            expected: Action::Block,
        });
        let snapshot = PolicySnapshot::compile(config.clone(), 1).unwrap();
        assert_eq!(
            snapshot.select("10.1.0.1".parse().unwrap()).policy.name,
            "default"
        );
        assert_eq!(
            snapshot.select("10.2.0.1".parse().unwrap()).policy.name,
            "iot"
        );
        assert_eq!(
            snapshot.select("2001:db8::1".parse().unwrap()).policy.name,
            "iot"
        );
        assert_eq!(
            snapshot
                .select("::ffff:10.1.0.1".parse().unwrap())
                .policy
                .name,
            "default"
        );
        assert_eq!(
            snapshot
                .select("::ffff:10.2.0.1".parse().unwrap())
                .policy
                .name,
            "iot"
        );
        config.assertions[0].expected = Action::Allow;
        assert!(PolicySnapshot::compile(config, 2).is_err());
    }
}
