//! Control-plane compilation; never run on the DNS executor.
use crate::{
    CompiledPolicy, PolicyConfigSet, PolicyError, PolicySnapshot,
    config::{excerpt, validate_name},
    exceptions, metadata,
    snapshot::ClientBinding,
    sources,
};
use hickory_proto::rr::{
    Name, RData, Record,
    rdata::{A, AAAA},
};
use ipnet::{IpNet, Ipv4Net};
use rustwalld_dns_filter::FilterSnapshot;
use rustwalld_dns_resolver::Forwarder;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::IpAddr,
    sync::Arc,
    time::Duration,
};
const MAX_FILTER_BYTES: usize = 256 * 1024 * 1024;
const MAX_POLICY_RULES: usize = 10_000_000;
impl PolicySnapshot {
    pub fn compile(config: PolicyConfigSet, generation: u64) -> Result<Self, PolicyError> {
        let snapshot = Self::build(config, generation)?;
        snapshot.test_assertions()?;
        Ok(snapshot)
    }
    // Never expose a snapshot that has not passed required assertions.
    pub(crate) fn build(config: PolicyConfigSet, generation: u64) -> Result<Self, PolicyError> {
        Self::build_using(config, generation, FilterSnapshot::compile)
    }
    /// Compile through an owned bounded pool, preserving the assertion gate.
    /// The caller must keep this synchronous work off the DNS executor.
    #[cfg(feature = "parallel")]
    pub fn compile_parallel(
        config: PolicyConfigSet,
        generation: u64,
        compiler: &rustwalld_dns_filter::ParallelCompiler,
    ) -> Result<Self, PolicyError> {
        let snapshot = Self::build_parallel(config, generation, compiler)?;
        snapshot.test_assertions()?;
        Ok(snapshot)
    }
    #[cfg(feature = "parallel")]
    pub(crate) fn build_parallel(
        config: PolicyConfigSet,
        generation: u64,
        compiler: &rustwalld_dns_filter::ParallelCompiler,
    ) -> Result<Self, PolicyError> {
        Self::build_using(config, generation, |lists, rules, bytes| {
            compiler.compile(lists, rules, bytes)
        })
    }
    fn build_using(
        config: PolicyConfigSet,
        generation: u64,
        compile_filters: impl Fn(
            &[rustwalld_dns_filter::ListInput],
            usize,
            usize,
        ) -> Result<FilterSnapshot, rustwalld_dns_filter::CompileError>,
    ) -> Result<Self, PolicyError> {
        let mut config = config;
        sources::validate(&config)?;
        validate_counts(&config, generation)?;
        // Admission compares canonical client IPs; store mapped networks as IPv4.
        for (index, network) in config.allowed_clients.iter_mut().enumerate() {
            *network = canonical_network(*network, || format!("allowed_clients[{index}]"))?;
        }
        let clock = exceptions::Clock::now();
        metadata::validate(&config.bindings)?;
        let (profiles, upstreams) = compile_upstreams(&config)?;
        let mut names = HashMap::new();
        let mut policies = Vec::new();
        let mut total_bytes = 0usize;
        for (index, input) in config.policies.iter().enumerate() {
            let field = |name: &str| format!("policies[{index}].{name}");
            validate_name(&input.name, || field("name"))?;
            if names.insert(input.name.clone(), policies.len()).is_some() {
                return Err(PolicyError::field(
                    field("name"),
                    format!("duplicate policy name {}", excerpt(&input.name)),
                ));
            }
            let upstream = *profiles.get(&input.upstream).ok_or_else(|| {
                PolicyError::field(
                    field("upstream"),
                    format!("unknown upstream profile {}", excerpt(&input.upstream)),
                )
            })?;
            PolicyError::check_count(|| field("lists"), input.lists.len(), 0, 256)?;
            PolicyError::check_count(|| field("rewrites"), input.rewrites.len(), 0, 10000)?;
            PolicyError::check_count(
                || field("temporary_exceptions"),
                input.temporary_exceptions.len(),
                0,
                1024,
            )?;
            total_bytes = total_bytes
                .saturating_add(input.lists.iter().map(|l| l.rules.len()).sum::<usize>());
            if total_bytes > MAX_FILTER_BYTES {
                return Err(PolicyError::field(
                    field("lists"),
                    "combined filter data exceeds 256 MiB",
                ));
            }
            let filters = compile_filters(&input.lists, MAX_POLICY_RULES, MAX_FILTER_BYTES)?;
            if let Some(list) = filters.stats.iter().find(|s| s.invalid > 0) {
                return Err(PolicyError::field(
                    field("lists"),
                    format!(
                        "policy {} list {} has {} invalid filter rules",
                        excerpt(&input.name),
                        excerpt(&list.name),
                        list.invalid
                    ),
                ));
            }
            policies.push(CompiledPolicy {
                id: policies.len(),
                name: input.name.clone(),
                upstream,
                filters,
                rewrites: compile_rewrites(index, input)?,
                exceptions: exceptions::Entries::compile(
                    index,
                    &input.temporary_exceptions,
                    &clock,
                )?,
            });
        }
        let default = *names.get(&config.default_policy).ok_or_else(|| {
            PolicyError::field(
                "default_policy",
                format!("unknown policy {}", excerpt(&config.default_policy)),
            )
        })?;
        let mut ipv4 = BTreeMap::<u8, HashMap<u32, ClientBinding>>::new();
        let mut ipv6 = BTreeMap::<u8, HashMap<u128, ClientBinding>>::new();
        let mut seen = HashSet::new();
        let mut metadata = HashMap::new();
        for (index, binding) in config.bindings.iter().enumerate() {
            let field = |name: &str| format!("bindings[{index}].{name}");
            validate_name(&binding.name, || field("name"))?;
            let network = canonical_network(binding.network, || field("network"))?.trunc();
            if !seen.insert(network) {
                return Err(PolicyError::field(
                    field("network"),
                    format!("duplicate client network {network}"),
                ));
            }
            let policy = *names.get(&binding.policy).ok_or_else(|| {
                PolicyError::field(
                    field("policy"),
                    format!("unknown policy {}", excerpt(&binding.policy)),
                )
            })?;
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
/// Query-path client addresses are canonicalized (`::ffff:a.b.c.d` becomes
/// `a.b.c.d`), so an IPv4-mapped IPv6 network can only ever match as the IPv4
/// network it maps. Convert it; a mapped prefix shorter than /96 would also
/// cover unrelated IPv6 space and is rejected.
fn canonical_network(network: IpNet, field: impl FnOnce() -> String) -> Result<IpNet, PolicyError> {
    let IpNet::V6(v6) = network else {
        return Ok(network);
    };
    let Some(v4) = v6.addr().to_ipv4_mapped() else {
        return Ok(network);
    };
    v6.prefix_len()
        .checked_sub(96)
        .and_then(|prefix| Ipv4Net::new(v4, prefix).ok())
        .map(IpNet::V4)
        .ok_or_else(|| {
            PolicyError::field(
                field(),
                format!("IPv4-mapped network {network} needs a prefix of /96 or longer"),
            )
        })
}
fn validate_counts(config: &PolicyConfigSet, generation: u64) -> Result<(), PolicyError> {
    if generation == 0 {
        return Err(PolicyError::Generation);
    }
    PolicyError::check_count(|| "policies".into(), config.policies.len(), 1, 256)?;
    PolicyError::check_count(|| "upstreams".into(), config.upstreams.len(), 1, 32)?;
    PolicyError::check_count(|| "bindings".into(), config.bindings.len(), 0, 65536)?;
    PolicyError::check_count(
        || "allowed_clients".into(),
        config.allowed_clients.len(),
        1,
        256,
    )?;
    PolicyError::check_count(|| "assertions".into(), config.assertions.len(), 0, 10000)?;
    PolicyError::check_count(
        || "policies[*].temporary_exceptions (combined)".into(),
        config
            .policies
            .iter()
            .map(|p| p.temporary_exceptions.len())
            .sum::<usize>(),
        0,
        4096,
    )
}
type Upstreams = (HashMap<String, usize>, Vec<Arc<Forwarder>>);
fn compile_upstreams(config: &PolicyConfigSet) -> Result<Upstreams, PolicyError> {
    let mut profiles = HashMap::new();
    let mut upstreams = Vec::new();
    for (index, profile) in config.upstreams.iter().enumerate() {
        let field = |name: &str| format!("upstreams[{index}].{name}");
        validate_name(&profile.name, || field("name"))?;
        if profiles
            .insert(profile.name.clone(), upstreams.len())
            .is_some()
        {
            return Err(PolicyError::field(
                field("name"),
                format!("duplicate upstream profile {}", excerpt(&profile.name)),
            ));
        }
        if !(10..=10000).contains(&profile.timeout_ms) {
            return Err(PolicyError::field(
                field("timeout_ms"),
                format!("{} is outside 10 through 10000", profile.timeout_ms),
            ));
        }
        if let Some(address) = profile.addresses.iter().find(|address| {
            let ip = address.ip().to_canonical();
            address.port() == 0 || ip.is_unspecified() || ip.is_multicast()
        }) {
            return Err(PolicyError::field(
                field("addresses"),
                format!("{address} requires a nonzero port and a unicast address"),
            ));
        }
        upstreams.push(Arc::new(
            Forwarder::with_transport(
                profile.addresses.clone(),
                Duration::from_millis(profile.timeout_ms),
                &profile.transport,
            )
            .map_err(|error| PolicyError::field(field("transport"), error.to_string()))?,
        ));
    }
    Ok((profiles, upstreams))
}
fn compile_rewrites(
    policy: usize,
    input: &crate::PolicyConfig,
) -> Result<HashMap<String, Vec<Record>>, PolicyError> {
    let mut rewrites = HashMap::new();
    for (index, rewrite) in input.rewrites.iter().enumerate() {
        let field = |name: &str| format!("policies[{policy}].rewrites[{index}].{name}");
        let domain = rustwalld_dns_filter::normalize(&rewrite.domain)
            .map_err(|_| PolicyError::field(field("domain"), excerpt(&rewrite.domain)))?;
        if rewrites.contains_key(&domain) {
            return Err(PolicyError::field(
                field("domain"),
                format!("duplicate rewrite for {domain}"),
            ));
        }
        PolicyError::check_count(|| field("addresses"), rewrite.addresses.len(), 1, 32)?;
        if rewrite.ttl > 86400 {
            return Err(PolicyError::field(
                field("ttl"),
                format!("{} exceeds 86400 seconds", rewrite.ttl),
            ));
        }
        let name = Name::from_ascii(format!("{domain}."))
            .map_err(|_| PolicyError::field(field("domain"), excerpt(&domain)))?;
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
    Ok(rewrites)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::{Binding, FilterSource, PolicyConfig};

    fn error(config: PolicyConfigSet) -> String {
        PolicySnapshot::compile(config, 1).unwrap_err().to_string()
    }

    #[test]
    fn names_reject_blank_control_and_bidirectional_formatting() {
        for name in ["Work – 内部", "a", "lab-1 (east)", &"x".repeat(128)] {
            assert!(validate_name(name, || "name".into()).is_ok(), "{name}");
        }
        for name in [
            "",
            " ",
            "\t\n",
            "\u{3000}",
            "line\nbreak",
            "safe\u{202E}gpj.exe",
            "\u{2066}isolated\u{2069}",
            "mark\u{200F}",
            "arabic\u{061C}mark",
            &"x".repeat(129),
        ] {
            let mut config = PolicyConfigSet::default();
            config.policies.push(PolicyConfig {
                name: name.into(),
                upstream: "default".into(),
                lists: vec![],
                rewrites: vec![],
                temporary_exceptions: vec![],
            });
            let message = error(config);
            assert!(message.contains("policies[1].name"), "{message}");
            // Diagnostics escape the offending text instead of rendering it.
            assert!(!message.contains('\u{202E}') && !message.contains('\n'));
            assert!(message.len() < 256, "{message}");
        }
    }

    #[test]
    fn failures_name_the_field_index_and_bounded_value() {
        let config = PolicyConfigSet::default();
        assert_eq!(
            PolicySnapshot::compile(config.clone(), 0)
                .unwrap_err()
                .to_string(),
            "invalid configuration: generation must be nonzero"
        );
        let mut many = config.clone();
        many.allowed_clients.clear();
        assert_eq!(
            error(many),
            "invalid configuration: allowed_clients has 0 entries; expected 1 through 256"
        );
        let mut timeout = config.clone();
        timeout.upstreams[0].timeout_ms = 5;
        assert_eq!(
            error(timeout),
            "invalid configuration: upstreams[0].timeout_ms: 5 is outside 10 through 10000"
        );
        let mut unknown = config.clone();
        unknown.policies[0].upstream = format!("missing{}", "x".repeat(1000));
        let message = error(unknown);
        assert!(message.starts_with(
            "invalid configuration: policies[0].upstream: unknown upstream profile \"missingxxx"
        ));
        assert!(message.len() < 200, "{message}");
        let mut binding = config.clone();
        binding.bindings = vec![
            Binding {
                network: "127.0.0.1/32".parse().unwrap(),
                policy: "default".into(),
                name: "one".into(),
                metadata: None,
            };
            2
        ];
        assert_eq!(
            error(binding),
            "invalid configuration: bindings[1].network: duplicate client network 127.0.0.1/32"
        );
        let mut source = config.clone();
        source.policies[0]
            .lists
            .push(rustwalld_dns_filter::ListInput {
                name: "remote".into(),
                action: rustwalld_dns_filter::Action::Block,
                rules: "ads.test".into(),
            });
        source.filter_sources = vec![FilterSource {
            policy: "default".into(),
            list: "remote".into(),
            url: "https://lists.test/a".into(),
            bootstrap_ips: vec![
                "192.0.2.1".parse().unwrap(),
                "::ffff:192.0.2.1".parse().unwrap(),
            ],
            ca_pem: None,
            download: None,
            refresh_interval_secs: None,
        }];
        assert_eq!(
            error(source),
            "invalid configuration: filter_sources[0].bootstrap_ips: ::ffff:192.0.2.1 is listed more than once"
        );
    }

    #[test]
    fn ipv4_mapped_client_networks_match_their_ipv4_clients() {
        let mut config = PolicyConfigSet {
            allowed_clients: vec![
                "::ffff:192.0.2.0/120".parse().unwrap(),
                "127.0.0.1/32".parse().unwrap(),
            ],
            ..Default::default()
        };
        config.policies.push(PolicyConfig {
            name: "lan".into(),
            upstream: "default".into(),
            lists: vec![],
            rewrites: vec![],
            temporary_exceptions: vec![],
        });
        config.bindings = vec![Binding {
            network: "::ffff:10.9.9.9/104".parse().unwrap(),
            policy: "lan".into(),
            name: "mapped".into(),
            metadata: None,
        }];
        let snapshot = PolicySnapshot::compile(config.clone(), 1).unwrap();
        for client in ["10.1.2.3", "::ffff:10.1.2.3"] {
            let selected = snapshot.select(client.parse().unwrap());
            assert_eq!(selected.policy.name(), "lan", "{client}");
            assert_eq!(selected.network.unwrap().to_string(), "10.0.0.0/8");
        }
        for client in ["192.0.2.7", "::ffff:192.0.2.7"] {
            assert!(snapshot.permits(client.parse().unwrap()), "{client}");
        }
        assert!(!snapshot.permits("192.0.3.1".parse().unwrap()));
        assert_eq!(
            snapshot.config().allowed_clients[0].to_string(),
            "192.0.2.0/24"
        );
        let mut duplicate = config.clone();
        duplicate.bindings.push(Binding {
            network: "10.0.0.0/8".parse().unwrap(),
            name: "plain".into(),
            ..duplicate.bindings[0].clone()
        });
        assert_eq!(
            error(duplicate),
            "invalid configuration: bindings[1].network: duplicate client network 10.0.0.0/8"
        );
        let mut short = config.clone();
        short.bindings[0].network = "::ffff:10.0.0.0/95".parse().unwrap();
        assert!(
            error(short)
                .starts_with("invalid configuration: bindings[0].network: IPv4-mapped network")
        );
        let mut short = config;
        short.allowed_clients[0] = "::ffff:0.0.0.0/80".parse().unwrap();
        assert!(error(short).contains("allowed_clients[0]"));
    }

    #[test]
    fn upstream_addresses_are_judged_by_their_canonical_ip() {
        for address in [
            "[::ffff:0.0.0.0]:53",
            "[::ffff:224.0.0.1]:53",
            "[ff02::1]:53",
            "127.0.0.1:0",
        ] {
            let mut config = PolicyConfigSet::default();
            config.upstreams[0].addresses = vec![address.parse().unwrap()];
            assert!(
                error(config).contains("upstreams[0].addresses"),
                "{address}"
            );
        }
        let mut config = PolicyConfigSet::default();
        config.upstreams[0].addresses = vec!["[::ffff:127.0.0.1]:53".parse().unwrap()];
        assert!(PolicySnapshot::compile(config, 1).is_ok());
    }
}
