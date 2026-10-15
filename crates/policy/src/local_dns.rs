//! Typed local DNS and suffix routes, compiled before publication.
use crate::{PolicyConfig, PolicyError, rewrite::LocalAnswers};
use hickory_proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
use hickory_proto::rr::{
    Name, RData, Record, RecordType,
    rdata::{A, AAAA, CNAME, HTTPS, MX, PTR, SRV, SVCB, TXT},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, Ipv6Addr},
};
/// A local record, including its original owner and TTL.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalRecord {
    /// Owner name; all data types except CNAME/PASSTHROUGH accept *. descendants.
    pub domain: String,
    /// Cache lifetime, 0..=86400 seconds; ignored for passthrough directives.
    #[serde(default = "ttl")]
    pub ttl: u32,
    /// Type-specific record data.
    pub data: LocalData,
}
fn ttl() -> u32 {
    60
}
/// Address family for an exact rewrite passthrough directive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AddressFamily {
    /// IPv4 questions.
    A,
    /// IPv6 questions.
    Aaaa,
}
impl AddressFamily {
    pub(crate) fn bit(self) -> u8 {
        match self {
            Self::A => 1,
            Self::Aaaa => 2,
        }
    }
}
/// Supported service parameters, compiled before publication; not raw wire data.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ServiceParams {
    /// Explicit endpoint port, including zero. None keeps the client's original service port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}
impl<'de> Deserialize<'de> for ServiceParams {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ParamsVisitor;
        impl<'de> serde::de::Visitor<'de> for ParamsVisitor {
            type Value = ServiceParams;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an object containing supported service parameters")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                map: M,
            ) -> Result<Self::Value, M::Error> {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Fields {
                    #[serde(default)]
                    port: Option<u16>,
                }
                let fields =
                    Fields::deserialize(serde::de::value::MapAccessDeserializer::new(map))?;
                Ok(ServiceParams { port: fields.port })
            }
        }
        deserializer.deserialize_map(ParamsVisitor)
    }
}
impl ServiceParams {
    fn is_empty(&self) -> bool {
        self.port.is_none()
    }
}
/// Supported local records and exact rewrite directives, not an authoritative zone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "UPPERCASE", deny_unknown_fields)]
pub enum LocalData {
    /// Resume ordinary filtering/forwarding for this family; never an allow rule.
    Passthrough {
        /// Question family whose local rewrite is suppressed.
        family: AddressFamily,
    },
    /// IPv4 address.
    A {
        /// Address returned.
        address: Ipv4Addr,
    },
    /// IPv6 address.
    Aaaa {
        /// Address returned.
        address: Ipv6Addr,
    },
    /// Alias; chains/loops are validated during compilation.
    Cname {
        /// Local or externally resolved target.
        target: String,
    },
    /// Reverse lookup target.
    Ptr {
        /// Hostname returned.
        target: String,
    },
    /// Text record, at most 4096 bytes, split into DNS character strings.
    Txt {
        /// Text returned.
        text: String,
    },
    /// Mail exchange.
    Mx {
        /// Lower values preferred.
        preference: u16,
        /// Exchange hostname.
        exchange: String,
    },
    /// Service discovery record.
    Srv {
        /// Service priority.
        priority: u16,
        /// Relative weight.
        weight: u16,
        /// Service port.
        port: u16,
        /// Service hostname.
        target: String,
    },
    /// HTTPS service record; does not enable a TLS listener.
    Https {
        /// Zero aliases this service; 1..=65535 describes an endpoint.
        priority: u16,
        /// Hostname; '.' is advisory unavailability in AliasMode, record owner otherwise.
        target: String,
        /// Optional typed ServiceMode parameters; empty for AliasMode.
        #[serde(default, skip_serializing_if = "ServiceParams::is_empty")]
        params: ServiceParams,
    },
    /// SVCB service record.
    Svcb {
        /// Zero aliases this service; 1..=65535 describes an endpoint.
        priority: u16,
        /// Hostname; '.' is advisory unavailability in AliasMode, record owner otherwise.
        target: String,
        /// Optional typed ServiceMode parameters; empty for AliasMode.
        #[serde(default, skip_serializing_if = "ServiceParams::is_empty")]
        params: ServiceParams,
    },
}
/// Domain-specific upstream inside a client policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainRoute {
    /// Apex and descendant names routed here.
    pub domain: String,
    /// Named upstream profile.
    pub upstream: String,
}
/// Local policy-block reply mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockMode {
    /// No such name (default).
    #[default]
    NxDomain,
    /// NOERROR with no records.
    NoData,
    /// Unspecified IPv4/IPv6 for A/AAAA, NODATA for other types.
    NullIp,
}
impl BlockMode {
    pub(crate) fn is_default(&self) -> bool {
        *self == Self::NxDomain
    }
}
fn normalized(value: &str, field: String) -> Result<(String, Name), PolicyError> {
    let domain = rustwalld_dns_filter::normalize(value)
        .map_err(|_| PolicyError::field(field.clone(), "invalid DNS name"))?;
    let name = Name::from_ascii(format!("{domain}."))
        .map_err(|_| PolicyError::field(field, "invalid DNS name"))?;
    Ok((domain, name))
}
pub(crate) fn normalized_owner(value: &str, field: String) -> Result<(String, Name), PolicyError> {
    let Some(suffix) = value.strip_prefix("*.") else {
        return normalized(value, field);
    };
    let (suffix, _) = normalized(suffix, field.clone())?;
    let owner = format!("*.{suffix}");
    let name = Name::from_ascii(format!("{owner}."))
        .map_err(|_| PolicyError::field(field, "invalid wildcard DNS name"))?;
    Ok((owner, name))
}
pub(crate) fn compile_routes(
    policy: usize,
    routes: &[DomainRoute],
    profiles: &HashMap<String, usize>,
) -> Result<Vec<(Name, usize)>, PolicyError> {
    PolicyError::check_count(
        || format!("policies[{policy}].routes"),
        routes.len(),
        0,
        256,
    )?;
    let mut result = Vec::new();
    let mut seen = HashSet::new();
    for (index, route) in routes.iter().enumerate() {
        let field = format!("policies[{policy}].routes[{index}]");
        let (domain, name) = normalized(&route.domain, format!("{field}.domain"))?;
        if !seen.insert(domain) {
            return Err(PolicyError::field(field, "duplicate route"));
        }
        let upstream = profiles
            .get(&route.upstream)
            .ok_or_else(|| PolicyError::field(format!("{field}.upstream"), "unknown profile"))?;
        result.push((name, *upstream));
    }
    result.sort_by_key(|(name, _)| std::cmp::Reverse(name.num_labels()));
    Ok(result)
}
pub(crate) fn compile_records(
    policy: usize,
    input: &PolicyConfig,
    records: &mut HashMap<String, LocalAnswers>,
) -> Result<(), PolicyError> {
    PolicyError::check_count(
        || format!("policies[{policy}].dns_records"),
        input.dns_records.len() + input.rewrites.len(),
        0,
        10000,
    )?;
    let legacy: HashSet<_> = records.keys().cloned().collect();
    for (index, record) in input.dns_records.iter().enumerate() {
        let field = format!("policies[{policy}].dns_records[{index}]");
        let (domain, name) = normalized_owner(&record.domain, format!("{field}.domain"))?;
        if name.is_wildcard()
            && !matches!(
                record.data,
                LocalData::A { .. }
                    | LocalData::Aaaa { .. }
                    | LocalData::Txt { .. }
                    | LocalData::Ptr { .. }
                    | LocalData::Mx { .. }
                    | LocalData::Srv { .. }
                    | LocalData::Https { .. }
                    | LocalData::Svcb { .. }
            )
        {
            return Err(PolicyError::field(
                field,
                "wildcard owners support only A/AAAA/TXT/PTR/MX/SRV/HTTPS/SVCB records",
            ));
        }
        if legacy.contains(&domain) && !matches!(record.data, LocalData::Passthrough { .. }) {
            return Err(PolicyError::field(
                field,
                "owner also exists in legacy rewrites",
            ));
        }
        if record.ttl > 86400 {
            return Err(PolicyError::field(
                format!("{field}.ttl"),
                "exceeds one day",
            ));
        }
        if let LocalData::Passthrough { family } = record.data {
            let answers = records.entry(domain).or_default();
            let bit = family.bit();
            if answers.passthrough & bit != 0 {
                return Err(PolicyError::field(field, "duplicate family passthrough"));
            }
            answers.passthrough |= bit;
            continue;
        }
        let target =
            |value: &str| normalized(value, format!("{field}.data.target")).map(|(_, name)| name);
        let data = match &record.data {
            LocalData::Passthrough { .. } => {
                return Err(PolicyError::field(field, "invalid passthrough record"));
            }
            LocalData::A { address } => RData::A(A(*address)),
            LocalData::Aaaa { address } => RData::AAAA(AAAA(*address)),
            LocalData::Cname { target: alias } => RData::CNAME(CNAME(target(alias)?)),
            LocalData::Ptr { target: host } => RData::PTR(PTR(target(host)?)),
            LocalData::Txt { text } => {
                if text.len() > 4096 {
                    return Err(PolicyError::field(field, "TXT exceeds 4096 bytes"));
                }
                let chunks = if text.is_empty() {
                    vec![&b""[..]]
                } else {
                    text.as_bytes().chunks(255).collect()
                };
                RData::TXT(TXT::from_bytes(chunks))
            }
            LocalData::Mx {
                preference,
                exchange,
            } => {
                if exchange == "." && *preference != 0 {
                    return Err(PolicyError::field(
                        field,
                        "null MX requires preference zero",
                    ));
                }
                RData::MX(MX::new(
                    *preference,
                    if exchange == "." {
                        Name::root()
                    } else {
                        target(exchange)?
                    },
                ))
            }
            LocalData::Srv {
                priority,
                weight,
                port,
                target: host,
            } => RData::SRV(SRV::new(
                *priority,
                *weight,
                *port,
                if host == "." {
                    Name::root()
                } else {
                    target(host)?
                },
            )),
            LocalData::Https {
                priority,
                target: host,
                params,
            }
            | LocalData::Svcb {
                priority,
                target: host,
                params,
            } => {
                if *priority == 0 && !params.is_empty() {
                    return Err(PolicyError::field(
                        field,
                        "HTTPS/SVCB AliasMode does not support service parameters; remove the port or use priority 1..65535",
                    ));
                }
                let value = SVCB::new(
                    *priority,
                    if host == "." {
                        Name::root()
                    } else {
                        target(host)?
                    },
                    params
                        .port
                        .map(|port| (SvcParamKey::Port, SvcParamValue::Port(port)))
                        .into_iter()
                        .collect(),
                );
                if *priority == 0
                    && (value.target_name == name
                        || (name.is_wildcard()
                            && name.base_name().num_labels() < value.target_name.num_labels()
                            && name.base_name().zone_of(&value.target_name)))
                {
                    return Err(PolicyError::field(
                        field,
                        "HTTPS/SVCB AliasMode target cannot alias its own exact or synthesized wildcard owner",
                    ));
                }
                if matches!(record.data, LocalData::Https { .. }) {
                    RData::HTTPS(HTTPS(value))
                } else {
                    RData::SVCB(value)
                }
            }
        };
        let answers = records.entry(domain).or_default();
        let cname = matches!(data, RData::CNAME(_));
        if (!cname && !answers.cname.is_empty())
            || (cname
                && (!answers.a.is_empty() || !answers.aaaa.is_empty() || !answers.other.is_empty()))
        {
            return Err(PolicyError::field(
                field,
                "CNAME cannot coexist with other records",
            ));
        }
        let list = match data.record_type() {
            RecordType::A => &mut answers.a,
            RecordType::AAAA => &mut answers.aaaa,
            RecordType::CNAME => &mut answers.cname,
            kind => answers.other.entry(kind).or_default(),
        };
        if !list.is_empty()
            && (is_service_alias(&data) || list.iter().any(|record| is_service_alias(&record.data)))
        {
            return Err(PolicyError::field(
                field,
                "HTTPS/SVCB AliasMode requires one record per owner/type; multiple aliases or mixed modes are unsupported",
            ));
        }
        if data.record_type() == RecordType::MX
            && !list.is_empty()
            && (matches!(&data,RData::MX(mx) if mx.exchange.is_root())
                || list
                    .iter()
                    .any(|record| matches!(&record.data,RData::MX(mx) if mx.exchange.is_root())))
        {
            return Err(PolicyError::field(
                field,
                "null MX cannot coexist with another MX",
            ));
        }
        if list.len() >= 32
            || list
                .iter()
                .any(|existing| existing.data == data || existing.ttl != record.ttl)
            || (cname && !list.is_empty())
        {
            return Err(PolicyError::field(
                field,
                "duplicate/conflicting record, mixed RRset TTL or more than 32 records",
            ));
        }
        list.push(Record::from_rdata(name, record.ttl, data));
    }
    if records
        .values()
        .any(|answer| answer.passthrough != 0 && !answer.cname.is_empty())
    {
        return Err(PolicyError::field(
            format!("policies[{policy}].dns_records"),
            "CNAME owner cannot also have a passthrough directive",
        ));
    }
    for (owner, answer) in records.iter() {
        if owner.starts_with("*.") && (answer.a.len() > 1 || answer.aaaa.len() > 1) {
            return Err(PolicyError::field(
                format!("policies[{policy}].dns_records"),
                "wildcard owners allow one address per family; source selection of multiple addresses is ambiguous",
            ));
        }
    }
    let wildcard_suffixes: HashSet<_> = records
        .keys()
        .filter_map(|owner| owner.strip_prefix("*."))
        .map(str::to_owned)
        .collect();
    let aliases: Vec<_> = records
        .iter()
        .filter(|(_, value)| !value.cname.is_empty())
        .map(|(name, _)| name.clone())
        .collect();
    for owner in aliases {
        let field = format!("policies[{policy}].dns_records");
        let mut current = owner.clone();
        let mut visited = HashSet::new();
        let mut chain = Vec::new();
        let (a, aaaa, other, forward, passthrough) = loop {
            if !chain.is_empty()
                && crate::rewrite::suffixes(&current)
                    .any(|suffix| wildcard_suffixes.contains(suffix))
            {
                return Err(PolicyError::field(
                    field,
                    "CNAME chain targets under wildcard coverage are not supported",
                ));
            }
            if !visited.insert(current.clone()) || chain.len() > 16 {
                return Err(PolicyError::field(
                    field,
                    "local CNAME loop or chain longer than 16",
                ));
            }
            let Some(answer) = records.get(&current) else {
                let (_, name) = normalized(&current, field.clone())?;
                break (Vec::new(), Vec::new(), HashMap::new(), Some(name), 0);
            };
            if let Some(alias) = answer.cname.first() {
                let RData::CNAME(target) = &alias.data else {
                    return Err(PolicyError::field(field, "invalid alias"));
                };
                chain.push(alias.clone());
                current = target
                    .0
                    .to_ascii()
                    .trim_end_matches('.')
                    .to_ascii_lowercase();
                continue;
            }
            break (
                answer.a.clone(),
                answer.aaaa.clone(),
                answer.other.clone(),
                None,
                answer.passthrough,
            );
        };
        let answer = records
            .get_mut(&owner)
            .ok_or_else(|| PolicyError::field(field, "missing alias owner"))?;
        answer.a = chain.iter().cloned().chain(a).collect();
        answer.aaaa = chain.iter().cloned().chain(aaaa).collect();
        answer.other = other
            .into_iter()
            .map(|(kind, values)| (kind, chain.iter().cloned().chain(values).collect()))
            .collect();
        answer.chain = chain;
        answer.forward = forward;
        answer.passthrough = passthrough;
    }
    Ok(())
}

fn is_service_alias(data: &RData) -> bool {
    match data {
        RData::HTTPS(value) => value.svc_priority == 0,
        RData::SVCB(value) => value.svc_priority == 0,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::{PolicyConfigSet, PolicySnapshot};
    #[test]
    fn null_mx_and_unavailable_service_targets_have_root_wire_names() {
        let mut config = PolicyConfigSet::default();
        config.policies[0].dns_records = vec![
            LocalRecord {
                domain: "nomail.test".into(),
                ttl: 60,
                data: LocalData::Mx {
                    preference: 0,
                    exchange: ".".into(),
                },
            },
            LocalRecord {
                domain: "_service._tcp.home.arpa".into(),
                ttl: 60,
                data: LocalData::Srv {
                    priority: 0,
                    weight: 0,
                    port: 0,
                    target: ".".into(),
                },
            },
        ];
        let snapshot = PolicySnapshot::compile(config.clone(), 1).unwrap();
        assert!(
            matches!(&snapshot.policies()[0].rewrite("nomail.test",RecordType::MX).unwrap()[0].data,RData::MX(mx) if mx.exchange.is_root())
        );
        assert!(
            matches!(&snapshot.policies()[0].rewrite("_service._tcp.home.arpa",RecordType::SRV).unwrap()[0].data,RData::SRV(srv) if srv.target.is_root())
        );
        config.policies[0].dns_records.push(LocalRecord {
            domain: "nomail.test".into(),
            ttl: 60,
            data: LocalData::Mx {
                preference: 10,
                exchange: "mail.test".into(),
            },
        });
        assert!(PolicySnapshot::compile(config.clone(), 1).is_err());
        config.policies[0].dns_records.pop();
        config.policies[0].dns_records[0].data = LocalData::Mx {
            preference: 10,
            exchange: ".".into(),
        };
        assert!(PolicySnapshot::compile(config, 1).is_err());
    }
    #[test]
    fn records_reject_loops_conflicts_and_oversized_data_and_route_by_dns_labels() {
        let mut config = PolicyConfigSet::default();
        config.policies[0].dns_records = vec![LocalRecord {
            domain: "one.test".into(),
            ttl: 60,
            data: LocalData::Cname {
                target: "one.test".into(),
            },
        }];
        assert!(PolicySnapshot::compile(config.clone(), 1).is_err());
        config.policies[0].dns_records[0].data = LocalData::A {
            address: "192.0.2.1".parse().unwrap(),
        };
        config.policies[0].dns_records.push(LocalRecord {
            domain: "one.test".into(),
            ttl: 60,
            data: LocalData::Cname {
                target: "other.test".into(),
            },
        });
        assert!(PolicySnapshot::compile(config.clone(), 1).is_err());
        config.policies[0].dns_records.pop();
        config.policies[0].dns_records[0].data = LocalData::Txt {
            text: "x".repeat(4097),
        };
        assert!(PolicySnapshot::compile(config.clone(), 1).is_err());
        config.policies[0].dns_records.clear();
        let mut upstream = config.upstreams[0].clone();
        upstream.name = "private".into();
        config.upstreams.push(upstream);
        config.policies[0].routes = vec![DomainRoute {
            domain: "home.arpa".into(),
            upstream: "private".into(),
        }];
        let snapshot = PolicySnapshot::compile(config.clone(), 1).unwrap();
        let policy = &snapshot.policies()[0];
        assert_eq!(
            policy.upstream_for(&Name::from_ascii("nas.home.arpa").unwrap()),
            1
        );
        assert_eq!(
            policy.upstream_for(&Name::from_ascii(r"nas\.home.arpa").unwrap()),
            0
        );
        assert_eq!(
            policy.upstream_for(&Name::from_ascii("nothome.arpa").unwrap()),
            0
        );
        let duplicate = config.policies[0].routes[0].clone();
        config.policies[0].routes.push(duplicate);
        assert!(PolicySnapshot::compile(config, 1).is_err());
    }
}
