//! Restricted source response values, interpreted only during offline migration.
use rustwalld_dns_policy::{LocalData, ServiceParams};
use std::net::IpAddr;

#[derive(PartialEq, Eq)]
pub(super) enum Response {
    Address(IpAddr),
    Txt(String),
    // Source exceptions compare case-sensitive FQDN strings. Native DNS names
    // have a separate canonical identity; do not conflate those comparisons.
    Ptr {
        source_fqdn: String,
        target: String,
    },
    Mx {
        preference: u16,
        exchange: String,
    },
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Https {
        priority: u16,
        target: String,
        port: Option<u16>,
    },
    Svcb {
        priority: u16,
        target: String,
        port: Option<u16>,
    },
}
impl Response {
    pub(super) fn parse(value: &str, exception: bool) -> Result<Self, &'static str> {
        if !value.contains(';') {
            return address(value).map(Self::Address);
        }
        let mut parts = value.splitn(3, ';');
        let (Some("NOERROR"), Some(kind), Some(value)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(
                "Rewrite responses require uppercase NOERROR and a supported type/value triple.",
            );
        };
        match kind {
            "A" | "AAAA" => {
                let ip = address(value)?;
                if ip.is_ipv4() != (kind == "A") {
                    return Err("Rewrite address family does not match its declared RR type.");
                }
                Ok(Self::Address(ip))
            }
            "TXT" => {
                if value.len() > 255
                    || value.trim() != value
                    || value.bytes().any(|byte| {
                        !(b' '..=b'~').contains(&byte)
                            || matches!(byte, b',' | b'\\' | b'\'' | b'"' | b'$')
                    })
                {
                    return Err(
                        "TXT import supports one 0..255-byte printable ASCII string without edge whitespace, commas, quotes, backslashes or dollar signs; escaping and modifiers require review.",
                    );
                }
                Ok(Self::Txt(value.to_owned()))
            }
            "PTR" => {
                let name = value.strip_suffix('.').unwrap_or(value);
                let target = hostname(name)?;
                Ok(Self::Ptr {
                    source_fqdn: format!("{name}."),
                    target,
                })
            }
            "MX" | "SRV" if exception => Err(
                "MX/SRV value exceptions require source-comparison review; no extracted pattern rewrites were activated.",
            ),
            "MX" => {
                let (preference, exchange) = value.split_once(' ').ok_or("MX import requires exactly a decimal preference and ASCII hostname separated by one space.")?;
                Ok(Self::Mx {
                    preference: number(preference)?,
                    exchange: hostname(exchange)?,
                })
            }
            "SRV" => {
                let mut fields = value.split(' ');
                let (Some(priority), Some(weight), Some(port), Some(target), None) = (
                    fields.next(),
                    fields.next(),
                    fields.next(),
                    fields.next(),
                    fields.next(),
                ) else {
                    return Err(
                        "SRV import requires exactly decimal priority, weight, port and target separated by single spaces.",
                    );
                };
                Ok(Self::Srv {
                    priority: number(priority)?,
                    weight: number(weight)?,
                    port: number(port)?,
                    target: if target == "." {
                        ".".into()
                    } else {
                        hostname(target)?
                    },
                })
            }
            "HTTPS" | "SVCB" if exception => Err(
                "HTTPS/SVCB value exceptions require source-comparison review; no extracted pattern rewrites were activated.",
            ),
            "HTTPS" | "SVCB" => {
                let mut fields = value.split(' ');
                let (Some(priority), Some(target)) = (fields.next(), fields.next()) else {
                    return Err(
                        "HTTPS/SVCB import requires decimal priority, target and optional port=0..65535 separated by single spaces.",
                    );
                };
                let priority = number(priority)?;
                let port = match (fields.next(), fields.next()) {
                    (None, None) => None,
                    (Some(value), None) if value.starts_with("port=") => Some(number(&value[5..])?),
                    _ => {
                        return Err(
                            "HTTPS/SVCB parameters are unsupported except one unquoted port=0..65535 in ServiceMode.",
                        );
                    }
                };
                if priority == 0 && port.is_some() {
                    return Err(
                        "HTTPS/SVCB AliasMode does not support service parameters; no extracted pattern rewrites were activated.",
                    );
                }
                let target = if target == "." {
                    ".".into()
                } else {
                    hostname(target)?
                };
                Ok(if kind == "HTTPS" {
                    Self::Https {
                        priority,
                        target,
                        port,
                    }
                } else {
                    Self::Svcb {
                        priority,
                        target,
                        port,
                    }
                })
            }
            _ => Err(
                "Unsupported rewrite response type; only NOERROR A/AAAA/TXT/PTR/MX/SRV/HTTPS/SVCB triples are supported.",
            ),
        }
    }
    pub(super) fn is_address(&self) -> bool {
        matches!(self, Self::Address(_))
    }
    pub(super) fn alias_target(&self) -> Option<&str> {
        match self {
            Self::Https {
                priority: 0,
                target,
                ..
            }
            | Self::Svcb {
                priority: 0,
                target,
                ..
            } => Some(target),
            _ => None,
        }
    }
    pub(super) fn kind(&self) -> &'static str {
        match self {
            Self::Address(ip) if ip.is_ipv4() => "A",
            Self::Address(_) => "AAAA",
            Self::Txt(_) => "TXT",
            Self::Ptr { .. } => "PTR",
            Self::Mx { .. } => "MX",
            Self::Srv { .. } => "SRV",
            Self::Https { .. } => "HTTPS",
            Self::Svcb { .. } => "SVCB",
        }
    }
    pub(super) fn same_native_value(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Ptr { target: a, .. }, Self::Ptr { target: b, .. }) => a == b,
            _ => self == other,
        }
    }
    pub(super) fn local(&self) -> LocalData {
        match self {
            Self::Address(IpAddr::V4(address)) => LocalData::A { address: *address },
            Self::Address(IpAddr::V6(address)) => LocalData::Aaaa { address: *address },
            Self::Txt(text) => LocalData::Txt { text: text.clone() },
            Self::Ptr { target, .. } => LocalData::Ptr {
                target: target.clone(),
            },
            Self::Mx {
                preference,
                exchange,
            } => LocalData::Mx {
                preference: *preference,
                exchange: exchange.clone(),
            },
            Self::Srv {
                priority,
                weight,
                port,
                target,
            } => LocalData::Srv {
                priority: *priority,
                weight: *weight,
                port: *port,
                target: target.clone(),
            },
            Self::Https {
                priority,
                target,
                port,
            } => LocalData::Https {
                priority: *priority,
                target: target.clone(),
                params: ServiceParams { port: *port },
            },
            Self::Svcb {
                priority,
                target,
                port,
            } => LocalData::Svcb {
                priority: *priority,
                target: target.clone(),
                params: ServiceParams { port: *port },
            },
        }
    }
}
fn address(value: &str) -> Result<IpAddr, &'static str> {
    let ip:IpAddr = value.parse().map_err(|_|"Only literal IP shorthand or supported NOERROR type/value triples are imported; scopes, badfilter, aliases and response codes require review.")?;
    if matches!(ip,IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some()) {
        return Err("IPv4-mapped IPv6 rewrite values require explicit source family review.");
    }
    Ok(ip)
}
fn number(value: &str) -> Result<u16, &'static str> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("Rewrite numeric fields require unsigned decimal integers in 0..65535.");
    }
    value
        .parse()
        .map_err(|_| "Rewrite numeric fields require unsigned decimal integers in 0..65535.")
}
fn hostname(value: &str) -> Result<String, &'static str> {
    if value.is_empty()
        || value.len() > 253
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(
            "Rewrite targets require an ASCII hostname with alphanumeric/hyphen labels, without whitespace or a root dot (PTR also accepts one root dot; SRV/HTTPS/SVCB accept '.'); HTTPS/SVCB parameters are unsupported except a single ServiceMode port override.",
        );
    }
    rustwalld_dns_filter::normalize(value)
        .map_err(|_| "Rewrite target fails native DNS name normalization; no extracted pattern rewrites were activated.")
}
