//! Offline resolver translation. Bootstrap DNS servers are not endpoint pins.
use super::{Report, Severity, literal_address};
use rustwalld_dns_policy::{DomainRoute, UpstreamProfile, UpstreamTransport};
use std::collections::BTreeMap;

pub(super) struct Imported {
    pub default: String,
    pub has_defaults: bool,
    pub profiles: Vec<UpstreamProfile>,
    pub routes: Vec<DomainRoute>,
}
pub(super) fn translate(
    values: &[String],
    base: &[UpstreamProfile],
    field: &str,
    report: &mut Report,
) -> Option<Imported> {
    if values
        .iter()
        .all(|value| value.trim().is_empty() || value.trim().starts_with('#'))
    {
        return None;
    }
    match checked(values, base, field, 32) {
        Ok(imported) => {
            report.issue(field,Severity::Warning,"Imported resolver addresses use ordered destination failover. Encrypted endpoints reuse matching destination pins/trust; source bootstrap DNS is never queried. Review resolver selection before activation.");
            Some(imported)
        }
        Err(message) => {
            report.issue(field, Severity::Blocker, message);
            None
        }
    }
}
pub(super) fn checked(
    values: &[String],
    base: &[UpstreamProfile],
    label: &str,
    max_profiles: usize,
) -> Result<Imported, String> {
    if values.len() > 256 {
        return Err("At most 256 upstream declarations can be imported".into());
    }
    let first = base
        .first()
        .ok_or("Destination resolver profile is missing")?;
    let mut defaults = Vec::new();
    let mut routes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for value in values {
        let value = value.trim();
        if value.is_empty() || value.starts_with('#') {
            continue;
        }
        if literal_address(value).is_some() {
            defaults.push(value.to_owned());
            continue;
        }
        if let Some(value) = value.strip_prefix('[') {
            let (domains, endpoints) = value
                .split_once(']')
                .ok_or("Invalid domain-specific upstream declaration")?;
            let domains = domains
                .strip_prefix('/')
                .and_then(|value| value.strip_suffix('/'))
                .ok_or("Invalid domain-specific upstream declaration")?;
            let endpoints: Vec<_> = endpoints
                .split_whitespace()
                .map(ToOwned::to_owned)
                .collect();
            if endpoints.is_empty() {
                return Err("Domain-specific upstream has no resolver".into());
            }
            for domain in domains.split('/') {
                // No wildcard, unqualified-only or default-resolver escape:
                // those have different selection semantics from suffix routes.
                if domain.is_empty()
                    || domain.len() > 253
                    || domain.contains('*')
                    || domain.contains('#')
                    || domain.starts_with('.')
                    || domain.ends_with('.')
                    || domain.split('.').any(|part| {
                        part.is_empty()
                            || part.len() > 63
                            || part.starts_with('-')
                            || part.ends_with('-')
                            || !part.bytes().all(|byte| {
                                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
                            })
                    })
                {
                    return Err("Wildcard/unqualified/invalid upstream domains require an explicit equivalent".into());
                }
                let domain = domain.to_ascii_lowercase();
                if routes.len() >= 256 && !routes.contains_key(&domain) {
                    return Err("Too many imported domain routes".into());
                }
                routes.entry(domain).or_default().extend(endpoints.clone());
            }
        } else {
            defaults.push(value.to_owned());
        }
    }
    let mut imported = Imported {
        default: first.name.clone(),
        has_defaults: !defaults.is_empty(),
        profiles: base.to_vec(),
        routes: Vec::new(),
    };
    if !defaults.is_empty() {
        let name = format!("{label}/default");
        insert(
            &mut imported.profiles,
            profile(&defaults, base, name.clone())?,
            max_profiles,
        )?;
        imported.default = name;
    }
    for (index, (domain, values)) in routes.into_iter().enumerate() {
        let name = format!("{label}/route-{index}");
        insert(
            &mut imported.profiles,
            profile(&values, base, name.clone())?,
            max_profiles,
        )?;
        imported.routes.push(DomainRoute {
            domain,
            upstream: name,
        });
    }
    Ok(imported)
}
fn insert(
    profiles: &mut Vec<UpstreamProfile>,
    profile: UpstreamProfile,
    max_profiles: usize,
) -> Result<(), String> {
    // Destination names may overlap imported names on a repeated migration.
    if let Some(existing) = profiles
        .iter_mut()
        .find(|existing| existing.name == profile.name)
    {
        *existing = profile;
    } else if profiles.len() >= max_profiles {
        return Err(format!("Imported resolver profiles exceed {max_profiles}"));
    } else {
        profiles.push(profile);
    }
    Ok(())
}
fn profile(
    values: &[String],
    base: &[UpstreamProfile],
    name: String,
) -> Result<UpstreamProfile, String> {
    let mut result: Option<UpstreamProfile> = None;
    for value in values {
        let mut next = endpoint(value, base)?;
        if let Some(result) = &mut result {
            if result.transport != next.transport || result.timeout_ms != next.timeout_ms {
                return Err("Mixed transports/identities/trust/deadlines in one upstream set need explicit destination profiles; no resolver was silently dropped".into());
            }
            for address in next.addresses {
                if !result.addresses.contains(&address) {
                    result.addresses.push(address);
                }
            }
            if result.addresses.len() > 8 {
                return Err("An imported resolver set exceeds eight pinned addresses".into());
            }
        } else {
            next.name = name.clone();
            result = Some(next);
        }
    }
    result.ok_or("Upstream set is empty".into())
}
fn endpoint(value: &str, base: &[UpstreamProfile]) -> Result<UpstreamProfile, String> {
    if let Some(address) = literal_address(value) {
        return Ok(UpstreamProfile {
            name: String::new(),
            addresses: vec![address],
            timeout_ms: 1500,
            transport: UpstreamTransport::Udp,
        });
    }
    let url = url::Url::parse(value)
        .map_err(|_| "Hostname/plain upstream needs explicit destination IP addresses")?;
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err("Upstream URL credentials/fragments are not accepted".into());
    }
    let host = url.host_str().ok_or("Upstream identity is missing")?;
    if host.parse::<std::net::IpAddr>().is_ok() || matches!(url.host(), Some(url::Host::Ipv6(_))) {
        return Err("Encrypted IP identities require a destination DNS authentication name; no certificate check was weakened".into());
    }
    let (port, path) = match url.scheme() {
        "tls" if matches!(url.path(), "" | "/") && url.query().is_none() => {
            (url.port().unwrap_or(853), None)
        }
        "https" => {
            let mut path = url.path().to_owned();
            if let Some(query) = url.query() {
                path.push('?');
                path.push_str(query);
            }
            (url.port().unwrap_or(443), Some(path))
        }
        _ => return Err(
            "Unsupported upstream transport or TLS URL path; no plaintext downgrade was performed"
                .into(),
        ),
    };
    let matching: Vec<_> = base
        .iter()
        .filter(|profile| {
            let identity = match (&profile.transport, &path) {
                (UpstreamTransport::Tls { server_name, .. }, None) => {
                    server_name.eq_ignore_ascii_case(host)
                }
                (
                    UpstreamTransport::Https {
                        server_name,
                        path: configured,
                        ..
                    },
                    Some(path),
                ) => server_name.eq_ignore_ascii_case(host) && configured == path,
                _ => false,
            };
            identity
                && !profile.addresses.is_empty()
                && profile
                    .addresses
                    .iter()
                    .all(|address| address.port() == port)
        })
        .collect();
    let Some(profile) = matching.first() else {
        return Err("Encrypted upstream needs a matching destination profile with explicit endpoint IPs, identity, port and trust. Source bootstrap servers were not used as endpoint addresses".into());
    };
    if matching.iter().skip(1).any(|other| {
        other.transport != profile.transport
            || other.addresses != profile.addresses
            || other.timeout_ms != profile.timeout_ms
    }) {
        return Err("Multiple destination profiles match this encrypted endpoint with different pins/trust/deadlines; choose one explicitly".into());
    }
    Ok((*profile).clone())
}
