//! Atomic offline client resolver overlay using original destination trust.
use super::{Report, Severity, upstreams};
use rustwalld_dns_policy::{DomainRoute, PolicyConfig, UpstreamProfile};
use std::collections::{HashMap, HashSet};

pub(super) fn translate(
    values: &[String],
    pins: &[UpstreamProfile],
    policy: &mut PolicyConfig,
    global: &PolicyConfig,
    index: usize,
    field: &str,
    report: &mut Report,
) {
    if values.len() > 256 {
        report.issue(field,Severity::Blocker,"At most 256 client upstream declarations can be imported; the complete inherited resolver selection was retained.");
        return;
    }
    if values
        .iter()
        .all(|value| value.trim().is_empty() || value.trim().starts_with('#'))
    {
        return;
    }
    let label = format!("adguard/client-{index}/upstreams");
    let result = upstreams::checked(values, pins, &label, 289)
        .and_then(|imported| overlay(imported, &report.config.upstreams, global));
    match result {
        Ok((profiles,default,routes)) => {
            report.config.upstreams=profiles;
            policy.upstream=default;
            policy.routes=routes;
            report.issue(field,Severity::Warning,"Imported client resolvers use ordered destination failover and bounded resolver-identity cache sharing. Source client cache enable/size and resolver selection modes are not translated; review operational differences before activation.");
        }
        Err(message) => report.issue(field,Severity::Blocker,format!("{message}. The complete inherited resolver selection was retained; no partial client resolver set was applied.")),
    }
}
fn overlay(
    imported: upstreams::Imported,
    registry: &[UpstreamProfile],
    global: &PolicyConfig,
) -> Result<(Vec<UpstreamProfile>, String, Vec<DomainRoute>), String> {
    let mut needed: HashSet<&str> = imported
        .routes
        .iter()
        .map(|route| route.upstream.as_str())
        .collect();
    if imported.has_defaults {
        needed.insert(&imported.default);
    }
    let mut profiles = registry.to_vec();
    let mut aliases = HashMap::new();
    for mut candidate in imported
        .profiles
        .into_iter()
        .filter(|profile| needed.contains(profile.name.as_str()))
    {
        let requested = candidate.name.clone();
        let resolved = if let Some(shared) = profiles.iter().find(|profile| {
            profile.addresses == candidate.addresses
                && profile.timeout_ms == candidate.timeout_ms
                && profile.transport == candidate.transport
        }) {
            shared.name.clone()
        } else {
            if profiles.len() >= 32 {
                return Err(
                    "Imported client resolver profiles exceed 32 after identical-profile sharing"
                        .into(),
                );
            }
            let mut name = requested.clone();
            for suffix in 1..=33 {
                if !profiles.iter().any(|profile| profile.name == name) {
                    break;
                }
                name = format!("{requested}-{suffix}");
            }
            candidate.name = name.clone();
            profiles.push(candidate);
            name
        };
        aliases.insert(requested, resolved);
    }
    let default = if imported.has_defaults {
        aliases
            .get(&imported.default)
            .cloned()
            .ok_or("Imported client default profile is missing")?
    } else {
        global.upstream.clone()
    };
    let custom: Vec<DomainRoute> = imported
        .routes
        .into_iter()
        .map(|route| {
            let upstream = aliases
                .get(&route.upstream)
                .cloned()
                .ok_or("Imported client route profile is missing")?;
            Ok(DomainRoute {
                domain: route.domain,
                upstream,
            })
        })
        .collect::<Result<_, String>>()?;
    let mut routes = if imported.has_defaults {
        Vec::new()
    } else {
        global
            .routes
            .iter()
            .filter(|route| !custom.iter().any(|own| covers(&own.domain, &route.domain)))
            .cloned()
            .collect()
    };
    routes.extend(custom);
    if routes.len() > 256 {
        return Err("Imported client route overlay exceeds 256 routes".into());
    }
    Ok((profiles, default, routes))
}
fn covers(parent: &str, child: &str) -> bool {
    child == parent
        || child
            .strip_suffix(parent)
            .is_some_and(|prefix| prefix.ends_with('.'))
}
