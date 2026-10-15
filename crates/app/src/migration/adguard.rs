use super::{Report, Severity, array, string, string_array, yaml};
use rustwalld_dns_filter::Action;
use rustwalld_dns_policy::{AddressFamily, Binding, BlockMode, LocalData, LocalRecord};
use serde_json::Value;
use std::{collections::HashSet, net::IpAddr};

pub(super) fn import(input: &[u8], report: &mut Report) -> Result<(), String> {
    let files = if input.starts_with(b"PK") {
        Some(super::archive::zip(input)?)
    } else {
        None
    };
    let source = if let Some(files) = &files {
        let configs: Vec<_> = files
            .iter()
            .filter(|(name, _)| {
                name.rsplit('/')
                    .next()
                    .is_some_and(|name| matches!(name, "AdGuardHome.yaml" | "AdGuardHome.yml"))
            })
            .collect();
        if configs.len() != 1 {
            return Err("AdGuard ZIP needs exactly one AdGuardHome.yaml/yml".into());
        }
        configs[0].1.as_slice()
    } else {
        input
    };
    let json_source = serde_json::from_slice::<serde::de::IgnoredAny>(source).is_ok();
    let root = yaml(source)?;
    if !root.is_object() {
        return Err("AdGuard configuration must be a mapping".into());
    }
    let schema_version = root
        .get("schema_version")
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| "schema_version must be a nonnegative integer".to_string())
        })
        .transpose()?;
    report.unreviewed(
        &root,
        "adguard",
        &[
            "dns",
            "filtering",
            "filters",
            "whitelist_filters",
            "user_rules",
            "clients",
            "tls",
            "dhcp",
        ],
        &[
            "http",
            "users",
            "auth_attempts",
            "block_auth_min",
            "pprof",
            "http_proxy",
            "language",
            "theme",
            "querylog",
            "statistics",
            "log",
            "os",
            "schema_version",
        ],
    );
    for field in ["dns", "filtering"] {
        if root
            .get(field)
            .is_some_and(|value| !value.is_null() && !value.is_object())
        {
            return Err(format!("{field} must be a mapping"));
        }
    }
    let rewrites_enabled = match root["filtering"].get("rewrites_enabled") {
        None => true,
        Some(value) => value
            .as_bool()
            .ok_or_else(|| "filtering.rewrites_enabled must be a boolean".to_string())?,
    };
    super::booleans(
        &root["dns"],
        "dns",
        &[
            "enable_dnssec",
            "aaaa_disabled",
            "use_private_ptr_resolvers",
        ],
    )?;
    super::booleans(&root["tls"], "tls", &["enabled"])?;
    super::booleans(&root["dhcp"], "dhcp", &["enabled"])?;
    let dns = &root["dns"];
    report.unreviewed(
        dns,
        "dns",
        &[
            "upstream_dns",
            "enable_dnssec",
            "ratelimit",
            "allowed_clients",
            "blocked_clients",
            "blocked_hosts",
            "fallback_dns",
            "local_ptr_upstreams",
            "bogus_nxdomain",
            "ipset",
            "trusted_proxies",
            "upstream_dns_file",
            "ipset_file",
            "aaaa_disabled",
            "use_private_ptr_resolvers",
            "edns_client_subnet",
            "upstream_mode",
            "protection_enabled",
            "filtering_enabled",
            "rewrites",
            "blocked_response_ttl",
            "blocking_mode",
            "safebrowsing_enabled",
            "parental_enabled",
            "safesearch_enabled",
            "safe_search",
            "blocked_services",
        ],
        &[
            "bind_hosts",
            "port",
            "bootstrap_dns",
            "cache_size",
            "cache_ttl_min",
            "cache_ttl_max",
            "cache_optimistic",
            "pending_requests",
            "upstream_timeout",
            "serve_http3",
            "use_http3_upstreams",
            "ratelimit_subnet_len_ipv4",
            "ratelimit_subnet_len_ipv6",
            "ratelimit_whitelist",
            "refuse_any",
            "trusted_networks",
        ],
    );
    if let Some(value) = root.get("filtering")
        && !value.is_object()
    {
        return Err("filtering must be a mapping".into());
    }
    let filtering = if root["filtering"].is_object() {
        &root["filtering"]
    } else {
        dns
    };
    if root["filtering"].is_object() {
        report.unreviewed(
            filtering,
            "filtering",
            &[
                "protection_enabled",
                "filtering_enabled",
                "rewrites",
                "rewrites_enabled",
                "blocked_response_ttl",
                "blocking_mode",
                "safebrowsing_enabled",
                "parental_enabled",
                "safesearch_enabled",
                "safe_search",
                "blocked_services",
            ],
            &[
                "blocking_ipv4",
                "blocking_ipv6",
                "protection_disabled_until",
                "safe_search_cache_size",
                "safebrowsing_cache_size",
                "parental_cache_size",
                "cache_time",
                "filters_update_interval",
            ],
        );
    }
    let base_upstreams = report.config.upstreams.clone();
    let imported = super::upstreams::translate(
        &string_array(&dns["upstream_dns"], "dns.upstream_dns")?,
        &base_upstreams,
        "adguard/upstreams",
        report,
    );
    if let Some(imported) = &imported {
        report.config.upstreams = imported.profiles.clone();
    }
    let mut policy = report.policy("adguard/default".into());
    policy.ds_routing = rustwalld_dns_policy::DsRouting::Parent;
    if let Some(imported) = imported {
        policy.upstream = imported.default;
        policy.routes = imported.routes;
    }
    super::booleans(
        filtering,
        "filtering",
        &[
            "protection_enabled",
            "filtering_enabled",
            "safebrowsing_enabled",
            "parental_enabled",
            "safesearch_enabled",
        ],
    )?;
    let protection = filtering["protection_enabled"].as_bool().unwrap_or(true)
        && filtering["filtering_enabled"].as_bool().unwrap_or(true);
    let filtering_enabled = filtering["filtering_enabled"].as_bool().unwrap_or(true);
    let filtering_path = if root["filtering"].is_object() {
        "filtering"
    } else {
        "dns"
    };
    let source_rules = string_array(&root["user_rules"], "user_rules")?;
    let mut extracted = super::pattern_rewrites::Extractor::default();
    let user_rules = extracted.user_rules(&source_rules, filtering_enabled, report);
    if filtering.get("blocked_response_ttl").is_some() {
        report.issue(format!("{filtering_path}.blocked_response_ttl"), Severity::Warning, "Source reply TTL is preserved for supported pattern rewrites only. Ordinary blocked replies and legacy local records retain native TTL semantics.");
    }
    if array(&root["filters"], "filters")?
        .len()
        .saturating_add(array(&root["whitelist_filters"], "whitelist_filters")?.len())
        > 256
    {
        return Err("AdGuard import exceeds 256 publisher lists".into());
    }
    if protection {
        report.rules(
            &mut policy,
            "adguard/user-rules".into(),
            Action::Block,
            user_rules,
        );
    } else {
        report.issue("filtering.protection_enabled",Severity::Warning,"Source protection/filtering is disabled; translated policy starts without block rules. Original inactive rule text is not activated.");
    }
    for (field, action) in [
        ("filters", Action::Block),
        ("whitelist_filters", Action::Allow),
    ] {
        let entries = array(&root[field], field)?;
        let mut ids = HashSet::new();
        let mut urls = HashSet::new();
        for (index, filter) in entries.iter().enumerate() {
            super::booleans(filter, field, &["enabled"])?;
            let path = format!("{field}[{index}]");
            // Source startup deduplicates publisher URLs and migrates IDs.
            // Never select a different active feed from an ambiguous backup.
            if filtering_enabled
                && (filter["id"].as_i64().is_some_and(|id| !ids.insert(id))
                    || filter["url"].as_str().is_some_and(|url| !urls.insert(url)))
            {
                report.issue(&path, Severity::Blocker, "Repeated filter IDs or publisher URLs require source identity/deduplication review; no extracted pattern rewrites were activated.");
                extracted.invalidate();
            }
            if filter["enabled"].as_bool() == Some(false) {
                continue;
            }
            let id = filter["id"]
                .as_i64()
                .ok_or_else(|| format!("{path}.id must be an integer"))?;
            let mut contents = None;
            if filtering_enabled {
                if id <= 0 {
                    report.issue(&path, Severity::Blocker, "Nonpositive filter IDs require source migration review; no extracted pattern rewrites were activated.");
                    extracted.invalidate();
                }
                let suffix = format!("filters/{id}.txt");
                let nested_suffix = format!("/{suffix}");
                if let Some(files) = &files {
                    let mut matching = files
                        .iter()
                        .filter(|(name, _)| *name == &suffix || name.ends_with(&nested_suffix));
                    contents = matching.next().map(|(_, data)| data);
                    if matching.next().is_some() {
                        report.issue(&path, Severity::Blocker, "Multiple archive files match this enabled filter ID; source contents are ambiguous and no extracted pattern rewrites were activated.");
                        extracted.invalidate();
                        contents = None;
                    }
                }
            }
            if protection && let Some(url) = string(&filter["url"]) {
                match super::publisher_url(&url) {
                    Ok(url) => report.publishers.push(super::Publisher {
                        policy: policy.name.clone(),
                        list: format!("adguard/{field}-{id}"),
                        url,
                        action,
                        needs_download: contents.is_none(),
                    }),
                    Err(error) => report.issue(format!("{path}.url"), Severity::Blocker, error),
                }
            }
            if filtering_enabled && field == "filters" {
                if let Some(contents) = contents {
                    let text = std::str::from_utf8(contents)
                        .map_err(|_| "AdGuard filter files must be UTF-8")?;
                    let (ordinary, present) =
                        extracted.feed(text, &format!("{path}.contents"), report);
                    if present {
                        if filter["enabled"].as_bool() != Some(true) {
                            report.issue(&path, Severity::Blocker, "Bundled rewrite feeds require explicit enabled: true; omitted source activation needs review.");
                            extracted.invalidate();
                        }
                        report.issue(&path, Severity::Warning, "Bundled rewrite rules are a frozen import snapshot. Reimport the complete backup to update or remove their native answers; ordinary list downloads cannot refresh converted rewrite effects. No automatic source was configured.");
                    }
                    if protection {
                        report.rules(
                            &mut policy,
                            format!("adguard/{field}-{id}"),
                            action,
                            ordinary,
                        );
                    }
                } else {
                    report.issue(&path, Severity::Blocker, if protection {
                        "Enabled downloaded list contents are absent. Download into the reviewed draft before claiming equivalent blocking."
                    } else {
                        "Paused protection does not prove an enabled downloaded list has no active pattern rewrites. Missing source contents require review."
                    });
                    extracted.invalidate();
                }
            } else if protection {
                if let Some(contents) = contents {
                    let text = std::str::from_utf8(contents)
                        .map_err(|_| "AdGuard filter files must be UTF-8")?;
                    report.rules(
                        &mut policy,
                        format!("adguard/{field}-{id}"),
                        action,
                        text.to_owned(),
                    );
                } else {
                    report.issue(&path,Severity::Blocker,"Enabled downloaded list contents are absent. Download into the reviewed draft before claiming equivalent blocking.");
                }
            }
            report.issue(format!("{path}.url"),Severity::Warning,"Publisher scheduling/bootstrap settings require review; import never contacts URLs or activates automatic downloads.");
        }
    }
    // Pattern activation and reply TTL use the same container moved by v26.
    // Do not reinterpret ignored old settings as live modern controls.
    let controls = [
        "blocked_response_ttl",
        "filtering_enabled",
        "protection_enabled",
        "rewrites",
        "rewrites_enabled",
    ];
    let old_controls = controls.iter().any(|field| dns.get(*field).is_some());
    let modern_controls = controls
        .iter()
        .any(|field| root["filtering"].get(*field).is_some());
    if extracted.present
        && ((old_controls
            && (root["filtering"].is_object()
                || schema_version.is_some_and(|version| version >= 26)))
            || (modern_controls && schema_version.is_some_and(|version| version < 26)))
    {
        report.issue(if old_controls { "dns" } else { "filtering" }, Severity::Blocker, "Pattern rules mix filtering control/TTL layouts inconsistent with the source schema hint; no extracted pattern rewrites were activated.");
        extracted.invalidate();
    }
    let legacy_rewrites = &root["filtering"]["rewrites"];
    let dns_rewrites = &dns["rewrites"];
    if !legacy_rewrites.is_null() && !dns_rewrites.is_null() {
        report.issue("dns.rewrites", Severity::Blocker, "Rewrites are defined in both filtering and dns containers; source precedence cannot be verified. Review one explicit definition.");
    }
    let (rewrites, rewrite_field) = if !legacy_rewrites.is_null() {
        (legacy_rewrites, "filtering.rewrites")
    } else {
        (dns_rewrites, "dns.rewrites")
    };
    let incompatible_layout =
        schema_version.is_some_and(|version| version >= 26) && !dns_rewrites.is_null();
    if incompatible_layout {
        report.issue("dns.rewrites", Severity::Blocker, "Source schemas 26 and later store rewrite entries under filtering; an old DNS-container definition conflicts with the schema hint.");
    }
    if root["filtering"].get("rewrites_enabled").is_some() && !dns_rewrites.is_null() {
        report.issue("filtering.rewrites_enabled", Severity::Blocker, "Global rewrite control and DNS-container entries mix source schema layouts; migration precedence requires review.");
    }
    if !filtering_enabled && !array(rewrites, rewrite_field)?.is_empty() {
        report.issue(format!("{filtering_path}.filtering_enabled"), Severity::Info, "Source filtering is disabled; legacy rewrite definitions were not activated as local records.");
    }
    if !rewrites_enabled {
        report.issue("filtering.rewrites_enabled", Severity::Info, "Source DNS rewrites are globally disabled; no rewrite definitions were activated. Ordinary filtering remains active.");
    }
    for (index, rewrite) in array(rewrites, rewrite_field)?.iter().enumerate() {
        let path = format!("{rewrite_field}[{index}]");
        if !rewrite.is_object() {
            return Err(format!("{path} must be a mapping"));
        }
        report.unreviewed(rewrite, &path, &["domain", "answer", "enabled"], &[]);
        let enabled = match rewrite.get("enabled") {
            None => true,
            Some(value) => value
                .as_bool()
                .ok_or_else(|| format!("{path}.enabled must be a boolean"))?,
        };
        let domain =
            string(&rewrite["domain"]).ok_or_else(|| format!("{path}.domain must be text"))?;
        let answer =
            string(&rewrite["answer"]).ok_or_else(|| format!("{path}.answer must be text"))?;
        if !filtering_enabled
            || !rewrites_enabled
            || (incompatible_layout && rewrite_field == "dns.rewrites")
        {
            continue;
        }
        if !enabled {
            if schema_version.is_some_and(|version| version < 31) {
                report.issue(&path, Severity::Blocker, "Source schemas before 31 initialize rewrite entries as enabled; an explicit disabled entry cannot claim equivalent activation.");
            }
            report.issue(
                &path,
                Severity::Info,
                "Disabled source rewrite was not activated or included as a local record.",
            );
            continue;
        }
        if domain.contains('*') && (!domain.starts_with("*.") || answer.parse::<IpAddr>().is_err())
        {
            report.issue(path, Severity::Blocker, "Only leading *. wildcard address rewrites are supported; wildcard CNAME/passthrough and other patterns require review.");
            continue;
        }
        if domain.chars().any(char::is_whitespace) {
            report.issue(path, Severity::Blocker, "Source rewrite owners with whitespace require review; normalization could change matching.");
            continue;
        }
        if domain.starts_with("*.") && (!domain.is_ascii() || domain.ends_with('.')) {
            report.issue(path, Severity::Blocker, "Wildcard source owners must be ASCII without a trailing root dot; normalization could change source matching.");
            continue;
        }
        let data = if matches!(answer.as_str(), "A" | "AAAA") {
            LocalData::Passthrough {
                family: if answer == "A" {
                    AddressFamily::A
                } else {
                    AddressFamily::Aaaa
                },
            }
        } else {
            match answer.parse::<IpAddr>() {
                Ok(IpAddr::V4(address)) => LocalData::A { address },
                Ok(IpAddr::V6(address)) => LocalData::Aaaa { address },
                Err(_) => LocalData::Cname { target: answer },
            }
        };
        policy.dns_records.push(LocalRecord {
            domain,
            ttl: 60,
            data,
        });
    }
    policy.block_mode = match filtering["blocking_mode"].as_str().unwrap_or("nxdomain") {
        "nxdomain" => BlockMode::NxDomain,
        "null_ip" => BlockMode::NullIp,
        "refused" | "custom_ip" => {
            report.issue("filtering.blocking_mode",Severity::Blocker,"Source block reply mode is not equivalent to NXDOMAIN; configure a supported mode explicitly.");
            BlockMode::NxDomain
        }
        _ => {
            report.issue(
                "filtering.blocking_mode",
                Severity::Blocker,
                "Unknown blocking mode requires review.",
            );
            BlockMode::NxDomain
        }
    };
    let safe_search = super::safe_search::translate(filtering, "filtering", report)?;
    if filtering["protection_enabled"].as_bool() != Some(false) {
        policy.safe_search = safe_search;
    } else if safe_search.is_some() {
        report.issue(
            "filtering.safe_search",
            Severity::Warning,
            "Source protection is disabled, so inactive SafeSearch choices were not activated.",
        );
    }
    let blocked_services = super::services::translate(
        &filtering["blocked_services"],
        "filtering.blocked_services",
        report,
        json_source,
    )?;
    if filtering["protection_enabled"].as_bool() != Some(false) {
        policy.blocked_services = blocked_services;
    }
    let allowed = string_array(&dns["allowed_clients"], "dns.allowed_clients")?;
    if !allowed.is_empty() {
        let mut networks = Vec::new();
        for (index, id) in allowed.iter().enumerate() {
            match cidr(id).parse() {
                Ok(network) => networks.push(network),
                Err(_) => report.issue(
                    format!("dns.allowed_clients[{index}]"),
                    Severity::Blocker,
                    "Non-IP client identity cannot be used as a source-network admission rule.",
                ),
            }
        }
        if networks.len() == allowed.len() {
            report.config.allowed_clients = networks;
        }
    }
    if dns["enable_dnssec"].as_bool() == Some(true) {
        report.issue(
            "dns.enable_dnssec",
            Severity::Blocker,
            "Destination DNSSEC validation must be configured and tested explicitly.",
        );
    }
    if dns["ratelimit"].as_u64().is_some_and(|value| value > 0) {
        report.issue(
            "dns.ratelimit",
            Severity::Blocker,
            "Source per-client rate limit needs an explicit destination equivalent.",
        );
    }
    for publisher in &report.publishers {
        if publisher.needs_download && !policy.lists.iter().any(|list| list.name == publisher.list)
        {
            policy.lists.push(rustwalld_dns_filter::ListInput {
                name: publisher.list.clone(),
                action: publisher.action,
                rules: String::new(),
                syntax: rustwalld_dns_filter::RuleSyntax::AdguardV6,
            });
        }
    }
    let separate_allowlist = protection
        && array(&root["whitelist_filters"], "whitelist_filters")?
            .iter()
            .any(|list| list["enabled"].as_bool().unwrap_or(true));
    let patterns = extracted.finish();
    let pattern_records = super::pattern_rewrites::translate(
        &patterns,
        filtering,
        filtering_path,
        &policy.dns_records,
        separate_allowlist,
        report,
    );
    policy.dns_records.extend(pattern_records);
    let omitted_filter_content = !source_rules.is_empty()
        || !array(rewrites, rewrite_field)?.is_empty()
        || !array(&root["filters"], "filters")?.is_empty()
        || !array(&root["whitelist_filters"], "whitelist_filters")?.is_empty();
    let global = policy.clone();
    let mut policies = vec![policy];
    let mut bindings = Vec::new();
    let mut combined_routes = global.routes.len();
    let mut seen = HashSet::new();
    let clients = if root["clients"].is_array() {
        &root["clients"]
    } else {
        &root["clients"]["persistent"]
    };
    let clients = array(clients, "clients.persistent")?;
    if clients.len() > 255
        || global
            .lists
            .iter()
            .map(|list| list.rules.len())
            .sum::<usize>()
            .saturating_mul(clients.len() + 1)
            > super::MAX_EXPANDED_BYTES
        || global.dns_records.len().saturating_mul(clients.len() + 1) > 10000
    {
        return Err("AdGuard client policies exceed the combined 256-policy/64-MiB/10000-local-record import budget".into());
    }
    let named_client_rules = global
        .lists
        .iter()
        .any(|list| list.rules.contains("client="))
        && rustwalld_dns_filter::FilterSnapshot::compile(
            &global.lists,
            10_000_000,
            256 * 1024 * 1024,
        )
        .is_ok_and(|snapshot| {
            snapshot
                .rules()
                .iter()
                .filter_map(|rule| rule.client())
                .any(|selector| {
                    selector
                        .include()
                        .iter()
                        .chain(selector.exclude())
                        .any(|value| matches!(value, rustwalld_dns_filter::ClientValue::Name(_)))
                })
        });
    for (index, client) in clients.iter().enumerate() {
        let path = format!("clients.persistent[{index}]");
        super::booleans(
            client,
            &path,
            &[
                "use_global_settings",
                "filtering_enabled",
                "safebrowsing_enabled",
                "parental_enabled",
                "safesearch_enabled",
                "use_global_safesearch",
                "use_global_blocked_services",
                "upstreams_cache_enabled",
            ],
        )?;
        let mut filter_tags = super::string_array(&client["tags"], &format!("{path}.tags"))?;
        if let Err(error) =
            rustwalld_dns_filter::ClientTags::compile(filter_tags.iter().map(String::as_str))
        {
            report.issue(
                format!("{path}.tags"),
                Severity::Blocker,
                format!("Cannot preserve source filtering tags: {error}"),
            );
            filter_tags.clear();
        }
        filter_tags.sort_unstable();
        let source_name = string(&client["name"]);
        if source_name.is_none() && named_client_rules {
            report.issue(format!("{path}.name"),Severity::Blocker,"Named client rules require an explicit source client name; a generated preview label cannot verify the original identity.");
        }
        let name = source_name.unwrap_or_else(|| format!("client-{index}"));
        let mut policy = global.clone();
        policy.name = format!("adguard/client-{index}");
        let services_path = format!("{path}.blocked_services");
        super::services::validate(&client["blocked_services"], &services_path)?;
        match client["use_global_blocked_services"].as_bool() {
            Some(false)
                if client
                    .get("blocked_services")
                    .is_none_or(|value| value.is_null()) =>
            {
                report.issue(format!("{path}.blocked_services"), Severity::Blocker, "Explicit custom service settings are absent; global choices were retained instead of guessing an empty override.");
            }
            Some(false) => {
                let custom = super::services::translate(
                    &client["blocked_services"],
                    &services_path,
                    report,
                    json_source,
                )?;
                policy.blocked_services =
                    if filtering["protection_enabled"].as_bool() == Some(false) {
                        None
                    } else {
                        custom
                    };
            }
            None if client
                .get("blocked_services")
                .is_some_and(|value| !value.is_null()) =>
            {
                report.issue(format!("{path}.use_global_blocked_services"),Severity::Blocker,"Client service inheritance is absent; global choices were retained for review instead of guessing an override.");
            }
            _ => {}
        }
        super::safe_search::validate(&client["safe_search"], &path)?;
        if client["use_global_safesearch"].as_bool() == Some(false) {
            let custom = super::safe_search::translate(client, &path, report)?;
            policy.safe_search = if filtering["protection_enabled"].as_bool() == Some(false) {
                None
            } else {
                custom
            };
        } else if client["use_global_safesearch"].is_null()
            && (client["safe_search"].is_object()
                || client["safesearch_enabled"].as_bool() == Some(true))
        {
            report.issue(format!("{path}.use_global_safesearch"),Severity::Blocker,"Client SafeSearch inheritance is absent; global provider choices were retained for review instead of guessing an override.");
        } else if client["use_global_safesearch"].is_null()
            && client["use_global_settings"].as_bool() == Some(false)
            && client["safesearch_enabled"].as_bool() == Some(false)
        {
            // Explicit legacy client override disables SafeSearch with its settings.
            if filtering["safe_search"].is_object() {
                report.issue(format!("{path}.use_global_safesearch"),Severity::Blocker,"Legacy client flag is mixed with structured global SafeSearch but its inheritance flag is absent; global choices were retained for review.");
            } else {
                policy.safe_search = None;
            }
        }
        if client["use_global_settings"].as_bool() == Some(false)
            && client["filtering_enabled"].as_bool() == Some(false)
        {
            policy.lists.clear();
            policy.dns_records.clear();
        }
        if !filtering_enabled
            && omitted_filter_content
            && client["use_global_settings"].as_bool() == Some(false)
            && client["filtering_enabled"].as_bool() == Some(true)
        {
            report.issue(format!("{path}.filtering_enabled"), Severity::Blocker, "Client filtering override re-enables globally omitted source contents; source inheritance requires explicit review before activation.");
        }
        let upstream_path = format!("{path}.upstreams");
        if client.get("upstreams_cache_size").is_some_and(|value| {
            !value.is_null() && value.as_u64().is_none_or(|size| size > u64::from(u32::MAX))
        }) {
            return Err(format!(
                "{path}.upstreams_cache_size must be an unsigned 32-bit size"
            ));
        }
        let values = string_array(&client["upstreams"], &upstream_path)?;
        super::client_upstreams::translate(
            &values,
            &base_upstreams,
            &mut policy,
            &global,
            index,
            &upstream_path,
            report,
        );
        combined_routes = combined_routes.saturating_add(policy.routes.len());
        if combined_routes > 4096 {
            return Err(
                "AdGuard client policies exceed the combined 4096-route import budget".into(),
            );
        }
        let identities = string_array(&client["ids"], &format!("{path}.ids"))?;
        if identities.is_empty() {
            report.issue(
                format!("{path}.ids"),
                Severity::Blocker,
                "Client identities are absent; no source-IP binding was invented for this policy.",
            );
        }
        for (id_index, id) in identities.iter().enumerate() {
            match cidr(id).parse(){
                Ok(network)=>{if !seen.insert(network){report.issue(format!("{path}.ids[{id_index}]"),Severity::Blocker,"Duplicate client identity");continue;}bindings.push(Binding{name:name.clone(),network,policy:policy.name.clone(),filter_tags:filter_tags.clone(),metadata:None});},
                Err(_)=>report.issue(format!("{path}.ids[{id_index}]"),Severity::Blocker,"MAC/hostname/client-ID identity needs discovery or encrypted-client mapping; no CIDR binding was invented."),
            }
        }
        report.unreviewed(
            client,
            &path,
            &[
                "name",
                "ids",
                "tags",
                "upstreams",
                "use_global_settings",
                "filtering_enabled",
                "safebrowsing_enabled",
                "parental_enabled",
                "safesearch_enabled",
                "safe_search",
                "use_global_safesearch",
                "use_global_blocked_services",
                "blocked_services",
            ],
            &[
                "ignore_querylog",
                "ignore_statistics",
                "upstreams_cache_enabled",
                "upstreams_cache_size",
            ],
        );
        feature_settings(client, &path, report);
        let inherited: Vec<_> = report
            .publishers
            .iter()
            .filter(|publisher| {
                publisher.policy == global.name
                    && policy.lists.iter().any(|list| list.name == publisher.list)
            })
            .map(|publisher| super::Publisher {
                policy: policy.name.clone(),
                list: publisher.list.clone(),
                url: publisher.url.clone(),
                action: publisher.action,
                needs_download: publisher.needs_download,
            })
            .collect();
        if report.publishers.len().saturating_add(inherited.len()) > 4096 {
            return Err("Too many imported publisher references".into());
        }
        report.publishers.extend(inherited);
        policies.push(policy);
    }
    if policies.len() > 256 {
        return Err("AdGuard import exceeds 256 policies".into());
    }
    report.config.default_policy = global.name.clone();
    report.config.policies = policies;
    report.config.bindings = bindings;
    feature_settings(filtering, "filtering", report);
    for key in [
        "blocked_clients",
        "blocked_hosts",
        "fallback_dns",
        "local_ptr_upstreams",
        "bogus_nxdomain",
        "ipset",
        "trusted_proxies",
    ] {
        if !array(&dns[key], &format!("dns.{key}"))?.is_empty() {
            report.issue(format!("dns.{key}"),Severity::Blocker,"This source setting requires an explicit equivalent and was not applied implicitly.");
        }
    }
    for key in ["upstream_dns_file", "ipset_file"] {
        if dns[key].as_str().is_some_and(|value| !value.is_empty()) {
            report.issue(
                format!("dns.{key}"),
                Severity::Blocker,
                "Source external file settings require explicit destination configuration.",
            );
        }
    }
    for key in ["aaaa_disabled", "use_private_ptr_resolvers"] {
        if dns[key].as_bool() == Some(true) {
            report.issue(format!("dns.{key}"),Severity::Blocker,"Source AAAA suppression/private-PTR resolver behavior needs an explicit destination equivalent.");
        }
    }
    if dns["edns_client_subnet"]["enabled"].as_bool() == Some(true) {
        report.issue(
            "dns.edns_client_subnet",
            Severity::Blocker,
            "Destination strips EDNS options; source ECS forwarding cannot be retained implicitly.",
        );
    }
    if dns["upstream_mode"].as_str() == Some("fastest_addr") {
        report.issue("dns.upstream_mode",Severity::Blocker,"Source fastest-address response selection is not equivalent to destination resolver failover.");
    }
    if root["tls"]["enabled"].as_bool() == Some(true) {
        report.issue("tls",Severity::Blocker,"Encrypted listeners/certificate paths must be configured and checked on the destination appliance.");
    }
    if root["dhcp"]["enabled"].as_bool() == Some(true) {
        report.issue("dhcp.enabled",Severity::Blocker,"DHCP requires reviewed deployment of the separate DHCP component; import does not take over address assignment.");
    }
    report.issue("administration",Severity::Info,"Users/passwords, tokens, filesystem paths, listener addresses and query history are not copied. Destination administration stays independently configured.");
    Ok(())
}
fn feature_settings(value: &Value, path: &str, report: &mut Report) {
    for key in ["safebrowsing_enabled", "parental_enabled"] {
        if value[key].as_bool() == Some(true) {
            report.issue(format!("{path}.{key}"),Severity::Blocker,"Cloud/category protection needs a reviewed local profile; it was not silently disabled.");
        }
    }
}
fn cidr(id: &str) -> String {
    match id.parse::<IpAddr>() {
        Ok(ip) => format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 }),
        Err(_) => id.to_owned(),
    }
}
