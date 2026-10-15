//! Pi-hole v5 Teleporter JSON tables normalized into a private, owned schema.
//! No source SQL, shell configuration or archive path is ever executed.
use super::{Files, Report, Severity};
use rusqlite::{Connection, params};
use rustwalld_dns_policy::{BlockMode, LocalData, LocalRecord};
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) fn database(files: &Files, report: &mut Report) -> Result<Vec<u8>, String> {
    if files.contains_key("gravity.db") || files.keys().any(|name| name.ends_with("/gravity.db")) {
        return Err(
            "A v5 Teleporter must contain JSON tables, not a second gravity database".into(),
        );
    }
    let scratch =
        tempfile::NamedTempFile::new().map_err(|_| "Private import scratch unavailable")?;
    let mut db =
        Connection::open(scratch.path()).map_err(|_| "Import scratch database unavailable")?;
    db.execute_batch("PRAGMA page_size=4096;PRAGMA max_page_count=16384;")
        .map_err(|_| "Import scratch size limit unavailable")?;
    db.execute_batch("CREATE TABLE \"group\"(id INTEGER PRIMARY KEY,enabled INTEGER,name TEXT);CREATE TABLE domainlist(id INTEGER PRIMARY KEY,type INTEGER,domain TEXT,enabled INTEGER);CREATE TABLE adlist(id INTEGER PRIMARY KEY,address TEXT,enabled INTEGER);CREATE TABLE client(id INTEGER PRIMARY KEY,ip TEXT,comment TEXT);CREATE TABLE domainlist_by_group(domainlist_id INTEGER,group_id INTEGER,PRIMARY KEY(domainlist_id,group_id));CREATE TABLE adlist_by_group(adlist_id INTEGER,group_id INTEGER,PRIMARY KEY(adlist_id,group_id));CREATE TABLE client_by_group(client_id INTEGER,group_id INTEGER,PRIMARY KEY(client_id,group_id));")
        .map_err(|_| "Import scratch schema unavailable")?;
    let tx = db
        .transaction()
        .map_err(|_| "Import scratch transaction unavailable")?;
    let error = |_: rusqlite::Error| {
        "Invalid/duplicate v5 table identity or scratch write failure".to_owned()
    };
    for row in rows(files, "group.json", 256, report)? {
        tx.execute(
            "INSERT INTO \"group\" VALUES(?1,?2,?3)",
            params![id(&row, "id")?, enabled(&row)?, text(&row, "name", 128)?],
        )
        .map_err(error)?;
    }
    for (file, kind) in [
        ("whitelist.exact.json", 0),
        ("blacklist.exact.json", 1),
        ("whitelist.regex.json", 2),
        ("blacklist.regex.json", 3),
    ] {
        for row in rows(files, file, 1_000_000, report)? {
            if row
                .get("type")
                .is_some_and(|value| value.as_i64() != Some(kind))
            {
                return Err("v5 rule type conflicts with its table".into());
            }
            tx.execute(
                "INSERT INTO domainlist VALUES(?1,?2,?3,?4)",
                params![
                    id(&row, "id")?,
                    kind,
                    text(&row, "domain", 4096)?,
                    enabled(&row)?
                ],
            )
            .map_err(error)?;
        }
    }
    for row in rows(files, "adlist.json", 256, report)? {
        tx.execute(
            "INSERT INTO adlist VALUES(?1,?2,?3)",
            params![
                id(&row, "id")?,
                text(&row, "address", 4096)?,
                enabled(&row)?
            ],
        )
        .map_err(error)?;
    }
    for row in rows(files, "client.json", 65536, report)? {
        let comment = match row.get("comment") {
            None | Some(Value::Null) => "",
            Some(value) => value
                .as_str()
                .filter(|text| text.len() <= 1024)
                .ok_or("Invalid v5 client comment")?,
        };
        tx.execute(
            "INSERT INTO client VALUES(?1,?2,?3)",
            params![id(&row, "id")?, text(&row, "ip", 256)?, comment],
        )
        .map_err(error)?;
    }
    for (file, table, column, parent) in [
        (
            "domainlist_by_group.json",
            "domainlist_by_group",
            "domainlist_id",
            "domainlist",
        ),
        (
            "adlist_by_group.json",
            "adlist_by_group",
            "adlist_id",
            "adlist",
        ),
        (
            "client_by_group.json",
            "client_by_group",
            "client_id",
            "client",
        ),
    ] {
        let mut insert = tx
            .prepare(&format!("INSERT INTO {table} VALUES(?1,?2)"))
            .map_err(error)?;
        for row in rows(files, file, 1_000_000, report)? {
            insert
                .execute(params![id(&row, column)?, id(&row, "group_id")?])
                .map_err(error)?;
        }
        let dangling: i64 = tx.query_row(&format!("SELECT count(*) FROM {table} a WHERE NOT EXISTS(SELECT 1 FROM \"group\" g WHERE g.id=a.group_id) OR NOT EXISTS(SELECT 1 FROM {parent} p WHERE p.id=a.{column})"),[],|row|row.get(0)).map_err(error)?;
        if dangling != 0 {
            return Err("v5 association references an unknown group or row".into());
        }
    }
    tx.commit().map_err(error)?;
    drop(db);
    let bytes = std::fs::read(scratch.path()).map_err(|_| "Import scratch read failure")?;
    if bytes.len() > super::MAX_EXPANDED_BYTES {
        return Err("Normalized v5 database exceeds 64 MiB".into());
    }
    Ok(bytes)
}
fn rows(files: &Files, file: &str, max: usize, report: &mut Report) -> Result<Vec<Value>, String> {
    let bytes = files
        .get(file)
        .ok_or_else(|| format!("v5 Teleporter is missing {file}"))?;
    let value = super::yaml(bytes)?;
    let Value::Array(rows) = value else {
        return Err(format!("{file} must contain an array"));
    };
    if rows.len() > max || rows.iter().any(|row| !row.is_object()) {
        return Err(format!("Invalid or oversized {file}"));
    }
    let allowed: &[&str] = match file {
        "group.json" => &[
            "id",
            "enabled",
            "name",
            "description",
            "date_added",
            "date_modified",
        ],
        "client.json" => &["id", "ip", "comment", "date_added", "date_modified"],
        "adlist.json" => &[
            "id",
            "address",
            "enabled",
            "comment",
            "date_added",
            "date_modified",
            "date_updated",
            "number",
            "invalid_domains",
            "abp_entries",
            "status",
        ],
        "domainlist_by_group.json" => &["domainlist_id", "group_id"],
        "client_by_group.json" => &["client_id", "group_id"],
        "adlist_by_group.json" => &["adlist_id", "group_id"],
        _ => &[
            "id",
            "type",
            "domain",
            "enabled",
            "comment",
            "date_added",
            "date_modified",
        ],
    };
    let mut seen = std::collections::BTreeSet::new();
    for row in &rows {
        if let Some(object) = row.as_object() {
            for key in object.keys() {
                if !allowed.contains(&key.as_str()) && seen.insert(key) {
                    report.issue(
                        format!("{file}.{key}"),
                        Severity::Blocker,
                        "Unknown source table field requires review; its value was not copied.",
                    );
                }
            }
        }
    }
    Ok(rows)
}
fn id(row: &Value, key: &str) -> Result<i64, String> {
    row[key]
        .as_i64()
        .filter(|id| *id >= 0)
        .ok_or_else(|| format!("v5 {key} must be a nonnegative integer"))
}
fn enabled(row: &Value) -> Result<i64, String> {
    row["enabled"]
        .as_i64()
        .filter(|value| matches!(value, 0 | 1))
        .ok_or("v5 enabled must be 0 or 1".into())
}
fn text<'a>(row: &'a Value, key: &str, max: usize) -> Result<&'a str, String> {
    row[key]
        .as_str()
        .filter(|value| value.len() <= max)
        .ok_or_else(|| format!("Invalid or oversized v5 {key}"))
}
pub(super) fn settings(files: &Files, report: &mut Report) -> Result<(), String> {
    // v5's default is NULL; absence of an override must not turn it into NXDOMAIN.
    for policy in &mut report.config.policies {
        policy.block_mode = BlockMode::NullIp;
    }
    report.issue("v5.ttl", Severity::Warning, "Destination null-address replies use TTL 60 seconds. Imported hosts/CNAME use TTL 60 unless the source CNAME includes an explicit TTL; review client caching expectations.");
    let mut upstreams = Vec::new();
    let mut routes = Vec::new();
    let mut local = Vec::new();
    for (name, bytes) in files {
        if name == "setupVars.conf" || name == "pihole-FTL.conf" {
            let mut seen = BTreeMap::new();
            for (key, value) in lines(bytes)? {
                if seen.insert(key.to_owned(), ()).is_some() {
                    return Err("Duplicate v5 configuration key".into());
                }
                let field = format!("{name}.{key}");
                if name == "setupVars.conf" {
                    match key {
                        key if key.strip_prefix("PIHOLE_DNS_").is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(|byte|byte.is_ascii_digit())) => {
                            // dnsmasq.d is the effective configuration when present.
                            if !files.contains_key("dnsmasq.d/01-pihole.conf") { upstreams.push(value.to_owned()); }
                        }
                        "DNSSEC" | "DHCP_ACTIVE" if value == "true" => report.issue(field,Severity::Blocker,"DNSSEC/DHCP requires explicitly configured and verified destination components."),
                        "DNSSEC" | "DHCP_ACTIVE" if value != "false" => return Err("Invalid v5 boolean setting".into()),
                        "DNSSEC" | "DHCP_ACTIVE" => {},
                        "WEBPASSWORD" => {},
                        "BLOCKING_ENABLED" if value == "false" => report.issue(field,Severity::Blocker,"Source blocking was disabled; review the desired protection state."),
                        "BLOCKING_ENABLED" if value != "true" => return Err("Invalid v5 blocking state".into()),
                        "BLOCKING_ENABLED" => {},
                        "QUERY_LOGGING" if value == "false" => report.issue(field, Severity::Blocker, "Source query logging was disabled; configure destination history privacy before activation."),
                        "QUERY_LOGGING" if value != "true" => return Err("Invalid v5 query logging setting".into()),
                        "PIHOLE_INTERFACE" | "IPV4_ADDRESS" | "IPV6_ADDRESS" | "QUERY_LOGGING" | "INSTALL_WEB_SERVER" | "INSTALL_WEB_INTERFACE" | "LIGHTTPD_ENABLED" | "DNSMASQ_LISTENING" | "TEMPERATUREUNIT" | "WEBUIBOXEDLAYOUT" | "WEBTHEME" => {},
                        key if key.starts_with("DHCP_") || key.starts_with("REV_SERVER") || matches!(key,"DNS_FQDN_REQUIRED"|"DNS_BOGUS_PRIV") => report.issue(field,Severity::Warning,"Source deployment setting remains independently configured; effective dnsmasq directives are checked separately."),
                        _ => report.issue(field,Severity::Blocker,"Untranslated v5 source setting requires review."),
                    }
                } else {
                    match key {
                        "BLOCKINGMODE" => {
                            let mode = match value { "NULL"=>Some(BlockMode::NullIp),"NXDOMAIN"=>Some(BlockMode::NxDomain),"NODATA"=>Some(BlockMode::NoData),_=>None };
                            if let Some(mode)=mode {for policy in &mut report.config.policies {policy.block_mode=mode;}}
                            else {report.issue(field,Severity::Blocker,"Source blocking mode needs an explicit equivalent.");}
                        }
                        "CNAME_DEEP_INSPECT" if value.eq_ignore_ascii_case("no") => report.issue(field,Severity::Warning,"Destination inspects reachable CNAME targets; protection is stricter."),
                        "CNAME_DEEP_INSPECT" if !value.eq_ignore_ascii_case("yes") => return Err("Invalid v5 CNAME inspection setting".into()),
                        "CNAME_DEEP_INSPECT" => {},
                        "PRIVACYLEVEL" if value != "0" => report.issue(field,Severity::Blocker,"Configure destination history privacy before activation; source privacy cannot be silently weakened."),
                        "PRIVACYLEVEL" => {},
                        "MAXDBDAYS" if value == "0" => report.issue(field, Severity::Blocker, "Source persistent history was disabled; configure destination history privacy before activation."),
                        "MAXDBDAYS" | "DBINTERVAL" | "DBFILE" | "LOGFILE" | "SOCKET_LISTENING" | "FTLPORT" | "MAXLOGAGE" | "RESOLVE_IPV4" | "RESOLVE_IPV6" | "AAAA_QUERY_ANALYSIS" => report.issue(field, Severity::Warning, "Source operational/history setting is not copied; destination administration remains independently configured."),
                        _ => report.issue(field,Severity::Blocker,"Untranslated FTL setting requires review."),
                    }
                }
            }
        } else if name.starts_with("dnsmasq.d/") {
            for (key, value) in lines(bytes)? {
                let field = format!("{name}.{key}");
                match key {
                    "server" => {
                        if let Some(value) = value.strip_prefix('/') {
                            let Some((domains, address)) = value.rsplit_once('/') else {
                                return Err("Invalid dnsmasq server directive".into());
                            };
                            routes.push(format!("[/{domains}/]{address}"));
                        } else {
                            upstreams.push(value.to_owned());
                        }
                    }
                    "cname" => {
                        let fields: Vec<_> = value.split(',').collect();
                        if fields.len() < 2 {
                            return Err("Invalid v5 CNAME directive".into());
                        }
                        let (owners, target, ttl) = if let Some(last) =
                            fields.last().and_then(|part| part.parse::<u32>().ok())
                        {
                            if fields.len() < 3 {
                                return Err("Invalid v5 CNAME TTL directive".into());
                            }
                            (&fields[..fields.len() - 2], fields[fields.len() - 2], last)
                        } else {
                            (&fields[..fields.len() - 1], fields[fields.len() - 1], 60)
                        };
                        for owner in owners {
                            local.push(LocalRecord {
                                domain: (*owner).into(),
                                ttl,
                                data: LocalData::Cname {
                                    target: target.into(),
                                },
                            });
                        }
                        if local.len() > 10000 {
                            return Err("Too many v5 CNAME records".into());
                        }
                    }
                    "addn-hosts" if value == "/etc/pihole/custom.list" => {}
                    "addn-hosts" | "hostsdir" => report.issue(
                        field,
                        Severity::Blocker,
                        "External/generated hosts file is not imported implicitly.",
                    ),
                    "domain-needed" | "bogus-priv" | "localise-queries" => report.issue(
                        field,
                        Severity::Blocker,
                        "Source private-name/query behavior needs an explicit equivalent.",
                    ),
                    "dnssec" | "trust-anchor" => report.issue(
                        field,
                        Severity::Blocker,
                        "Configure and verify destination DNSSEC validation.",
                    ),
                    "no-resolv" | "log-queries" | "log-facility" | "log-async" | "cache-size"
                    | "interface" | "bind-interfaces" | "local-service" | "except-interface" => {}
                    _ => report.issue(
                        field,
                        Severity::Blocker,
                        "Untranslated dnsmasq directive requires review; it was not executed.",
                    ),
                }
            }
        } else if !matches!(
            name.as_str(),
            "gravity.db"
                | "group.json"
                | "client.json"
                | "domainlist_by_group.json"
                | "adlist_by_group.json"
                | "client_by_group.json"
                | "adlist.json"
                | "domain_audit.json"
                | "custom.list"
                | "whitelist.exact.json"
                | "whitelist.regex.json"
                | "blacklist.exact.json"
                | "blacklist.regex.json"
                | "dhcp.leases"
        ) {
            report.issue(
                name,
                Severity::Blocker,
                "Untranslated archive file requires review; no paths or contents were applied.",
            );
        }
    }
    upstreams.extend(routes);
    let base_upstreams = report.config.upstreams.clone();
    if let Some(imported) =
        super::upstreams::translate(&upstreams, &base_upstreams, "pi-hole/v5", report)
    {
        for policy in &mut report.config.policies {
            policy.upstream = imported.default.clone();
            policy.routes = imported.routes.clone();
        }
        report.config.upstreams = imported.profiles;
    }
    if report
        .config
        .policies
        .iter()
        .map(|p| p.dns_records.len())
        .sum::<usize>()
        .saturating_add(local.len().saturating_mul(report.config.policies.len()))
        > 10000
    {
        return Err("Combined v5 local records exceed 10000".into());
    }
    for policy in &mut report.config.policies {
        policy.dns_records.extend(local.clone());
    }
    report.issue("v5.teleporter",Severity::Info,"v5 backups omit downloaded gravity contents. Enabled publishers require a reviewed download; JSON groups, rules and IP/CIDR clients retain their assignments.");
    Ok(())
}
fn lines(bytes: &[u8]) -> Result<Vec<(&str, &str)>, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "v5 settings must be UTF-8")?;
    let mut result = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.len() > 8192 || result.len() >= 10000 {
            return Err("v5 settings line/count budget exceeded".into());
        }
        let (key, value) = line.split_once('=').unwrap_or((line, ""));
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err("Invalid v5 setting name".into());
        }
        result.push((key, value));
    }
    Ok(result)
}
