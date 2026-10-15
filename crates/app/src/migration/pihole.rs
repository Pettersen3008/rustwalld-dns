use super::{MAX_EXPANDED_BYTES, Publisher, Report, Severity, literal_address};
use rusqlite::{Connection, OpenFlags, limits::Limit};
use rustwalld_dns_filter::{Action, ListInput};
use rustwalld_dns_policy::{
    Binding, DomainRoute, LocalData, LocalRecord, UpstreamProfile, UpstreamTransport,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    net::IpAddr,
};
const MAX_ROWS: usize = 1_000_000;
type Associations = BTreeMap<i64, BTreeSet<i64>>;
type GroupLists = BTreeMap<i64, BTreeMap<String, ListInput>>;
struct Feed {
    url: String,
    action: Action,
    groups: BTreeSet<i64>,
    rows: usize,
}

pub(super) fn import(input: &[u8], report: &mut Report) -> Result<(), String> {
    let legacy = input.starts_with(&[0x1f, 0x8b]);
    let files = if legacy {
        let mut files = super::archive::tar_gz(input)?;
        let database = super::pihole_v5::database(&files, report)?;
        files.insert("gravity.db".into(), database);
        Some(files)
    } else if input.starts_with(b"PK") {
        Some(super::archive::zip(input)?)
    } else {
        None
    };
    let data = if let Some(files) = &files {
        let databases: Vec<_> = files
            .iter()
            .filter(|(name, _)| name == &"gravity.db" || name.ends_with("/gravity.db"))
            .collect();
        if databases.len() != 1 {
            return Err("Pi-hole ZIP must contain exactly one gravity.db".into());
        }
        databases[0].1.as_slice()
    } else {
        input
    };
    if !data.starts_with(b"SQLite format 3\0") {
        return Err("Pi-hole import needs a v5 Teleporter tar.gz, v6 Teleporter ZIP or gravity SQLite database".into());
    }
    let mut file =
        tempfile::NamedTempFile::new().map_err(|_| "Private import scratch file unavailable")?;
    file.write_all(data)
        .map_err(|_| "Import scratch write failed")?;
    file.flush().map_err(|_| "Import scratch flush failed")?;
    let db = Connection::open_with_flags(file.path(), OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|_| "Invalid Pi-hole SQLite database")?;
    db.set_limit(Limit::SQLITE_LIMIT_LENGTH, 1024 * 1024)
        .map_err(|_| "Source SQLite length limit unavailable")?;
    db.set_limit(Limit::SQLITE_LIMIT_COLUMN, 64)
        .map_err(|_| "Source SQLite column limit unavailable")?;
    db.set_limit(Limit::SQLITE_LIMIT_EXPR_DEPTH, 32)
        .map_err(|_| "Source SQLite expression limit unavailable")?;
    db.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA query_only=ON;")
        .map_err(|_| "Cannot restrict source database")?;
    let error = |_: rusqlite::Error| {
        "Pi-hole database schema/data is invalid or exceeds import bounds".to_owned()
    };
    for table in [
        "group",
        "domainlist",
        "adlist",
        "client",
        "domainlist_by_group",
        "adlist_by_group",
        "client_by_group",
    ] {
        if !table_exists(&db, table).map_err(error)? {
            return Err(format!("Pi-hole database is missing table {table}"));
        }
    }
    let mut groups = BTreeMap::new();
    let mut statement = db
        .prepare("SELECT id,enabled,name FROM \"group\" LIMIT 257")
        .map_err(error)?;
    for row in statement
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, bool>(1)?,
                r.get::<_, String>(2)?,
            ))
        })
        .map_err(error)?
    {
        let (id, enabled, name) = row.map_err(error)?;
        if groups.len() >= 256 || id < 0 || name.len() > 128 {
            return Err("Pi-hole group bounds exceeded".into());
        }
        groups.insert(id, (enabled, name));
    }
    groups.entry(0).or_insert_with(|| {
        report.issue(
            "group[0]",
            Severity::Blocker,
            "Default group is absent; no source-equivalent default policy can be assumed.",
        );
        (true, "Default".into())
    });
    let domain_groups = associations(&db, "domainlist_by_group", "domainlist_id").map_err(error)?;
    let feed_groups = associations(&db, "adlist_by_group", "adlist_id").map_err(error)?;
    let client_groups = associations(&db, "client_by_group", "client_id").map_err(error)?;
    for (table, associations) in [
        ("domainlist_by_group", &domain_groups),
        ("adlist_by_group", &feed_groups),
        ("client_by_group", &client_groups),
    ] {
        if associations
            .values()
            .flatten()
            .any(|group| !groups.contains_key(group))
        {
            report.issue(
                table,
                Severity::Blocker,
                "Source assignment references an unknown group; review before activation.",
            );
        }
    }
    let mut lists = GroupLists::new();
    let mut bytes = 0usize;
    let mut custom = db
        .prepare("SELECT id,type,domain FROM domainlist WHERE enabled=1 LIMIT 1000001")
        .map_err(error)?;
    for (index, row) in custom
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
            ))
        })
        .map_err(error)?
        .enumerate()
    {
        if index == MAX_ROWS {
            return Err("Pi-hole custom rule count exceeds one million".into());
        }
        let (id, kind, domain) = row.map_err(error)?;
        if !domain_groups.contains_key(&id) {
            report.issue(format!("domainlist[{id}].groups"), Severity::Blocker, "Source rule has no group assignments; destination default-group behavior requires explicit review.");
        }
        if domain.len() > 4096 {
            return Err("Pi-hole rule exceeds 4096 bytes".into());
        }
        let (action, text) = match kind {
            0 => (Action::Allow, format!("={domain}")),
            1 => (Action::Block, format!("={domain}")),
            2 | 3 => {
                if domain.contains(';')
                    || domain.contains('/')
                    || domain
                        .as_bytes()
                        .windows(2)
                        .any(|bytes| bytes[0] == b'\\' && bytes[1].is_ascii_alphanumeric())
                {
                    report.issue(format!("domainlist[{id}]"),Severity::Blocker,"FTL regex options, delimiters or POSIX escape extensions require manual translation; they were not silently interpreted as Rust regex.");
                    continue;
                }
                (
                    if kind == 2 {
                        Action::Allow
                    } else {
                        Action::Block
                    },
                    format!("/{domain}/"),
                )
            }
            _ => {
                report.issue(
                    format!("domainlist[{id}].type"),
                    Severity::Blocker,
                    "Unknown rule kind was not converted.",
                );
                continue;
            }
        };
        let memberships = domain_groups
            .get(&id)
            .cloned()
            .unwrap_or_else(|| BTreeSet::from([0]));
        for group in memberships {
            if groups.get(&group).is_some_and(|(enabled, _)| *enabled) {
                append(
                    &mut lists,
                    group,
                    format!("pi-hole/custom-{kind}"),
                    action,
                    &text,
                    &mut bytes,
                )?;
            } else if !groups.contains_key(&group) {
                report.issue(
                    format!("domainlist[{id}].group"),
                    Severity::Blocker,
                    "Rule references an unknown group.",
                );
            }
        }
    }
    let adlist_type = if column_exists(&db, "adlist", "type").map_err(error)? {
        "type"
    } else {
        "0"
    };
    let mut feeds = BTreeMap::new();
    let mut query = db
        .prepare(&format!(
            "SELECT id,address,{adlist_type} FROM adlist WHERE enabled=1 LIMIT 257"
        ))
        .map_err(error)?;
    for row in query
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })
        .map_err(error)?
    {
        let (id, url, kind) = row.map_err(error)?;
        if !feed_groups.contains_key(&id) {
            report.issue(format!("adlist[{id}].groups"), Severity::Blocker, "Source list has no group assignments; destination default-group behavior requires explicit review.");
        }
        if feeds.len() >= 256 || url.len() > 4096 {
            return Err("Pi-hole adlist bounds exceeded".into());
        }
        let action = match kind {
            0 => Action::Block,
            1 => Action::Allow,
            _ => {
                report.issue(
                    format!("adlist[{id}].type"),
                    Severity::Blocker,
                    "Unknown adlist kind",
                );
                continue;
            }
        };
        let memberships = feed_groups
            .get(&id)
            .cloned()
            .unwrap_or_else(|| BTreeSet::from([0]));
        feeds.insert(
            id,
            Feed {
                url,
                action,
                groups: memberships,
                rows: 0,
            },
        );
    }
    for table in ["gravity", "antigravity"] {
        if !table_exists(&db, table).map_err(error)? {
            continue;
        }
        let mut query = db
            .prepare(&format!(
                "SELECT domain,adlist_id FROM {table} LIMIT 1000001"
            ))
            .map_err(error)?;
        for (index, row) in query
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
            .map_err(error)?
            .enumerate()
        {
            if index == MAX_ROWS {
                return Err("Pi-hole gravity rule count exceeds one million".into());
            }
            let (domain, id) = row.map_err(error)?;
            if domain.len() > 253 {
                return Err("Pi-hole gravity domain is too long".into());
            }
            let Some(feed) = feeds.get_mut(&id) else {
                continue;
            };
            if (table == "gravity" && feed.action != Action::Block)
                || (table == "antigravity" && feed.action != Action::Allow)
            {
                return Err("Pi-hole adlist content/action mismatch".into());
            }
            feed.rows += 1;
            for group in &feed.groups {
                if groups.get(group).is_some_and(|(enabled, _)| *enabled) {
                    append(
                        &mut lists,
                        *group,
                        format!("pi-hole/adlist-{id}"),
                        feed.action,
                        &format!("={domain}"),
                        &mut bytes,
                    )?;
                }
            }
        }
    }
    let mut clients = Vec::new();
    let mut query = db
        .prepare("SELECT id,ip,COALESCE(comment,'') FROM client LIMIT 65537")
        .map_err(error)?;
    for row in query
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })
        .map_err(error)?
    {
        if clients.len() >= 65536 {
            return Err("Pi-hole client bounds exceeded".into());
        }
        let (id, identity, comment) = row.map_err(error)?;
        if !client_groups.contains_key(&id) {
            report.issue(format!("client[{id}].groups"), Severity::Blocker, "Source client has no group assignments; destination default-group behavior requires explicit review.");
        }
        if identity.len() > 256 || comment.len() > 1024 {
            return Err("Pi-hole client field is too large".into());
        }
        clients.push((id, identity, comment));
    }
    let mut sets: BTreeSet<Vec<i64>> = groups.keys().map(|id| vec![*id]).collect();
    sets.insert(vec![0]);
    for (id, _, _) in &clients {
        sets.insert(
            client_groups
                .get(id)
                .map_or_else(|| vec![0], |groups| groups.iter().copied().collect()),
        );
    }
    if sets.len() > 256 {
        return Err("Pi-hole group combinations exceed 256 destination policies".into());
    }
    let mut names = BTreeMap::new();
    let mut policies = Vec::new();
    let mut policy_bytes = 0usize;
    for set in sets {
        let identity = set
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("-");
        let name = if identity.len() <= 100 {
            format!("pi-hole/groups-{identity}")
        } else {
            let digest = ring::digest::digest(&ring::digest::SHA256, identity.as_bytes());
            format!(
                "pi-hole/groups-{:02x}{:02x}{:02x}{:02x}",
                digest.as_ref()[0],
                digest.as_ref()[1],
                digest.as_ref()[2],
                digest.as_ref()[3]
            )
        };
        let mut policy = report.policy(name.clone());
        for group in &set {
            if let Some(inputs) = lists.get(group) {
                for (label, list) in inputs {
                    policy_bytes = policy_bytes.saturating_add(list.rules.len());
                    if policy_bytes > MAX_EXPANDED_BYTES {
                        return Err("Materialized group policies exceed 64 MiB".into());
                    }
                    let mut list = list.clone();
                    list.name = format!("group-{group}/{label}");
                    report.translated_rules += list.rules.lines().count();
                    policy.lists.push(list);
                }
            }
        }
        names.insert(set, name);
        policies.push(policy);
    }
    let mut bindings = Vec::new();
    let mut networks = BTreeSet::new();
    for (id, identity, comment) in clients {
        let text = identity.parse::<IpAddr>().map_or(identity.clone(), |ip| {
            format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 })
        });
        let Ok(network) = text.parse() else {
            report.issue(format!("client[{id}].ip"),Severity::Blocker,"MAC/interface/hostname client identity needs discovery; no source-IP binding was invented.");
            continue;
        };
        if !networks.insert(network) {
            report.issue(
                format!("client[{id}].ip"),
                Severity::Blocker,
                "Duplicate client network",
            );
            continue;
        }
        let set = client_groups
            .get(&id)
            .map_or_else(|| vec![0], |groups| groups.iter().copied().collect());
        let policy = names
            .get(&set)
            .ok_or("Missing imported client policy")?
            .clone();
        let label = if comment.is_empty() {
            identity
        } else {
            comment
        };
        bindings.push(Binding {
            name: label,
            network,
            policy,
            filter_tags: Vec::new(),
            metadata: None,
        });
    }
    report.config.default_policy = names
        .get(&vec![0])
        .ok_or("Missing default group policy")?
        .clone();
    report.config.policies = policies;
    report.config.bindings = bindings;
    for (id, feed) in feeds {
        let needs_download = feed.rows == 0;
        let url = match super::publisher_url(&feed.url) {
            Ok(url) => url,
            Err(error) => {
                report.issue(format!("adlist[{id}].url"), Severity::Blocker, error);
                continue;
            }
        };
        if needs_download
            && feed
                .groups
                .iter()
                .any(|group| groups.get(group).is_some_and(|(enabled, _)| *enabled))
        {
            report.issue(format!("adlist[{id}]"),Severity::Blocker,"Export omits this enabled list's domains. Fetch and review its contents before equivalent activation.");
        }
        for (set, policy) in &names {
            for group in set {
                if feed.groups.contains(group) {
                    if report.publishers.len() >= 4096 {
                        return Err("Too many imported publisher references".into());
                    }
                    report.publishers.push(Publisher {
                        policy: policy.clone(),
                        list: format!("group-{group}/pi-hole/adlist-{id}"),
                        url: url.clone(),
                        action: feed.action,
                        needs_download,
                    });
                }
            }
        }
    }
    if let Some(files) = &files {
        if legacy {
            super::pihole_v5::settings(files, report)?;
        }
        let settings: Vec<_> = files
            .iter()
            .filter(|(name, _)| name == &"pihole.toml" || name.ends_with("/pihole.toml"))
            .collect();
        if settings.len() > 1 {
            return Err("Ambiguous pihole.toml files".into());
        }
        if let Some((_, data)) = settings.first() {
            settings_toml(data, report)?;
        }
        for (name, data) in files {
            if name == "custom.list" || name.ends_with("/custom.list") {
                hosts(data, report)?;
            }
        }
    } else {
        report.issue("pihole.toml",Severity::Warning,"A standalone gravity database omits local DNS, upstream and DHCP settings. Supply a Teleporter export to include those settings.");
    }
    report.issue("administration",Severity::Info,"Destination listener admission, credentials and history remain independent. Imported groups select policy and never grant DNS access.");
    Ok(())
}
fn table_exists(db: &Connection, name: &str) -> rusqlite::Result<bool> {
    db.query_row(
        "SELECT count(*) FROM pragma_table_list WHERE schema='main' AND type='table' AND name=?1",
        [name],
        |row| row.get::<_, i64>(0),
    )
    .map(|count| count == 1)
}
fn column_exists(db: &Connection, table: &str, column: &str) -> rusqlite::Result<bool> {
    db.query_row(
        "SELECT count(*) FROM pragma_table_info(?1) WHERE name=?2",
        [table, column],
        |row| row.get::<_, i64>(0),
    )
    .map(|count| count == 1)
}
fn associations(db: &Connection, table: &str, id: &str) -> rusqlite::Result<Associations> {
    let mut statement = db.prepare(&format!("SELECT {id},group_id FROM {table} LIMIT 1000001"))?;
    let mut associations = Associations::new();
    for (index, row) in statement
        .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?
        .enumerate()
    {
        if index == MAX_ROWS {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let (id, group) = row?;
        associations.entry(id).or_default().insert(group);
    }
    Ok(associations)
}
fn append(
    lists: &mut GroupLists,
    group: i64,
    label: String,
    action: Action,
    text: &str,
    bytes: &mut usize,
) -> Result<(), String> {
    *bytes = bytes.saturating_add(text.len() + 1);
    if *bytes > MAX_EXPANDED_BYTES {
        return Err("Imported rule text exceeds 64 MiB".into());
    }
    let list = lists
        .entry(group)
        .or_default()
        .entry(label.clone())
        .or_insert_with(|| ListInput {
            syntax: Default::default(),
            name: label,
            action,
            rules: String::new(),
        });
    list.rules.push_str(text);
    list.rules.push('\n');
    Ok(())
}
pub(super) fn hosts(input: &[u8], report: &mut Report) -> Result<(), String> {
    let text = std::str::from_utf8(input).map_err(|_| "Local DNS file must be UTF-8")?;
    let mut records = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split_whitespace();
        let address = fields
            .next()
            .ok_or("Empty host row")?
            .parse::<IpAddr>()
            .map_err(|_| format!("Invalid IP in local DNS row {}", index + 1))?;
        for domain in fields {
            records.push(LocalRecord {
                domain: domain.into(),
                ttl: 60,
                data: match address {
                    IpAddr::V4(address) => LocalData::A { address },
                    IpAddr::V6(address) => LocalData::Aaaa { address },
                },
            });
        }
        if records.len() > 10000 {
            return Err("Too many local DNS records".into());
        }
    }
    if records.len().saturating_mul(report.config.policies.len()) > 10000 {
        return Err("Combined local DNS import exceeds 10000 records".into());
    }
    for policy in &mut report.config.policies {
        policy.dns_records.extend(records.clone());
    }
    Ok(())
}
pub(super) fn settings_toml(input: &[u8], report: &mut Report) -> Result<(), String> {
    if input.len() > super::MAX_INPUT_BYTES {
        return Err("pihole.toml exceeds 16 MiB".into());
    }
    let text = std::str::from_utf8(input).map_err(|_| "pihole.toml must be UTF-8")?;
    let root: serde_json::Value = toml::from_str(text).map_err(|_| "Invalid pihole.toml")?;
    report.unreviewed(
        &root,
        "pihole",
        &["dns", "dhcp"],
        &["webserver", "database", "ntp", "files", "debug"],
    );
    let dns = &root["dns"];
    super::booleans(dns, "dns", &["dnssec", "CNAMEdeepInspect"])?;
    super::booleans(&dns["blocking"], "dns.blocking", &["active"])?;
    report.unreviewed(&dns["blocking"], "dns.blocking", &["active"], &[]);
    report.unreviewed(
        dns,
        "dns",
        &[
            "upstreams",
            "hosts",
            "cnameRecords",
            "revServers",
            "dnssec",
            "blockTTL",
            "blocking",
            "CNAMEdeepInspect",
        ],
        &[
            "interface",
            "listeningMode",
            "port",
            "queryLogging",
            "cache",
            "analyzeOnlyAandAAAA",
            "EDNS0ECS",
            "expandHosts",
            "domainNeeded",
            "bogusPriv",
            "domain",
        ],
    );
    let old_upstream = report.config.upstreams[0].name.clone();
    report.literal_upstreams(
        &super::string_array(&dns["upstreams"], "dns.upstreams")?,
        "dns.upstreams",
    );
    if report.config.upstreams[0].name != old_upstream {
        let name = report.config.upstreams[0].name.clone();
        for policy in &mut report.config.policies {
            policy.upstream = name.clone();
        }
    }
    let hosts_text = super::string_array(&dns["hosts"], "dns.hosts")?.join("\n");
    hosts(hosts_text.as_bytes(), report)?;
    let mut aliases = Vec::new();
    for (index, value) in super::string_array(&dns["cnameRecords"], "dns.cnameRecords")?
        .iter()
        .enumerate()
    {
        let fields: Vec<_> = value.trim_start_matches("cname=").split(',').collect();
        if !(2..=3).contains(&fields.len()) {
            return Err(format!("Invalid dns.cnameRecords[{index}]"));
        }
        let ttl = if fields.len() == 3 {
            fields[2].parse::<u32>().map_err(|_| "Invalid CNAME TTL")?
        } else {
            60
        };
        aliases.push(LocalRecord {
            domain: fields[0].into(),
            ttl,
            data: LocalData::Cname {
                target: fields[1].into(),
            },
        });
    }
    if report
        .config
        .policies
        .iter()
        .map(|p| p.dns_records.len())
        .sum::<usize>()
        .saturating_add(aliases.len().saturating_mul(report.config.policies.len()))
        > 10000
    {
        return Err("Combined local DNS import exceeds 10000 records".into());
    }
    for policy in &mut report.config.policies {
        policy.dns_records.extend(aliases.clone());
    }
    for (index, value) in super::string_array(&dns["revServers"], "dns.revServers")?
        .iter()
        .enumerate()
    {
        let fields: Vec<_> = value.split(',').collect();
        if fields.first() == Some(&"false") {
            continue;
        }
        if fields.len() < 3 || fields[0] != "true" {
            report.issue(
                format!("dns.revServers[{index}]"),
                Severity::Blocker,
                "Invalid reverse-server declaration",
            );
            continue;
        }
        let network = fields[1]
            .parse::<ipnet::IpNet>()
            .map_err(|_| "Invalid reverse-server network")?;
        let address =
            literal_address(fields[2]).ok_or("Reverse-server address needs a literal IP")?;
        let zone = match network {
            ipnet::IpNet::V4(net) if net.prefix_len() % 8 == 0 => {
                let count = usize::from(net.prefix_len() / 8);
                let mut labels = net.network().octets()[..count]
                    .iter()
                    .rev()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>();
                labels.push("in-addr".into());
                labels.push("arpa".into());
                labels.join(".")
            }
            ipnet::IpNet::V6(net) if net.prefix_len() % 4 == 0 => {
                let hex = format!("{:032x}", u128::from(net.network()));
                let mut labels = hex[..usize::from(net.prefix_len() / 4)]
                    .chars()
                    .rev()
                    .map(|c| c.to_string())
                    .collect::<Vec<_>>();
                labels.push("ip6".into());
                labels.push("arpa".into());
                labels.join(".")
            }
            _ => {
                report.issue(
                    format!("dns.revServers[{index}]"),
                    Severity::Blocker,
                    "Non-byte/nibble reverse routing needs an explicit equivalent",
                );
                continue;
            }
        };
        let name = format!("pi-hole/reverse-{index}");
        report.config.upstreams.push(UpstreamProfile {
            name: name.clone(),
            addresses: vec![address],
            timeout_ms: 1500,
            transport: UpstreamTransport::Udp,
        });
        for policy in &mut report.config.policies {
            policy.routes.push(DomainRoute {
                domain: zone.clone(),
                upstream: name.clone(),
            });
            if let Some(domain) = fields.get(3).filter(|domain| !domain.is_empty()) {
                policy.routes.push(DomainRoute {
                    domain: (*domain).into(),
                    upstream: name.clone(),
                });
            }
        }
    }
    if dns["dnssec"].as_bool() == Some(true) {
        report.issue("dns.dnssec",Severity::Blocker,"Configure and verify Unbound/DNSSEC mode on the destination; source validation is not silently assumed.");
    }
    if dns["CNAMEdeepInspect"].as_bool() == Some(false) {
        report.issue("dns.CNAMEdeepInspect",Severity::Warning,"Destination inspects reachable CNAME targets; protection is stricter than this source setting.");
    }
    if root["dhcp"]["active"].as_bool() == Some(true) {
        report.issue("dhcp.active",Severity::Blocker,"DHCP needs reviewed deployment of the separate component; import does not take over leases.");
    }
    if dns["blocking"]["active"].as_bool() == Some(false) {
        report.issue(
            "dns.blocking.active",
            Severity::Blocker,
            "Source blocking was disabled. Review desired protection state before activation.",
        );
    }
    Ok(())
}
