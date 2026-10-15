#![allow(clippy::unwrap_used)]
use rustwalld_dns::migration::{self, Source};
use rustwalld_dns_filter::Action;
use rustwalld_dns_policy::{PolicyConfigSet, PolicySnapshot, UpstreamProfile, UpstreamTransport};
use std::io::{Cursor, Write};
fn legacy_archive(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut tar = tar::Builder::new(Vec::new());
    for (name, bytes) in files {
        let mut header = tar::Header::new_ustar();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o600);
        header.set_cksum();
        tar.append_data(&mut header, *name, *bytes).unwrap();
    }
    let raw = tar.into_inner().unwrap();
    gzip(&raw)
}
fn gzip(raw: &[u8]) -> Vec<u8> {
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gzip.write_all(raw).unwrap();
    gzip.finish().unwrap()
}
fn legacy_files() -> Vec<(&'static str, &'static [u8])> {
    vec![
        ("group.json",br#"[{"id":0,"enabled":1,"name":"Default"},{"id":1,"enabled":1,"name":"TV"}]"#),
        ("client.json",br#"[{"id":3,"ip":"127.0.0.2","comment":"TV"}]"#),
        ("whitelist.exact.json",br#"[{"id":1,"domain":"safe.test","enabled":1,"type":0}]"#),
        ("blacklist.exact.json",br#"[{"id":2,"domain":"ads.test","enabled":1,"type":1}]"#),
        ("whitelist.regex.json",b"[]"),
        ("blacklist.regex.json",br#"[{"id":4,"domain":"^track[0-9]+\\.test$","enabled":1,"type":3}]"#),
        ("adlist.json",b"[]"),
        ("domainlist_by_group.json",br#"[{"domainlist_id":1,"group_id":0},{"domainlist_id":2,"group_id":0},{"domainlist_id":4,"group_id":1}]"#),
        ("adlist_by_group.json",b"[]"),
        ("client_by_group.json",br#"[{"client_id":3,"group_id":1}]"#),
        ("setupVars.conf",b"PIHOLE_DNS_1=127.0.0.1#15354\nDNSSEC=false\nDHCP_ACTIVE=false\nWEBPASSWORD=NEVER_COPY_ME\n"),
        ("pihole-FTL.conf",b"BLOCKINGMODE=NODATA\n"),
        ("custom.list",b"192.0.2.10 nas.home.arpa\n"),
        ("dnsmasq.d/05-pihole-custom-cname.conf",b"cname=storage.home.arpa,files.home.arpa,nas.home.arpa,40\n"),
    ]
}
#[test]
fn v5_rules_groups_aliases_modes_and_literal_upstreams_translate() {
    let report = migration::preview(
        Source::Pihole,
        &legacy_archive(&legacy_files()),
        PolicyConfigSet::default(),
    )
    .unwrap();
    assert!(
        report.ready,
        "{}",
        serde_json::to_string(&report.issues).unwrap()
    );
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains("NEVER_COPY_ME")
    );
    assert_eq!(
        report.config.policies[0].block_mode,
        rustwalld_dns_policy::BlockMode::NoData
    );
    let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
    let local = "127.0.0.1".parse().unwrap();
    let tv = "127.0.0.2".parse().unwrap();
    assert_eq!(
        snapshot.explain(local, "ads.test").unwrap().decision.action,
        Action::Block
    );
    assert_eq!(
        snapshot
            .explain(local, "child.ads.test")
            .unwrap()
            .decision
            .action,
        Action::Allow
    );
    assert_eq!(
        snapshot.explain(tv, "ads.test").unwrap().decision.action,
        Action::Allow
    );
    assert_eq!(
        snapshot
            .explain(tv, "track12.test")
            .unwrap()
            .decision
            .action,
        Action::Block
    );
    assert!(snapshot.select(local).policy.has_rewrite("files.home.arpa"));
    assert_eq!(
        snapshot.explain(local, "nas.home.arpa").unwrap().upstream,
        "pi-hole/v5/default"
    );
}
#[test]
fn v5_missing_feeds_settings_and_privacy_remain_blockers() {
    let mut files = legacy_files();
    files.retain(|(name, _)| !matches!(*name, "adlist.json" | "adlist_by_group.json"));
    files.extend([
        (
            "adlist.json",
            br#"[{"id":7,"enabled":1,"address":"https://publisher.test/list"}]"#.as_slice(),
        ),
        (
            "adlist_by_group.json",
            br#"[{"adlist_id":7,"group_id":0}]"#.as_slice(),
        ),
        (
            "dnsmasq.d/custom.conf",
            b"dhcp-range=192.0.2.10,192.0.2.20\nunknown-directive=PRIVATE_VALUE\n".as_slice(),
        ),
    ]);
    let report = migration::preview(
        Source::Pihole,
        &legacy_archive(&files),
        PolicyConfigSet::default(),
    )
    .unwrap();
    assert!(!report.ready);
    assert!(report.blockers >= 3);
    assert!(report.publishers[0].needs_download);
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains("PRIVATE_VALUE")
    );
    files.retain(|(name, _)| *name != "pihole-FTL.conf");
    files.push(("pihole-FTL.conf", b"PRIVACYLEVEL=3\n"));
    let report = migration::preview(
        Source::Pihole,
        &legacy_archive(&files),
        PolicyConfigSet::default(),
    )
    .unwrap();
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.field == "pihole-FTL.conf.PRIVACYLEVEL"
                && issue.severity == migration::Severity::Blocker)
    );
}
#[test]
fn v5_missing_duplicate_malformed_and_dangling_tables_are_rejected() {
    for (file, bytes) in [
        (
            "group.json",
            b"[{\"id\":0,\"enabled\":1,\"name\":\"a\"},{\"id\":0,\"enabled\":1,\"name\":\"b\"}]"
                .as_slice(),
        ),
        (
            "client_by_group.json",
            b"[{\"client_id\":3,\"group_id\":999}]".as_slice(),
        ),
        (
            "blacklist.exact.json",
            b"[{\"id\":2,\"domain\":\"ads.test\",\"enabled\":\"0\",\"type\":1}]".as_slice(),
        ),
        (
            "blacklist.exact.json",
            b"[{\"id\":2,\"domain\":\"ads.test\",\"enabled\":1,\"type\":3}]".as_slice(),
        ),
        (
            "group.json",
            b"[{\"id\":0,\"id\":1,\"enabled\":1,\"name\":\"a\"}]".as_slice(),
        ),
    ] {
        let mut files = legacy_files();
        files.retain(|(name, _)| *name != file);
        files.push((file, bytes));
        assert!(
            migration::preview(
                Source::Pihole,
                &legacy_archive(&files),
                PolicyConfigSet::default()
            )
            .is_err(),
            "{file}"
        );
    }
    let mut files = legacy_files();
    files.retain(|(name, _)| *name != "client_by_group.json");
    assert!(
        migration::preview(
            Source::Pihole,
            &legacy_archive(&files),
            PolicyConfigSet::default()
        )
        .is_err()
    );
}
#[test]
fn gzip_checksums_links_duplicates_hidden_data_and_expansion_are_rejected() {
    let input = legacy_archive(&legacy_files());
    let mut broken = input.clone();
    let n = broken.len();
    broken[n - 8] ^= 1;
    assert!(migration::preview(Source::Pihole, &broken, PolicyConfigSet::default()).is_err());
    assert!(
        migration::preview(
            Source::Pihole,
            &input[..input.len() - 8],
            PolicyConfigSet::default()
        )
        .is_err()
    );
    assert!(
        migration::preview(
            Source::Pihole,
            &legacy_archive(&[("same", b"a"), ("same", b"b")]),
            PolicyConfigSet::default()
        )
        .is_err()
    );
    let mut tar = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_ustar();
    header.set_size(0);
    header.set_mode(0o600);
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_link_name("/etc/passwd").unwrap();
    header.set_cksum();
    tar.append_data(&mut header, "link", Cursor::new(Vec::<u8>::new()))
        .unwrap();
    assert!(
        migration::preview(
            Source::Pihole,
            &gzip(&tar.into_inner().unwrap()),
            PolicyConfigSet::default()
        )
        .is_err()
    );
    let mut hidden = input.clone();
    hidden.extend(gzip(b"hidden-data"));
    assert!(migration::preview(Source::Pihole, &hidden, PolicyConfigSet::default()).is_err());
    assert!(
        migration::preview(
            Source::Pihole,
            &gzip(&vec![0; 64 * 1024 * 1024 + 1]),
            PolicyConfigSet::default()
        )
        .is_err()
    );
}
#[test]
fn adguard_suffix_routes_choose_most_specific_resolver_and_preserve_base_admission() {
    let base = PolicyConfigSet::default();
    let admission = base.allowed_clients.clone();
    let report=migration::preview(Source::Adguard,b"dns:\n  upstream_dns: ['127.0.0.1:15354', '[/home.arpa/]127.0.0.1:15355', '[/tv.home.arpa/]127.0.0.2:15355']\n",base).unwrap();
    assert!(report.ready);
    assert!(report.validation.as_ref().unwrap().valid);
    assert_eq!(
        report.config.policies[0].ds_routing,
        rustwalld_dns_policy::DsRouting::Parent
    );
    assert_eq!(report.config.allowed_clients, admission);
    let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
    let local = "127.0.0.1".parse().unwrap();
    assert_eq!(
        snapshot.explain(local, "external.test").unwrap().upstream,
        "adguard/upstreams/default"
    );
    assert_eq!(
        snapshot.explain(local, "nas.home.arpa").unwrap().upstream,
        "adguard/upstreams/route-0"
    );
    assert_eq!(
        snapshot
            .explain(local, "child.tv.home.arpa")
            .unwrap()
            .upstream,
        "adguard/upstreams/route-1"
    );
}
#[test]
fn adguard_encrypted_upstreams_reuse_only_exact_destination_identity_port_path_and_trust() {
    use rustwalld_dns_policy::{UpstreamProfile, UpstreamTransport};
    let mut base = PolicyConfigSet::default();
    base.upstreams.push(UpstreamProfile {
        name: "pinned-dot".into(),
        addresses: vec!["127.0.0.1:1853".parse().unwrap()],
        timeout_ms: 1200,
        transport: UpstreamTransport::Tls {
            server_name: "resolver.test".into(),
            ca_pem: None,
            max_connections: 1,
        },
    });
    let original = base.upstreams.clone();
    let report = migration::preview(
        Source::Adguard,
        b"dns:\n  upstream_dns: ['tls://resolver.test:1853']\n  bootstrap_dns: ['192.0.2.99']\n",
        base.clone(),
    )
    .unwrap();
    assert!(
        report.ready,
        "{}",
        serde_json::to_string(&report.issues).unwrap()
    );
    let imported = report
        .config
        .upstreams
        .iter()
        .find(|p| p.name == "adguard/upstreams/default")
        .unwrap();
    assert_eq!(imported.addresses, original[1].addresses);
    assert_eq!(imported.transport, original[1].transport);
    for endpoint in [
        "tls://resolver.test:853",
        "tls://other.test:1853",
        "tls://127.0.0.1:1853",
        "https://resolver.test:1853/dns-query",
        "quic://resolver.test:1853",
        "tls://user:PRIVATE@resolver.test:1853",
    ] {
        let input =
            format!("dns:\n  upstream_dns: ['{endpoint}']\n  bootstrap_dns: ['192.0.2.99']\n");
        let report = migration::preview(Source::Adguard, input.as_bytes(), base.clone()).unwrap();
        assert!(!report.ready, "{endpoint}");
        assert_eq!(report.config.upstreams, original);
        assert!(!serde_json::to_string(&report).unwrap().contains("PRIVATE"));
    }
    base.upstreams.push(UpstreamProfile {
        name: "ambiguous".into(),
        addresses: vec!["127.0.0.2:1853".parse().unwrap()],
        ..base.upstreams[1].clone()
    });
    assert!(
        !migration::preview(
            Source::Adguard,
            b"dns: {upstream_dns: ['tls://resolver.test:1853']}",
            base
        )
        .unwrap()
        .ready
    );
}
#[test]
fn adguard_unsupported_or_mixed_resolvers_never_silently_drop_a_fallback() {
    let base = PolicyConfigSet::default();
    for values in [
        "'127.0.0.1:15354', 'tls://missing.test'",
        "'[/home.arpa/]127.0.0.1:15355', '[/bad.test/]#'",
        "'[//]127.0.0.1'",
        "'[/*.test/]127.0.0.1'",
        "'[/home.arpa/]127.0.0.1', '[/HOME.ARPA/]resolver.test'",
    ] {
        let input = format!("dns: {{upstream_dns: [{values}]}}");
        let report = migration::preview(Source::Adguard, input.as_bytes(), base.clone()).unwrap();
        assert!(!report.ready);
        assert_eq!(report.config.upstreams, base.upstreams);
        assert!(report.config.policies[0].routes.is_empty());
    }
}
#[test]
fn v5_unknown_table_fields_and_empty_client_assignments_are_blockers() {
    for (file,bytes,expected) in [
        ("group.json",br#"[{"id":0,"enabled":1,"name":"Default","future_policy_flag":"PRIVATE"},{"id":1,"enabled":1,"name":"TV"}]"#.as_slice(),"group.json.future_policy_flag"),
        ("client_by_group.json",b"[]".as_slice(),"client[3].groups"),
        ("pihole-FTL.conf",b"MAXDBDAYS=0\n".as_slice(),"pihole-FTL.conf.MAXDBDAYS"),
        ("setupVars.conf",b"QUERY_LOGGING=false\n".as_slice(),"setupVars.conf.QUERY_LOGGING"),
    ] {
        let mut files=legacy_files();files.retain(|(name,_)|*name!=file);files.push((file,bytes));
        let report=migration::preview(Source::Pihole,&legacy_archive(&files),PolicyConfigSet::default()).unwrap();
        assert!(!report.ready);assert!(report.issues.iter().any(|issue|issue.field==expected && issue.severity==migration::Severity::Blocker));
        assert!(!serde_json::to_string(&report).unwrap().contains("PRIVATE"));
    }
}
#[test]
fn tar_unsafe_paths_extensions_and_entry_count_are_rejected() {
    let mut tar = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_ustar();
    header.set_size(0);
    header.set_mode(0o600);
    header.set_cksum();
    tar.append_data(&mut header, "entry", Cursor::new(Vec::<u8>::new()))
        .unwrap();
    let raw = tar.into_inner().unwrap();
    // Valid gzip around a TAR missing both/one terminal blocks, or a partial block.
    for len in [512, 1024, 1025] {
        let error = migration::preview(
            Source::Pihole,
            &gzip(&raw[..len]),
            PolicyConfigSet::default(),
        )
        .err()
        .unwrap();
        assert!(error.contains("end markers"), "{error}");
    }
    for name in [
        "../group.json",
        "/group.json",
        "dir\\group.json",
        "C:group.json",
    ] {
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_ustar();
        header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
        header.set_mode(0o600);
        header.set_size(0);
        header.set_cksum();
        tar.append(&header, Cursor::new(Vec::<u8>::new())).unwrap();
        let error = migration::preview(
            Source::Pihole,
            &gzip(&tar.into_inner().unwrap()),
            PolicyConfigSet::default(),
        )
        .err()
        .unwrap();
        assert!(error.contains("Unsafe TAR"), "{error}");
    }
    for kind in [
        tar::EntryType::Link,
        tar::EntryType::GNUSparse,
        tar::EntryType::XHeader,
        tar::EntryType::GNULongName,
    ] {
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_ustar();
        header.set_size(0);
        header.set_mode(0o600);
        header.set_entry_type(kind);
        header.set_cksum();
        tar.append_data(&mut header, "entry", Cursor::new(Vec::<u8>::new()))
            .unwrap();
        assert!(
            migration::preview(
                Source::Pihole,
                &gzip(&tar.into_inner().unwrap()),
                PolicyConfigSet::default()
            )
            .is_err()
        );
    }
    let names: Vec<_> = (0..132).map(|index| format!("file-{index}")).collect();
    let files: Vec<_> = names
        .iter()
        .map(|name| (name.as_str(), b"".as_slice()))
        .collect();
    let error = migration::preview(
        Source::Pihole,
        &legacy_archive(&files),
        PolicyConfigSet::default(),
    )
    .err()
    .unwrap();
    assert!(error.contains("64 entries"));
}
#[test]
fn adguard_https_path_query_and_private_ca_are_preserved_without_network() {
    use rustwalld_dns_policy::{UpstreamProfile, UpstreamTransport};
    let mut base = PolicyConfigSet::default();
    let pem = rcgen::generate_simple_self_signed(vec!["resolver.test".into()])
        .unwrap()
        .cert
        .pem();
    base.upstreams.push(UpstreamProfile {
        name: "private-doh".into(),
        addresses: vec!["127.0.0.1:1443".parse().unwrap()],
        timeout_ms: 450,
        transport: UpstreamTransport::Https {
            server_name: "resolver.test".into(),
            path: "/private-query?profile=home".into(),
            ca_pem: Some(pem),
            max_connections: 1,
        },
    });
    let original = base.upstreams.clone();
    let source=b"dns: {upstream_dns: ['https://resolver.test:1443/private-query?profile=home'], bootstrap_dns: ['192.0.2.99']}";
    let report = migration::preview(Source::Adguard, source, base.clone()).unwrap();
    assert!(
        report.ready,
        "{}",
        serde_json::to_string(&report.issues).unwrap()
    );
    let imported = report
        .config
        .upstreams
        .iter()
        .find(|p| p.name == "adguard/upstreams/default")
        .unwrap();
    assert_eq!(imported.transport, original[1].transport);
    assert_eq!(imported.addresses, original[1].addresses);
    assert_eq!(imported.timeout_ms, 450);
    for source in [
        "https://resolver.test:1443/private-query?profile=other",
        "https://resolver.test:1443/dns-query",
    ] {
        let report = migration::preview(
            Source::Adguard,
            format!("dns: {{upstream_dns: ['{source}']}}").as_bytes(),
            base.clone(),
        )
        .unwrap();
        assert!(!report.ready);
        assert_eq!(report.config.upstreams, original);
    }
}

#[test]
fn explicit_adguard_safesearch_provider_choices_preserve_client_inheritance() {
    use rustwalld_dns_policy::YouTubeMode;
    let source=br#"filtering:
  safe_search: {enabled: true, google: true, bing: true, duckduckgo: true, youtube: true, yandex: false, pixabay: false, ecosia: false}
clients:
  persistent:
    - name: inherited
      ids: [127.0.0.2]
      use_global_safesearch: true
    - name: off
      ids: [127.0.0.3]
      use_global_safesearch: false
      safe_search: {enabled: false}
    - name: bing-only
      ids: [127.0.0.4]
      use_global_safesearch: false
      safe_search: {enabled: true, google: false, bing: true, duckduckgo: false, youtube: false, yandex: false, pixabay: false, ecosia: false}
"#;
    let report = migration::preview(Source::Adguard, source, PolicyConfigSet::default()).unwrap();
    assert!(
        report.ready,
        "{}",
        serde_json::to_string(&report.issues).unwrap()
    );
    let global = report.config.policies[0].safe_search.as_ref().unwrap();
    assert_eq!(global.youtube, YouTubeMode::Moderate);
    assert_eq!(report.config.policies[1].safe_search.as_ref(), Some(global));
    assert!(report.config.policies[2].safe_search.is_none());
    let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
    assert!(
        snapshot
            .select("127.0.0.2".parse().unwrap())
            .policy
            .safe_search_match("www.google.com")
            .is_some()
    );
    assert!(
        snapshot
            .select("127.0.0.3".parse().unwrap())
            .policy
            .safe_search_match("www.google.com")
            .is_none()
    );
    assert!(
        snapshot
            .select("127.0.0.4".parse().unwrap())
            .policy
            .safe_search_match("www.google.com")
            .is_none()
    );
    assert!(
        snapshot
            .select("127.0.0.4".parse().unwrap())
            .policy
            .safe_search_match("www.bing.com")
            .is_some()
    );
}
#[test]
fn ambiguous_provider_flags_legacy_enablement_and_unsupported_providers_are_blockers() {
    for source in [
        "filtering: {safesearch_enabled: true}",
        "filtering: {safe_search: {enabled: true, bing: true}}",
        "filtering: {safe_search: {enabled: true, google: false, bing: true, duckduckgo: false, youtube: false, yandex: true, pixabay: false, ecosia: false}}",
        "filtering: {safe_search: {enabled: true, google: null, bing: true, duckduckgo: false, youtube: false, yandex: false, pixabay: false, ecosia: false}}",
        "clients: {persistent: [{ids: [127.0.0.2], safe_search: {enabled: false}}]}",
        "filtering: {safe_search: {enabled: false, schedule: PRIVATE_SOURCE_VALUE}}",
        "filtering: {safe_search: {enabled: true, google: true, bing: false, duckduckgo: false, youtube: false, yandex: false, pixabay: false, ecosia: false}}\nclients: {persistent: [{ids: [127.0.0.2], use_global_settings: false, safesearch_enabled: false}]}",
    ] {
        let report = migration::preview(
            Source::Adguard,
            source.as_bytes(),
            PolicyConfigSet::default(),
        )
        .unwrap();
        assert!(!report.ready, "{source}");
        assert!(report.blockers > 0);
        assert!(
            !serde_json::to_string(&report)
                .unwrap()
                .contains("PRIVATE_SOURCE_VALUE")
        );
    }
    for source in [
        "filtering: {safe_search: {enabled: true, bing: 'false'}}",
        "clients: {persistent: [{ids: [127.0.0.2], use_global_safesearch: 'false'}]}",
    ] {
        assert!(
            migration::preview(
                Source::Adguard,
                source.as_bytes(),
                PolicyConfigSet::default()
            )
            .is_err()
        );
    }
}
fn archive(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in files {
        zip.start_file(
            *name,
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored),
        )
        .unwrap();
        zip.write_all(data).unwrap();
    }
    zip.finish().unwrap().into_inner()
}
fn gravity() -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gravity.db");
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch("CREATE TABLE \"group\"(id INTEGER,enabled INTEGER,name TEXT);CREATE TABLE domainlist(id INTEGER,type INTEGER,domain TEXT,enabled INTEGER);CREATE TABLE adlist(id INTEGER,address TEXT,enabled INTEGER,type INTEGER);CREATE TABLE client(id INTEGER,ip TEXT,comment TEXT);CREATE TABLE domainlist_by_group(domainlist_id INTEGER,group_id INTEGER);CREATE TABLE adlist_by_group(adlist_id INTEGER,group_id INTEGER);CREATE TABLE client_by_group(client_id INTEGER,group_id INTEGER);CREATE TABLE gravity(domain TEXT,adlist_id INTEGER);INSERT INTO \"group\" VALUES(0,1,'Default'),(1,1,'IoT');INSERT INTO domainlist VALUES(1,1,'ads.test',1),(2,0,'safe.test',1),(3,3,'^track[0-9]+\\.test$',1);INSERT INTO domainlist_by_group VALUES(1,0),(2,0),(3,1);INSERT INTO adlist VALUES(7,'https://publisher.test/list',1,0);INSERT INTO adlist_by_group VALUES(7,0);INSERT INTO gravity VALUES('gravity.test',7);INSERT INTO client VALUES(1,'127.0.0.2','TV');INSERT INTO client_by_group VALUES(1,1);").unwrap();
    drop(db);
    std::fs::read(path).unwrap()
}
#[test]
fn pihole_groups_exact_gravity_regex_local_dns_and_reverse_routes_translate() {
    let db = gravity();
    let settings=b"[dns]\nupstreams=['127.0.0.1#15354']\nhosts=['192.0.2.10 nas.home.arpa']\ncnameRecords=['storage.home.arpa,nas.home.arpa,40']\nrevServers=['true,192.0.2.0/24,127.0.0.1#15355,home.arpa']\n";
    let input = archive(&[
        ("etc/pihole/gravity.db", &db),
        ("etc/pihole/pihole.toml", settings),
    ]);
    let report = migration::preview(Source::Pihole, &input, PolicyConfigSet::default()).unwrap();
    assert!(
        report.ready,
        "{}",
        serde_json::to_string(&report.issues).unwrap()
    );
    let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
    let local = "127.0.0.1".parse().unwrap();
    let tv = "127.0.0.2".parse().unwrap();
    assert_eq!(
        snapshot
            .explain(local, "gravity.test")
            .unwrap()
            .decision
            .action,
        Action::Block
    );
    assert_eq!(
        snapshot
            .explain(local, "child.gravity.test")
            .unwrap()
            .decision
            .action,
        Action::Allow
    );
    assert_eq!(
        snapshot.explain(local, "ads.test").unwrap().decision.action,
        Action::Block
    );
    assert_eq!(
        snapshot.explain(tv, "ads.test").unwrap().decision.action,
        Action::Allow
    );
    assert_eq!(
        snapshot
            .explain(tv, "track12.test")
            .unwrap()
            .decision
            .action,
        Action::Block
    );
    assert!(
        snapshot
            .select(local)
            .policy
            .has_rewrite("storage.home.arpa")
    );
    assert_eq!(
        snapshot.explain(local, "nas.home.arpa").unwrap().upstream,
        "pi-hole/reverse-0"
    );
}
#[test]
fn adguard_exact_domain_suffix_regex_and_scoped_client_settings_translate() {
    let input = br#"dns:
  upstream_dns: [127.0.0.1:15354]
user_rules:
  - ads.test
  - '||tracking.test^'
  - '@@|safe.tracking.test^'
  - '/^metric[0-9]+\.test$/'
filtering:
  rewrites:
    - domain: nas.home.arpa
      answer: 192.0.2.10
clients:
  persistent:
    - name: TV
      ids: [127.0.0.2]
      use_global_settings: false
      filtering_enabled: false
"#;
    let report = migration::preview(Source::Adguard, input, PolicyConfigSet::default()).unwrap();
    assert!(
        report.ready,
        "{}",
        serde_json::to_string(&report.issues).unwrap()
    );
    let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
    let local = "127.0.0.1".parse().unwrap();
    assert_eq!(
        snapshot.explain(local, "ads.test").unwrap().decision.action,
        Action::Block
    );
    assert_eq!(
        snapshot
            .explain(local, "child.ads.test")
            .unwrap()
            .decision
            .action,
        Action::Allow
    );
    assert_eq!(
        snapshot
            .explain(local, "child.tracking.test")
            .unwrap()
            .decision
            .action,
        Action::Block
    );
    assert_eq!(
        snapshot
            .explain(local, "safe.tracking.test")
            .unwrap()
            .decision
            .action,
        Action::Allow
    );
    assert_eq!(
        snapshot
            .explain(local, "metric12.test")
            .unwrap()
            .decision
            .action,
        Action::Block
    );
    assert_eq!(
        snapshot
            .explain("127.0.0.2".parse().unwrap(), "ads.test")
            .unwrap()
            .decision
            .action,
        Action::Allow
    );
}
#[test]
fn unsupported_settings_missing_feeds_and_secrets_are_accounted_for() {
    let source = br#"users: [{name: owner, password: private-sentinel-never-export}]
dns:
  upstream_dns: [tls://resolver.test]
filters: [{id: 1, enabled: true, url: 'https://publisher.test/list'}]
user_rules: ['||ads.test^$unsupported']
dhcp: {enabled: true}
"#;
    let report = migration::preview(Source::Adguard, source, PolicyConfigSet::default()).unwrap();
    assert!(!report.ready);
    assert!(report.blockers >= 4);
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains("private-sentinel-never-export")
    );
    let invalid = [
        b"dns: {a: 1, a: 2}".as_slice(),
        b"dns: &a {x: 1}\nother: *a".as_slice(),
        b"dns: !include /etc/passwd".as_slice(),
    ];
    for input in invalid {
        assert!(migration::preview(Source::Adguard, input, PolicyConfigSet::default()).is_err());
    }
}
#[test]
fn zip_traversal_duplicates_and_schema_views_are_rejected() {
    let input = archive(&[("../gravity.db", b"junk")]);
    assert!(migration::preview(Source::Pihole, &input, PolicyConfigSet::default()).is_err());
    let input = archive(&[("one/gravity.db", b"junk"), ("two/gravity.db", b"junk")]);
    assert!(migration::preview(Source::Pihole, &input, PolicyConfigSet::default()).is_err());
    for bytes in [b"PK".as_slice(), &[0; 20], b"SQLite format 3\0broken"] {
        assert!(migration::preview(Source::Pihole, bytes, PolicyConfigSet::default()).is_err());
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.db");
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch("CREATE VIEW \"group\" AS SELECT 0 id,1 enabled,'bad' name;")
        .unwrap();
    drop(db);
    assert!(
        migration::preview(
            Source::Pihole,
            &std::fs::read(path).unwrap(),
            PolicyConfigSet::default()
        )
        .is_err()
    );
}
#[test]
fn unsupported_source_fields_are_reported_without_leaking_values() {
    let report=migration::preview(Source::Adguard,b"dns:\n  unknown_security_feature: private-source-value\nusers:\n  - password: source-password-should-never-appear\n",PolicyConfigSet::default()).unwrap();
    assert!(!report.ready);
    assert!(report.blockers > 0);
    let serialized = serde_json::to_string(&report).unwrap();
    assert!(serialized.contains("unknown_security_feature"));
    assert!(!serialized.contains("private-source-value"));
    assert!(!serialized.contains("source-password"));
    assert!(
        migration::preview(
            Source::Adguard,
            b"filtering:\n  protection_enabled: 'false'\n",
            PolicyConfigSet::default()
        )
        .is_err()
    );
    let db = gravity();
    let input = archive(&[
        ("gravity.db", &db),
        ("pihole.toml", b"[dns]\nnewSecurityOption=true\n"),
    ]);
    let report = migration::preview(Source::Pihole, &input, PolicyConfigSet::default()).unwrap();
    assert!(!report.ready);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.field == "dns.newSecurityOption")
    );
}
#[test]
fn source_virtual_tables_are_not_accepted_as_physical_teleporter_tables() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("gravity.db");
    std::fs::write(&path, gravity()).unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch("DROP TABLE client;CREATE VIRTUAL TABLE client USING fts5(id,ip,comment);")
        .unwrap();
    drop(db);
    let error = migration::preview(
        Source::Pihole,
        &std::fs::read(path).unwrap(),
        PolicyConfigSet::default(),
    )
    .err()
    .unwrap();
    assert!(error.contains("missing table client"));
}

#[test]
fn adguard_service_ids_global_client_scope_and_disabled_protection_remain_reviewed() {
    let source = br#"
filtering:
  filtering_enabled: false
  blocked_services: {ids: [youtube, reddit]}
clients:
  persistent:
    - {name: inherit, ids: [127.0.0.2], use_global_blocked_services: true, blocked_services: [discord]}
    - {name: off, ids: [127.0.0.3], use_global_blocked_services: false, blocked_services: []}
    - {name: custom, ids: [127.0.0.4], use_global_blocked_services: false, blocked_services: [tiktok]}
    - {name: ambiguous, ids: [127.0.0.5], blocked_services: [discord]}
"#;
    let report = migration::preview(Source::Adguard, source, PolicyConfigSet::default()).unwrap();
    assert!(!report.ready);
    let global = report.config.policies[0].blocked_services.as_ref().unwrap();
    assert_eq!(global.ids, ["youtube", "reddit"]);
    assert_eq!(
        report.config.policies[1].blocked_services.as_ref(),
        Some(global)
    );
    assert!(report.config.policies[2].blocked_services.is_none());
    assert_eq!(
        report.config.policies[3]
            .blocked_services
            .as_ref()
            .unwrap()
            .ids,
        ["tiktok"]
    );
    assert_eq!(
        report.config.policies[4].blocked_services.as_ref(),
        Some(global)
    );
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.field.ends_with("use_global_blocked_services")
                && issue.severity == migration::Severity::Blocker)
    );
    let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
    assert_eq!(
        snapshot
            .explain("127.0.0.2".parse().unwrap(), "www.youtube.com")
            .unwrap()
            .decision
            .action,
        Action::Block
    );
    assert_eq!(
        snapshot
            .explain("127.0.0.3".parse().unwrap(), "www.youtube.com")
            .unwrap()
            .decision
            .action,
        Action::Allow
    );
    let off = migration::preview(
        Source::Adguard,
        b"filtering: {protection_enabled: false, blocked_services: [youtube]}",
        PolicyConfigSet::default(),
    )
    .unwrap();
    assert!(off.config.policies[0].blocked_services.is_none());
}

#[test]
fn adguard_service_shapes_unsupported_ids_and_schedules_never_disappear_silently() {
    for source in [
        "filtering: {blocked_services: {ids: [youtube, unknown], schedule: {mon: {start: PRIVATE_SOURCE_VALUE, end: '1h'}}}}",
        "filtering: {blocked_services: {ids: [youtube], unknown: PRIVATE_SOURCE_VALUE}}",
        "filtering: {blocked_services: {schedule: {}}}",
        "filtering: {blocked_services: [youtube, youtube]}",
        "filtering: {blocked_services: [youtube]}\nclients: {persistent: [{ids: [127.0.0.2], use_global_blocked_services: false}]}",
    ] {
        let report = migration::preview(
            Source::Adguard,
            source.as_bytes(),
            PolicyConfigSet::default(),
        )
        .unwrap();
        assert!(!report.ready);
        assert!(
            !serde_json::to_string(&report.issues)
                .unwrap()
                .contains("PRIVATE_SOURCE_VALUE")
        );
    }
    for source in [
        "filtering: {blocked_services: 'youtube'}",
        "filtering: {blocked_services: [false]}",
        "filtering: {blocked_services: {ids: false}}",
        "filtering: {blocked_services: {ids: [], schedule: false}}",
        "clients: {persistent: [{ids: [127.0.0.2], use_global_blocked_services: 'false'}]}",
        "clients: {persistent: [{ids: [127.0.0.2], use_global_blocked_services: true, blocked_services: false}]}",
    ] {
        assert!(
            migration::preview(
                Source::Adguard,
                source.as_bytes(),
                PolicyConfigSet::default()
            )
            .is_err()
        );
    }
}

#[test]
fn adguard_utc_allowed_windows_and_api_millisecond_durations_translate_without_guessing() {
    for source in [
        "filtering: {blocked_services: {ids: [youtube], schedule: {time_zone: UTC, mon: {start: 8h, end: 9h30m}}}}",
        r#"{"filtering":{"blocked_services":{"ids":["youtube"],"schedule":{"time_zone":"UTC","mon":{"start":28800000,"end":34200000}}}}}"#,
    ] {
        let report = migration::preview(
            Source::Adguard,
            source.as_bytes(),
            PolicyConfigSet::default(),
        )
        .unwrap();
        let schedule = report.config.policies[0]
            .blocked_services
            .as_ref()
            .unwrap()
            .schedule
            .as_ref()
            .unwrap();
        assert_eq!(schedule.mode, rustwalld_dns_policy::ScheduleMode::Allow);
        assert_eq!(schedule.windows[0].start, "08:00");
        assert_eq!(schedule.windows[0].end, "09:30");
        let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
        let at = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1791793800); // Monday 08:30 UTC
        assert_eq!(
            snapshot
                .explain_at("127.0.0.1".parse().unwrap(), "www.youtube.com", at)
                .unwrap()
                .decision
                .action,
            Action::Allow
        );
        assert_eq!(
            snapshot
                .explain_at(
                    "127.0.0.1".parse().unwrap(),
                    "www.youtube.com",
                    at + std::time::Duration::from_secs(3600)
                )
                .unwrap()
                .decision
                .action,
            Action::Block
        );
    }
}
#[test]
fn source_schedule_zone_precision_unknown_fields_and_dst_differences_remain_blockers() {
    for source in [
        "filtering: {blocked_services: {ids: [youtube], schedule: {time_zone: Local, mon: {start: 8h, end: 9h}}}}",
        "filtering: {blocked_services: {ids: [youtube], schedule: {mon: {start: 8h, end: 9h}}}}",
        "filtering: {blocked_services: {ids: [youtube], schedule: {time_zone: UTC, mon: {start: 8h1s, end: 9h}}}}",
        "filtering: {blocked_services: {ids: [youtube], schedule: {time_zone: UTC, mon: {start: 8h, end: 9h}, unknown: PRIVATE_SOURCE_VALUE}}}",
        "filtering: {blocked_services: {ids: [youtube], schedule: {time_zone: Europe/Oslo, sun: {start: 2h, end: 3h}}}}",
    ] {
        let report = migration::preview(
            Source::Adguard,
            source.as_bytes(),
            PolicyConfigSet::default(),
        )
        .unwrap();
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.field.contains("schedule")
                    && issue.severity == migration::Severity::Blocker)
        );
        assert!(
            !serde_json::to_string(&report.issues)
                .unwrap()
                .contains("PRIVATE_SOURCE_VALUE")
        );
    }
    for source in [
        "filtering: {blocked_services: {ids: [youtube], schedule: {time_zone: false}}}",
        "filtering: {blocked_services: {ids: [youtube], schedule: {time_zone: UTC, mon: false}}}",
        "clients: {persistent: [{ids: [127.0.0.2], use_global_blocked_services: true, blocked_services: {ids: [], schedule: {mon: {start: false}}}}]}",
    ] {
        assert!(
            migration::preview(
                Source::Adguard,
                source.as_bytes(),
                PolicyConfigSet::default()
            )
            .is_err()
        );
    }
}

#[test]
fn expanded_adguard_service_drafts_preserve_client_inheritance_and_unknown_blockers() {
    let source=b"filtering: {blocked_services: [netflix, spotify, steam, signal, unsupported]}\nclients: {persistent: [{ids: [127.0.0.2], use_global_blocked_services: true}, {ids: [127.0.0.3], use_global_blocked_services: false, blocked_services: [whatsapp, telegram, roblox, twitch]}]}";
    let report = migration::preview(Source::Adguard, source, PolicyConfigSet::default()).unwrap();
    assert!(!report.ready);
    let global = report.config.policies[0].blocked_services.as_ref().unwrap();
    assert_eq!(global.catalog_version, 2);
    assert_eq!(global.ids, ["netflix", "spotify", "steam", "signal"]);
    assert_eq!(
        report.config.policies[1].blocked_services.as_ref(),
        Some(global)
    );
    assert_eq!(
        report.config.policies[2]
            .blocked_services
            .as_ref()
            .unwrap()
            .ids,
        ["whatsapp", "telegram", "roblox", "twitch"]
    );
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.field.ends_with("ids[4]")
                && issue.severity == migration::Severity::Blocker)
    );
    let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
    for (client, domain, action) in [
        ("127.0.0.2", "www.netflix.com", Action::Block),
        ("127.0.0.3", "www.netflix.com", Action::Allow),
        ("127.0.0.3", "web.whatsapp.com", Action::Block),
        ("127.0.0.2", "web.whatsapp.com", Action::Allow),
    ] {
        assert_eq!(
            snapshot
                .explain(client.parse().unwrap(), domain)
                .unwrap()
                .decision
                .action,
            action
        );
    }
}

fn selected_port(config: &PolicyConfigSet, client: &str, domain: &str) -> u16 {
    let snapshot = PolicySnapshot::compile(config.clone(), 1).unwrap();
    let trace = snapshot.explain(client.parse().unwrap(), domain).unwrap();
    config
        .upstreams
        .iter()
        .find(|profile| profile.name == trace.upstream)
        .unwrap()
        .addresses[0]
        .port()
}
#[test]
fn client_defaults_replace_global_routes_and_route_only_overlays_preserve_source_precedence() {
    let source=br#"dns:
  upstream_dns: ['127.0.0.1:15401', '[/local.test/]127.0.0.1:15404', '[/svc.apps.local.test/]127.0.0.1:15405']
clients:
  persistent:
    - {ids: [127.0.0.2], use_global_settings: true, upstreams: ['127.0.0.1:15402', '[/only.test/]127.0.0.1:15406']}
    - {ids: [127.0.0.3], upstreams: []}
    - {ids: [127.0.0.4], upstreams: [' ', '# inherit']}
    - {ids: [127.0.0.5], upstreams: ['[/apps.local.test/]127.0.0.1:15403']}
"#;
    let report = migration::preview(Source::Adguard, source, PolicyConfigSet::default()).unwrap();
    assert!(report.ready);
    assert!(report.validation.as_ref().unwrap().valid);
    for (client, domain, port) in [
        ("127.0.0.1", "external.test", 15401),
        ("127.0.0.2", "host.local.test", 15402),
        ("127.0.0.2", "only.test", 15406),
        ("127.0.0.3", "svc.apps.local.test", 15405),
        ("127.0.0.4", "svc.apps.local.test", 15405),
        ("127.0.0.5", "svc.apps.local.test", 15403),
        ("127.0.0.5", "apps.local.test", 15403),
        ("127.0.0.5", "sibling.local.test", 15404),
        ("127.0.0.5", "notapps.local.test", 15404),
        ("127.0.0.5", "external.test", 15401),
    ] {
        assert_eq!(
            selected_port(&report.config, client, domain),
            port,
            "{client} {domain}"
        );
    }
    let snapshot = PolicySnapshot::compile(report.config.clone(), 1).unwrap();
    for (client, domain, port) in [
        ("127.0.0.1", "svc.apps.local.test", 15404),
        ("127.0.0.2", "only.test", 15402),
        ("127.0.0.2", "deep.only.test", 15406),
        ("127.0.0.5", "apps.local.test", 15404),
        ("127.0.0.5", "svc.apps.local.test", 15403),
    ] {
        let trace = snapshot
            .explain_query(
                client.parse().unwrap(),
                domain,
                hickory_proto::rr::RecordType::DS,
            )
            .unwrap();
        assert_eq!(
            report
                .config
                .upstreams
                .iter()
                .find(|profile| profile.name == trace.upstream)
                .unwrap()
                .addresses[0]
                .port(),
            port,
            "{client} {domain}"
        );
    }
    assert_eq!(report.config.policies[1].routes.len(), 1);
    assert_eq!(report.config.policies[4].routes.len(), 2);
}
#[test]
fn client_resolver_sharing_and_conflicting_names_preserve_existing_profile_choices() {
    let mut base = PolicyConfigSet::default();
    base.upstreams.push(UpstreamProfile {
        name: "adguard/client-0/upstreams/default".into(),
        addresses: vec!["192.0.2.20:15420".parse().unwrap()],
        timeout_ms: 1500,
        transport: UpstreamTransport::Udp,
    });
    let source=b"dns: {upstream_dns: ['127.0.0.1:15401']}\nclients: {persistent: [{ids: [127.0.0.2], upstreams: ['127.0.0.1:15402']}, {ids: [127.0.0.3], upstreams: ['127.0.0.1:15402']}, {ids: ['2001:db8::2'], upstreams: ['[2001:db8::10]:15410']}]}";
    let report = migration::preview(Source::Adguard, source, base).unwrap();
    assert!(
        report.ready,
        "{}",
        serde_json::to_string(&report.issues).unwrap()
    );
    assert_eq!(
        report.config.policies[1].upstream,
        report.config.policies[2].upstream
    );
    assert_eq!(
        report.config.policies[1].upstream,
        "adguard/client-0/upstreams/default-1"
    );
    assert_eq!(
        report
            .config
            .upstreams
            .iter()
            .find(|profile| profile.name == "adguard/client-0/upstreams/default")
            .unwrap()
            .addresses[0],
        "192.0.2.20:15420".parse().unwrap()
    );
    assert_eq!(report.config.upstreams.len(), 5);
    assert_eq!(
        selected_port(&report.config, "2001:db8::2", "external.test"),
        15410
    );
}
#[test]
fn client_encrypted_profiles_use_original_destination_pins_and_keep_identity_path_and_trust() {
    let mut base = PolicyConfigSet::default();
    let tls = UpstreamProfile {
        name: "adguard/upstreams/default".into(),
        addresses: vec!["192.0.2.10:1953".parse().unwrap()],
        timeout_ms: 321,
        transport: UpstreamTransport::Tls {
            server_name: "resolver.test".into(),
            ca_pem: None,
            max_connections: 2,
        },
    };
    let doh = UpstreamProfile {
        name: "pinned-doh".into(),
        addresses: vec!["[2001:db8::10]:9443".parse().unwrap()],
        timeout_ms: 654,
        transport: UpstreamTransport::Https {
            server_name: "resolver.test".into(),
            ca_pem: None,
            path: "/private-query?profile=work".into(),
            max_connections: 3,
        },
    };
    base.upstreams.extend([tls.clone(), doh.clone()]);
    let source=b"dns: {upstream_dns: ['127.0.0.1:15401'], bootstrap_dns: ['192.0.2.99']}\nclients: {persistent: [{ids: [127.0.0.2], upstreams: ['tls://resolver.test:1953']}, {ids: [127.0.0.3], upstreams: ['https://resolver.test:9443/private-query?profile=work']}]}";
    let report = migration::preview(Source::Adguard, source, base).unwrap();
    assert!(report.ready);
    for (index, expected) in [(1, tls), (2, doh)] {
        let imported = report
            .config
            .upstreams
            .iter()
            .find(|profile| profile.name == report.config.policies[index].upstream)
            .unwrap();
        assert_eq!(imported.addresses, expected.addresses);
        assert_eq!(imported.transport, expected.transport);
        assert_eq!(imported.timeout_ms, expected.timeout_ms);
    }
    assert!(
        !serde_json::to_string(&report.config)
            .unwrap()
            .contains("192.0.2.99")
    );
}
#[test]
fn unsupported_client_sets_retain_complete_inherited_resolvers_without_partial_profiles_or_secret_values()
 {
    let prefix = "dns: {upstream_dns: ['127.0.0.1:15401', '[/home.arpa/]127.0.0.1:15404']}\nclients: {persistent: [{ids: [127.0.0.2], upstreams: ";
    for values in [
        "['127.0.0.1:15402', 'tls://no-pin.test']",
        "['127.0.0.1:15402', 'https://user:PRIVATE_SENTINEL@resolver.test/dns-query']",
        "['[/home.arpa/]127.0.0.1:15402', '[/other/]#']",
        "['[/home.arpa/]127.0.0.1:15402', '[/wrong*/]127.0.0.1:15403']",
        "['quic://PRIVATE_SENTINEL.test']",
    ] {
        let source = format!("{prefix}{values}}}]}}");
        let report = migration::preview(
            Source::Adguard,
            source.as_bytes(),
            PolicyConfigSet::default(),
        )
        .unwrap();
        assert!(!report.ready);
        assert_eq!(
            report.config.policies[1].upstream,
            report.config.policies[0].upstream
        );
        assert_eq!(
            serde_json::to_value(&report.config.policies[1].routes).unwrap(),
            serde_json::to_value(&report.config.policies[0].routes).unwrap()
        );
        assert_eq!(report.config.upstreams.len(), 3);
        let body = serde_json::to_string(&report).unwrap();
        assert!(!body.contains("PRIVATE_SENTINEL"));
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.message.contains("no partial client"))
        );
    }
}
#[test]
fn client_identity_cache_types_and_profile_route_declaration_budgets_are_enforced() {
    for source in [
        "clients: {persistent: [{ids: [127.0.0.2], upstreams: [false]}]}",
        "clients: {persistent: [{ids: [127.0.0.2], upstreams_cache_enabled: 'false'}]}",
        "clients: {persistent: [{ids: [127.0.0.2], upstreams_cache_size: -1}]}",
        "clients: {persistent: [{ids: [127.0.0.2], upstreams_cache_size: 4294967296}]}",
    ] {
        assert!(
            migration::preview(
                Source::Adguard,
                source.as_bytes(),
                PolicyConfigSet::default()
            )
            .is_err()
        );
    }
    let missing = migration::preview(
        Source::Adguard,
        b"clients: {persistent: [{upstreams: ['127.0.0.1:15402']}]}",
        PolicyConfigSet::default(),
    )
    .unwrap();
    assert!(!missing.ready);
    assert!(
        missing
            .issues
            .iter()
            .any(|issue| issue.field == "clients.persistent[0].ids")
    );
    let base = PolicyConfigSet {
        upstreams: (0..32)
            .map(|i| UpstreamProfile {
                name: format!("base-{i}"),
                addresses: vec![format!("192.0.2.1:{}", 20000 + i).parse().unwrap()],
                timeout_ms: 1500,
                transport: UpstreamTransport::Udp,
            })
            .collect(),
        ..Default::default()
    };
    for (endpoint, ready) in [("192.0.2.1:20000", true), ("192.0.2.2:30000", false)] {
        let source =
            format!("clients: {{persistent: [{{ids: [127.0.0.2], upstreams: ['{endpoint}']}}]}}");
        let report = migration::preview(Source::Adguard, source.as_bytes(), base.clone()).unwrap();
        assert_eq!(
            report.ready,
            ready,
            "{}",
            serde_json::to_string(&report.issues).unwrap()
        );
        assert_eq!(report.config.upstreams, base.upstreams);
    }
    let source = serde_json::json!({"clients":{"persistent":[{"ids":["127.0.0.2"],"upstreams":vec!["127.0.0.1:15402";257]}]}});
    let report = migration::preview(
        Source::Adguard,
        &serde_json::to_vec(&source).unwrap(),
        PolicyConfigSet::default(),
    )
    .unwrap();
    assert!(!report.ready);
    assert_eq!(report.config.upstreams.len(), 1);
    let source = serde_json::json!({"dns":{"upstream_dns":(0..31).map(|i|format!("[/z{i}.test/]127.0.0.1:15401")).collect::<Vec<_>>()},"clients":{"persistent":(0..132).map(|i|serde_json::json!({"ids":[format!("127.0.0.{}",i+2)]})).collect::<Vec<_>>()}});
    assert!(
        migration::preview(
            Source::Adguard,
            &serde_json::to_vec(&source).unwrap(),
            PolicyConfigSet::default()
        )
        .err()
        .unwrap()
        .contains("4096-route")
    );
}

#[test]
fn client_route_sharing_respects_per_policy_and_combined_budgets_atomically() {
    let custom: Vec<_> = (0..256)
        .map(|i| format!("[/c{i}.test/]127.0.0.1:15401"))
        .collect();
    let source =
        serde_json::json!({"clients":{"persistent":[{"ids":["127.0.0.2"],"upstreams":custom}]}});
    let report = migration::preview(
        Source::Adguard,
        &serde_json::to_vec(&source).unwrap(),
        PolicyConfigSet::default(),
    )
    .unwrap();
    assert!(report.validation.as_ref().unwrap().valid);
    assert_eq!(report.config.upstreams.len(), 2);
    assert_eq!(report.config.policies[1].routes.len(), 256);
    assert_eq!(
        selected_port(&report.config, "127.0.0.2", "www.c255.test"),
        15401
    );
    let mut source = source;
    source["dns"] = serde_json::json!({"upstream_dns":["[/global.test/]127.0.0.1:15401"]});
    let report = migration::preview(
        Source::Adguard,
        &serde_json::to_vec(&source).unwrap(),
        PolicyConfigSet::default(),
    )
    .unwrap();
    assert_eq!(report.config.upstreams.len(), 2);
    assert_eq!(report.config.policies[1].routes.len(), 1);
    assert_eq!(report.config.policies[1].routes[0].domain, "global.test");
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.message.contains("overlay exceeds 256"))
    );
    assert_eq!(
        selected_port(&report.config, "127.0.0.2", "www.global.test"),
        15401
    );
}

#[test]
fn global_ipv6_and_native_profile_budget_fail_without_partial_translation() {
    let report = migration::preview(
        Source::Adguard,
        b"dns: {upstream_dns: ['[2001:db8::10]:15410']}",
        PolicyConfigSet::default(),
    )
    .unwrap();
    assert!(report.ready);
    assert_eq!(
        selected_port(&report.config, "127.0.0.1", "allowed.test"),
        15410
    );
    let source = serde_json::json!({"dns":{"upstream_dns":(0..32).map(|i|format!("[/r{i}.test/]127.0.0.1:15401")).collect::<Vec<_>>()}});
    let report = migration::preview(
        Source::Adguard,
        &serde_json::to_vec(&source).unwrap(),
        PolicyConfigSet::default(),
    )
    .unwrap();
    assert!(!report.ready);
    assert_eq!(report.config.upstreams.len(), 1);
    assert!(report.config.policies[0].routes.is_empty());
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.message.contains("profiles exceed 32"))
    );
}

#[test]
fn adguard_v2_badfilter_imports_cancel_across_lists_and_inherited_clients() {
    let input = archive(&[
        ("AdGuardHome.yaml", b"dns: {upstream_dns: ['127.0.0.1:15354']}\nfilters: [{id: 1, enabled: true, url: 'https://publisher.test/list'}]\nuser_rules: ['||tracking.test^$badfilter', '@@||safe.test^$badfilter']\nclients:\n  persistent:\n    - {name: inherited, ids: ['127.0.0.2'], use_global_settings: true}\n    - {name: exempt, ids: ['127.0.0.3'], use_global_settings: false, filtering_enabled: false}\n"),
        ("data/filters/1.txt", b"||tracking.test^\n||safe.test^\n@@||safe.test^\n||ads.test^\n"),
    ]);
    let report = migration::preview(Source::Adguard, &input, PolicyConfigSet::default()).unwrap();
    assert!(report.ready, "{:?}", report.issues);
    assert!(
        report
            .config
            .policies
            .iter()
            .flat_map(|policy| &policy.lists)
            .all(|list| list.syntax == rustwalld_dns_filter::RuleSyntax::AdguardV6)
    );
    let serialized = serde_json::to_value(&report).unwrap();
    assert_eq!(
        serialized["config"]["policies"][0]["lists"][0]["syntax"],
        "adguard_v6"
    );
    let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
    for client in ["127.0.0.1", "127.0.0.2"] {
        assert_eq!(
            snapshot
                .explain(client.parse().unwrap(), "tracking.test")
                .unwrap()
                .decision
                .action,
            Action::Allow
        );
        assert_eq!(
            snapshot
                .explain(client.parse().unwrap(), "safe.test")
                .unwrap()
                .decision
                .action,
            Action::Block
        );
        assert_eq!(
            snapshot
                .explain(client.parse().unwrap(), "ads.test")
                .unwrap()
                .decision
                .action,
            Action::Block
        );
    }
    assert_eq!(
        snapshot
            .explain("127.0.0.3".parse().unwrap(), "ads.test")
            .unwrap()
            .decision
            .action,
        Action::Allow
    );
    assert_eq!(snapshot.policies()[0].filters().cancellation_targets(), 2);
    for rule in [
        "bare.test$badfilter",
        "||tracking.test^$important,badfilter",
        "||tracking.test^$badfilter=1",
    ] {
        let input = serde_json::to_vec(&serde_json::json!({"user_rules": [rule]})).unwrap();
        let report =
            migration::preview(Source::Adguard, &input, PolicyConfigSet::default()).unwrap();
        assert!(!report.ready);
        assert!(report.blockers > 0);
    }
}

#[test]
fn adguard_v3_exclusions_keep_other_blocks_and_inherited_client_scope() {
    let report = migration::preview(
        Source::Adguard,
        br#"
dns: {upstream_dns: ['127.0.0.1:15354']}
user_rules: ['||test^$denyallow=safe.test', '||ads.safe.test^']
clients:
  persistent:
    - name: inherited
      ids: ['192.0.2.10']
      use_global_settings: true
"#,
        PolicyConfigSet::default(),
    )
    .unwrap();
    assert!(report.ready, "{:?}", report.issues);
    let config = report.config;
    assert!(
        config
            .policies
            .iter()
            .flat_map(|policy| &policy.lists)
            .all(|list| list.syntax == rustwalld_dns_filter::RuleSyntax::AdguardV6)
    );
    let snapshot = rustwalld_dns_policy::PolicySnapshot::compile(config, 1).unwrap();
    for client in ["127.0.0.1", "192.0.2.10"] {
        for (name, action) in [
            ("safe.test", Action::Allow),
            ("x.safe.test", Action::Allow),
            ("ads.safe.test", Action::Block),
            ("blocked.test", Action::Block),
        ] {
            assert_eq!(
                snapshot
                    .explain(client.parse().unwrap(), name)
                    .unwrap()
                    .decision
                    .action,
                action
            );
        }
    }
    let report = migration::preview(
        Source::Adguard,
        br#"dns: {upstream_dns: ['127.0.0.1:15354']}
user_rules: ['||test^$denyallow=safe.test,badfilter']"#,
        PolicyConfigSet::default(),
    )
    .unwrap();
    assert!(!report.ready);
}

#[test]
fn adguard_v4_imports_typed_rules_with_inheritance_and_rejects_unknown_types() {
    let report = migration::preview(
        Source::Adguard,
        br#"dns: {upstream_dns: ['127.0.0.1:15354']}
user_rules: ['||ads.test^$dnstype=AAAA', '||canon.test^$dnstype=~CNAME']
clients: {persistent: [{name: inherited, ids: ['192.0.2.10'], use_global_settings: true}]}
"#,
        PolicyConfigSet::default(),
    )
    .unwrap();
    assert!(report.ready, "{:?}", report.issues);
    let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
    for client in ["127.0.0.1", "192.0.2.10"] {
        for (kind, action) in [
            (hickory_proto::rr::RecordType::A, Action::Allow),
            (hickory_proto::rr::RecordType::AAAA, Action::Block),
        ] {
            assert_eq!(
                snapshot
                    .explain_query(client.parse().unwrap(), "ads.test", kind)
                    .unwrap()
                    .decision
                    .action,
                action
            );
        }
    }
    let report = migration::preview(
        Source::Adguard,
        br#"dns: {upstream_dns: ['127.0.0.1:15354']}
user_rules: ['||ads.test^$dnstype=MADEUP']"#,
        PolicyConfigSet::default(),
    )
    .unwrap();
    assert!(!report.ready);
}

#[test]
fn v5_client_rules_preserve_exact_names_and_inherited_shared_input() {
    let report=migration::preview(Source::Adguard,br#"dns: {upstream_dns: ['127.0.0.1:15354']}
user_rules: ['||client.test^$client=Kids|2001:db8::/32,dnstype=AAAA', '||except.test^$client=~Kids']
clients: {persistent: [{name: Kids, ids: ['192.0.2.1'], use_global_settings: true}, {name: Adults, ids: ['192.0.2.2'], use_global_settings: true}]}
"#,PolicyConfigSet::default()).unwrap();
    assert!(report.ready, "{:?}", report.issues);
    assert!(
        report
            .config
            .policies
            .iter()
            .all(|policy| policy.lists[0].syntax == rustwalld_dns_filter::RuleSyntax::AdguardV6)
    );
    let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
    for (client, action) in [
        ("192.0.2.1", Action::Block),
        ("192.0.2.2", Action::Allow),
        ("2001:db8::1", Action::Block),
    ] {
        assert_eq!(
            snapshot
                .explain_query(
                    client.parse().unwrap(),
                    "client.test",
                    hickory_proto::rr::RecordType::AAAA
                )
                .unwrap()
                .decision
                .action,
            action
        );
    }
    assert_eq!(
        snapshot
            .explain("192.0.2.1".parse().unwrap(), "except.test")
            .unwrap()
            .decision
            .action,
        Action::Allow
    );
    assert_eq!(
        snapshot
            .explain("192.0.2.2".parse().unwrap(), "except.test")
            .unwrap()
            .decision
            .action,
        Action::Block
    );
}

#[test]
fn unnamed_source_clients_do_not_silently_match_generated_labels() {
    let report = migration::preview(
        Source::Adguard,
        br#"dns: {upstream_dns: ['127.0.0.1:15354']}
user_rules: ['||client.test^$client=client-0']
clients: {persistent: [{ids: ['192.0.2.1']}]}
"#,
        PolicyConfigSet::default(),
    )
    .unwrap();
    assert!(!report.ready);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.field == "clients.persistent[0].name")
    );
}

#[test]
fn source_ctags_use_explicit_tags_on_each_cidr_and_leave_metadata_advisory() {
    let report=migration::preview(Source::Adguard,br#"dns: {upstream_dns: ['127.0.0.1:15354']}
user_rules: ['||tag.test^$ctag=device_phone|~user_admin,dnstype=AAAA']
clients: {persistent: [{name: Phone, ids: ['192.0.2.1','2001:db8::1'], tags: [device_phone], use_global_settings: true}, {name: Admin, ids: ['192.0.2.2'], tags: [device_phone,user_admin]}]}
"#,PolicyConfigSet::default()).unwrap();
    assert!(report.ready, "{:?}", report.issues);
    assert_eq!(report.config.bindings[0].filter_tags, vec!["device_phone"]);
    assert_eq!(report.config.bindings[1].filter_tags, vec!["device_phone"]);
    assert!(
        report
            .config
            .bindings
            .iter()
            .all(|binding| binding.metadata.is_none())
    );
    let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
    for (client, expected) in [
        ("192.0.2.1", Action::Block),
        ("2001:db8::1", Action::Block),
        ("192.0.2.2", Action::Allow),
        ("192.0.2.3", Action::Allow),
    ] {
        assert_eq!(
            snapshot
                .explain_query(
                    client.parse().unwrap(),
                    "tag.test",
                    hickory_proto::rr::RecordType::AAAA
                )
                .unwrap()
                .decision
                .action,
            expected
        );
    }
    let invalid = migration::preview(
        Source::Adguard,
        br#"clients: {persistent: [{name: Phone, ids: ['192.0.2.1'], tags: [unknown_tag]}]}"#,
        PolicyConfigSet::default(),
    )
    .unwrap();
    assert!(!invalid.ready);
    assert!(
        invalid
            .issues
            .iter()
            .any(|issue| issue.field == "clients.persistent[0].tags")
    );
}

#[test]
fn disabled_rewrite_states_preserve_legacy_defaults_and_client_inheritance() {
    for container in ["filtering", "dns"] {
        let source = format!(
            "{container}:\n  rewrites:\n    - {{domain: legacy.home.arpa, answer: 192.0.2.10}}\n    - {{domain: active.home.arpa, answer: '2001:db8::10', enabled: true}}\n    - {{domain: disabled.home.arpa, answer: 192.0.2.11, enabled: false}}\n    - {{domain: '*.inactive.test', answer: A, enabled: false}}\nclients: {{persistent: [{{name: Work, ids: [127.0.0.2]}}]}}\n"
        );
        let report = migration::preview(
            Source::Adguard,
            source.as_bytes(),
            PolicyConfigSet::default(),
        )
        .unwrap();
        assert!(report.ready, "{:?}", report.issues);
        assert!(
            report
                .config
                .policies
                .iter()
                .all(|policy| policy.dns_records.len() == 2)
        );
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.field == format!("{container}.rewrites[2]"))
        );
        let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
        for client in ["127.0.0.1", "127.0.0.2"] {
            let selected = snapshot.select(client.parse().unwrap()).policy;
            assert!(selected.has_rewrite("legacy.home.arpa"));
            assert!(selected.has_rewrite("active.home.arpa"));
            assert!(!selected.has_rewrite("disabled.home.arpa"));
        }
    }
}
#[test]
fn rewrite_entry_fields_are_reviewed_without_echoing_unknown_values() {
    for enabled in ["true", "false"] {
        let source = format!(
            "filtering: {{rewrites: [{{domain: local.test, answer: 192.0.2.10, enabled: {enabled}, secret_option: private-fixture-secret}}]}}\n"
        );
        let report = migration::preview(
            Source::Adguard,
            source.as_bytes(),
            PolicyConfigSet::default(),
        )
        .unwrap();
        assert!(!report.ready);
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.field == "filtering.rewrites[0].secret_option")
        );
        assert!(
            !serde_json::to_string(&report.issues)
                .unwrap()
                .contains("private-fixture-secret")
        );
    }
    for item in [
        "null",
        "false",
        "hello",
        "[]",
        "{domain: local.test, answer: 192.0.2.10, enabled: null}",
        "{domain: local.test, answer: 192.0.2.10, enabled: 'false'}",
        "{domain: 1, answer: 192.0.2.10, enabled: false}",
        "{domain: local.test, answer: [], enabled: false}",
    ] {
        let source = format!("dns: {{rewrites: [{item}]}}\n");
        assert!(
            migration::preview(
                Source::Adguard,
                source.as_bytes(),
                PolicyConfigSet::default()
            )
            .is_err(),
            "{item}"
        );
    }
    let active = migration::preview(
        Source::Adguard,
        b"dns: {rewrites: [{domain: '*.active.test', answer: A, enabled: true}]}",
        PolicyConfigSet::default(),
    )
    .unwrap();
    assert!(!active.ready);
    assert!(
        active
            .issues
            .iter()
            .any(|issue| issue.field == "dns.rewrites[0]")
    );
}

#[test]
fn rewrite_containers_are_selected_independently_and_ambiguity_blocks() {
    let report = migration::preview(
        Source::Adguard,
        b"filtering: {}\ndns: {rewrites: [{domain: retained.test, answer: 192.0.2.10}]}\n",
        PolicyConfigSet::default(),
    )
    .unwrap();
    assert!(report.ready, "{:?}", report.issues);
    assert_eq!(
        report.config.policies[0].dns_records[0].domain,
        "retained.test"
    );
    let report=migration::preview(Source::Adguard,b"filtering: {rewrites: []}\ndns: {rewrites: [{domain: ambiguous.test, answer: 192.0.2.10}]}\n",PolicyConfigSet::default()).unwrap();
    assert!(!report.ready);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.field == "dns.rewrites")
    );
    for value in ["null", "false", "[]", "hello"] {
        let input = format!("filtering: {value}\n");
        assert!(
            migration::preview(
                Source::Adguard,
                input.as_bytes(),
                PolicyConfigSet::default()
            )
            .is_err()
        );
    }
}

#[test]
fn legacy_passthrough_import_preserves_family_filters_aliases_and_client_inheritance() {
    let report = migration::preview(
        Source::Adguard,
        br#"filtering:
  rewrites:
    - {domain: split.test, answer: 192.0.2.10}
    - {domain: split.test, answer: AAAA}
    - {domain: alias.test, answer: split.test}
    - {domain: inactive.test, answer: A, enabled: false}
user_rules: ['||split.test^', '||alias.test^']
clients: {persistent: [{name: Work, ids: ['127.0.0.2']}]}
"#,
        PolicyConfigSet::default(),
    )
    .unwrap();
    assert!(report.ready, "{:?}", report.issues);
    let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
    for client in ["127.0.0.1", "127.0.0.2"] {
        for domain in ["split.test", "alias.test"] {
            let a = snapshot
                .explain_query(
                    client.parse().unwrap(),
                    domain,
                    hickory_proto::rr::RecordType::A,
                )
                .unwrap();
            assert!(a.rewrite);
            assert_eq!(a.decision.action, Action::Allow);
            let aaaa = snapshot
                .explain_query(
                    client.parse().unwrap(),
                    domain,
                    hickory_proto::rr::RecordType::AAAA,
                )
                .unwrap();
            assert!(!aaaa.rewrite);
            assert_eq!(aaaa.decision.action, Action::Block);
        }
        assert!(
            !snapshot
                .select(client.parse().unwrap())
                .policy
                .has_rewrite("inactive.test")
        );
    }
}
#[test]
fn cname_owner_passthrough_conflicts_remain_import_blockers() {
    let report=migration::preview(Source::Adguard,b"filtering: {rewrites: [{domain: split.test, answer: A}, {domain: split.test, answer: alias.test}]}",PolicyConfigSet::default()).unwrap();
    assert!(!report.ready);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.severity == migration::Severity::Blocker)
    );
}

#[test]
fn historical_dns_container_preserves_exact_passthrough_semantics_for_each_family() {
    for (family, kind, other) in [("A", 1, 28), ("AAAA", 28, 1)] {
        let source = format!(
            "schema_version: 25\ndns: {{rewrites: [{{domain: split.test, answer: '{family}'}}]}}\nuser_rules: ['||split.test^']\nclients: {{persistent: [{{name: Work, ids: ['127.0.0.2']}}]}}\n"
        );
        let report = migration::preview(
            Source::Adguard,
            source.as_bytes(),
            PolicyConfigSet::default(),
        )
        .unwrap();
        assert!(report.ready, "{:?}", report.issues);
        let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
        for client in ["127.0.0.1", "127.0.0.2"] {
            let pass = snapshot
                .explain_query(
                    client.parse().unwrap(),
                    "split.test",
                    hickory_proto::rr::RecordType::from(kind),
                )
                .unwrap();
            assert!(!pass.rewrite);
            assert_eq!(pass.decision.action, Action::Block);
            let nodata = snapshot
                .explain_query(
                    client.parse().unwrap(),
                    "split.test",
                    hickory_proto::rr::RecordType::from(other),
                )
                .unwrap();
            assert!(nodata.rewrite);
            assert_eq!(nodata.decision.action, Action::Allow);
            assert!(
                !snapshot
                    .select(client.parse().unwrap())
                    .policy
                    .has_rewrite("sub.split.test")
            );
        }
    }
}
#[test]
fn global_rewrite_switch_defaults_and_client_inheritance_preserve_normal_filters() {
    for switch in [None, Some(true), Some(false)] {
        let flag = switch
            .map(|enabled| format!("  rewrites_enabled: {enabled}\n"))
            .unwrap_or_default();
        let source = format!(
            "filtering:\n{flag}  rewrites:\n    - {{domain: privacy.test, answer: 192.0.2.10, enabled: true}}\n    - {{domain: privacy.test, answer: AAAA}}\n    - {{domain: disabled.test, answer: 192.0.2.11, enabled: false}}\nuser_rules: [privacy.test]\nclients: {{persistent: [{{name: Work, ids: ['127.0.0.2']}}]}}\n"
        );
        let report = migration::preview(
            Source::Adguard,
            source.as_bytes(),
            PolicyConfigSet::default(),
        )
        .unwrap();
        assert!(report.ready, "{:?}", report.issues);
        let active = switch.unwrap_or(true);
        assert!(
            report
                .config
                .policies
                .iter()
                .all(|policy| policy.dns_records.len() == if active { 2 } else { 0 })
        );
        if !active {
            assert!(
                report
                    .issues
                    .iter()
                    .any(|issue| issue.field == "filtering.rewrites_enabled"
                        && issue.severity == migration::Severity::Info)
            );
        }
        let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
        for client in ["127.0.0.1", "127.0.0.2"] {
            let a = snapshot
                .explain(client.parse().unwrap(), "privacy.test")
                .unwrap();
            assert_eq!(a.rewrite, active);
            assert_eq!(
                a.decision.action,
                if active { Action::Allow } else { Action::Block }
            );
            let aaaa = snapshot
                .explain_query(
                    client.parse().unwrap(),
                    "privacy.test",
                    hickory_proto::rr::RecordType::AAAA,
                )
                .unwrap();
            assert!(!aaaa.rewrite);
            assert_eq!(aaaa.decision.action, Action::Block);
            assert!(
                !snapshot
                    .select(client.parse().unwrap())
                    .policy
                    .has_rewrite("disabled.test")
            );
        }
    }
}
#[test]
fn global_rewrite_controls_fail_closed_on_malformed_unknown_and_mixed_layout_settings() {
    for value in ["null", "'false'", "0", "[]", "{}"] {
        let source = format!("filtering: {{rewrites_enabled: {value}, rewrites: []}}\n");
        let error = migration::preview(
            Source::Adguard,
            source.as_bytes(),
            PolicyConfigSet::default(),
        )
        .err()
        .unwrap();
        assert_eq!(error, "filtering.rewrites_enabled must be a boolean");
    }
    for entry in [
        "false",
        "{domain: 7, answer: A}",
        "{domain: valid.test, answer: 1}",
        "{domain: valid.test, answer: A, enabled: null}",
    ] {
        let source = format!("filtering: {{rewrites_enabled: false, rewrites: [{entry}]}}\n");
        assert!(
            migration::preview(
                Source::Adguard,
                source.as_bytes(),
                PolicyConfigSet::default()
            )
            .is_err()
        );
    }
    let report=migration::preview(Source::Adguard,b"filtering: {rewrites_enabled: false, rewrites: [{domain: private.test, answer: A, secret_option: private-fixture-secret}]}",PolicyConfigSet::default()).unwrap();
    assert!(!report.ready);
    assert!(report.config.policies[0].dns_records.is_empty());
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.field == "filtering.rewrites[0].secret_option")
    );
    assert!(
        !serde_json::to_string(&report.issues)
            .unwrap()
            .contains("private-fixture-secret")
    );
    for source in [
        b"dns: {rewrites_enabled: false, rewrites: [{domain: old.test, answer: A}]}".as_slice(),
        b"dns: {rewrites: [{domain: old.test, answer: A}]}\nfiltering: {rewrites_enabled: false}"
            .as_slice(),
    ] {
        let report =
            migration::preview(Source::Adguard, source, PolicyConfigSet::default()).unwrap();
        assert!(!report.ready);
    }
}
#[test]
fn global_off_omits_inactive_patterns_without_amplifying_diagnostics() {
    let entries = (0..1000)
        .map(|index| format!("{{domain: '*.inactive{index}.test', answer: A, enabled: true}}"))
        .collect::<Vec<_>>()
        .join(",");
    let source = format!("filtering: {{rewrites_enabled: false, rewrites: [{entries}]}}\n");
    let report = migration::preview(
        Source::Adguard,
        source.as_bytes(),
        PolicyConfigSet::default(),
    )
    .unwrap();
    assert!(report.ready, "{:?}", report.issues);
    assert!(report.config.policies[0].dns_records.is_empty());
    assert_eq!(
        report
            .issues
            .iter()
            .filter(|issue| issue.field == "filtering.rewrites_enabled")
            .count(),
        1
    );
    assert!(
        report
            .issues
            .iter()
            .all(|issue| !issue.field.starts_with("filtering.rewrites["))
    );
}

#[test]
fn explicit_old_schema_cannot_claim_disabled_entry_equivalence() {
    for (version, container, ready) in [
        (25, "dns", false),
        (30, "filtering", false),
        (31, "filtering", true),
        (34, "filtering", true),
    ] {
        let source = format!(
            "schema_version: {version}\n{container}: {{rewrites: [{{domain: disabled.test, answer: 192.0.2.10, enabled: false}}]}}\n"
        );
        let report = migration::preview(
            Source::Adguard,
            source.as_bytes(),
            PolicyConfigSet::default(),
        )
        .unwrap();
        assert_eq!(report.ready, ready, "{:?}", report.issues);
        assert!(report.config.policies[0].dns_records.is_empty());
        if !ready {
            assert!(
                report
                    .issues
                    .iter()
                    .any(|issue| issue.field == format!("{container}.rewrites[0]")
                        && issue.severity == migration::Severity::Blocker)
            );
        }
    }
    for version in ["null", "'25'", "-1", "false", "1.5"] {
        let source = format!("schema_version: {version}\n");
        assert_eq!(
            migration::preview(
                Source::Adguard,
                source.as_bytes(),
                PolicyConfigSet::default()
            )
            .err()
            .unwrap(),
            "schema_version must be a nonnegative integer"
        );
    }
}

#[test]
fn explicit_new_schema_cannot_activate_old_dns_container_definitions() {
    for version in [26, 31, 34] {
        let source = format!(
            "schema_version: {version}\ndns: {{rewrites: [{{domain: mismatched.test, answer: 192.0.2.10}}]}}\nuser_rules: [mismatched.test]\n"
        );
        let report = migration::preview(
            Source::Adguard,
            source.as_bytes(),
            PolicyConfigSet::default(),
        )
        .unwrap();
        assert!(!report.ready);
        assert!(report.config.policies[0].dns_records.is_empty());
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.field == "dns.rewrites"
                    && issue.severity == migration::Severity::Blocker)
        );
        let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
        let explanation = snapshot
            .explain("127.0.0.1".parse().unwrap(), "mismatched.test")
            .unwrap();
        assert!(!explanation.rewrite);
        assert_eq!(explanation.decision.action, Action::Block);
    }
}

#[test]
fn wildcard_address_import_preserves_family_precedence_and_client_inheritance_in_both_layouts() {
    use hickory_proto::rr::{RData, RecordType};
    for (version, container) in [(25, "dns"), (34, "filtering")] {
        let source = format!(
            "schema_version: {version}\n{container}:\n  rewrites:\n    - {{domain: '*.lab.test', answer: 192.0.2.10}}\n    - {{domain: '*.lab.test', answer: '2001:db8::a'}}\n    - {{domain: '*.deep.lab.test', answer: 192.0.2.20}}\n    - {{domain: 'fixed.deep.lab.test', answer: 192.0.2.30}}\n    - {{domain: '*.inactive.test', answer: 192.0.2.99, enabled: false}}\nuser_rules: [lab.test]\nclients: {{persistent: [{{name: Work, ids: ['127.0.0.2']}}]}}\n"
        );
        // Pre-31 disabled entries are blocked rather than claiming source activation parity.
        let source = if version == 25 {
            source
                .replace(", enabled: false", ", enabled: true")
                .replace(
                    "    - {domain: '*.inactive.test', answer: 192.0.2.99, enabled: true}\n",
                    "",
                )
        } else {
            source
        };
        let report = migration::preview(
            Source::Adguard,
            source.as_bytes(),
            PolicyConfigSet::default(),
        )
        .unwrap();
        assert!(report.ready, "{:?}", report.issues);
        let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
        for client in ["127.0.0.1", "127.0.0.2"] {
            let policy = snapshot.select(client.parse().unwrap()).policy;
            for (name, kind, last) in [
                ("x.lab.test", RecordType::A, 10),
                ("x.deep.lab.test", RecordType::A, 20),
                ("fixed.deep.lab.test", RecordType::A, 30),
                ("fixed.deep.lab.test", RecordType::AAAA, 10),
            ] {
                let answers = policy.rewrite(name, kind).unwrap();
                assert_eq!(answers.len(), 1);
                match &answers[0].data {
                    RData::A(ip) => assert_eq!(ip.0.octets()[3], last),
                    RData::AAAA(ip) => assert_eq!(ip.0.segments()[7], u16::from(last)),
                    other => panic!("{other:?}"),
                };
                assert!(
                    snapshot
                        .explain_query(client.parse().unwrap(), name, kind)
                        .unwrap()
                        .rewrite
                );
            }
            assert!(!policy.has_rewrite("lab.test"));
            assert!(!policy.has_rewrite("badlab.test"));
            assert!(!policy.has_rewrite("x.inactive.test"));
            assert!(
                policy
                    .rewrite("x.lab.test", RecordType::TXT)
                    .unwrap()
                    .is_empty()
            );
        }
    }
}

#[test]
fn ambiguous_unsupported_and_noncanonical_source_wildcards_remain_blockers() {
    for entries in [
        "{domain: '*.lab.test', answer: A}",
        "{domain: '*.lab.test', answer: alias.test}",
        "{domain: 'part*.lab.test', answer: 192.0.2.1}",
        "{domain: '*.lab.test.', answer: 192.0.2.1}",
        "{domain: '*.bücher.test', answer: 192.0.2.1}",
        "{domain: '*.lab.test', answer: 192.0.2.1}, {domain: '*.lab.test', answer: 192.0.2.2}",
        "{domain: '*.lab.test', answer: 192.0.2.1}, {domain: alias.test, answer: x.lab.test}",
    ] {
        let source = format!("filtering: {{rewrites: [{entries}]}}\n");
        let report = migration::preview(
            Source::Adguard,
            source.as_bytes(),
            PolicyConfigSet::default(),
        )
        .unwrap();
        assert!(!report.ready, "{entries}");
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.severity == migration::Severity::Blocker)
        );
    }
}

#[test]
fn globally_or_individually_disabled_wildcards_do_not_override_filtering() {
    for switch in ["rewrites_enabled: false,", ""] {
        let enabled = if switch.is_empty() { "false" } else { "true" };
        let source = format!(
            "schema_version: 34\nfiltering: {{{switch} rewrites: [{{domain: '*.lab.test', answer: 192.0.2.1, enabled: {enabled}}}]}}\nuser_rules: ['||lab.test^']\n"
        );
        let report = migration::preview(
            Source::Adguard,
            source.as_bytes(),
            PolicyConfigSet::default(),
        )
        .unwrap();
        assert!(report.ready);
        let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
        assert!(!snapshot.policies()[0].has_rewrite("x.lab.test"));
        assert_eq!(
            snapshot
                .explain("127.0.0.1".parse().unwrap(), "x.lab.test")
                .unwrap()
                .decision
                .action,
            Action::Block
        );
    }
}
