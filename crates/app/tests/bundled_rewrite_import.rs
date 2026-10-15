#![allow(clippy::unwrap_used)]
use hickory_proto::rr::{RData, RecordType};
use rustwalld_dns::migration::{self, Source};
use rustwalld_dns_filter::Action;
use rustwalld_dns_policy::{PolicyConfigSet, PolicySnapshot};
use serde_json::{Value, json};
use std::io::{Cursor, Write};
fn archive(config: Value, files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("AdGuardHome.yaml", options).unwrap();
    zip.write_all(&serde_json::to_vec(&config).unwrap())
        .unwrap();
    for (name, contents) in files {
        zip.start_file(*name, options).unwrap();
        zip.write_all(contents).unwrap();
    }
    zip.finish().unwrap().into_inner()
}
fn preview(config: Value, files: &[(&str, &[u8])]) -> migration::Report {
    migration::preview(
        Source::Adguard,
        &archive(config, files),
        PolicyConfigSet::default(),
    )
    .unwrap()
}
fn source() -> Value {
    json!({"schema_version":34,"filtering":{"blocked_response_ttl":27},"filters":[{"id":1,"enabled":true,"url":"https://publisher.test/one"},{"id":2,"enabled":true,"url":"https://publisher.test/two"}]})
}
#[test]
fn custom_and_bundled_feeds_share_address_sets_exceptions_ttl_and_client_inheritance() {
    let mut config = source();
    config["user_rules"] = json!([
        "|pool.test^$dnsrewrite=192.0.2.10",
        "|cancelled.test^$dnsrewrite=192.0.2.10"
    ]);
    config["clients"] = json!({"persistent":[{"name":"Inherited","ids":["127.0.0.2"]},{"name":"Off","ids":["127.0.0.3"],"use_global_settings":false,"filtering_enabled":false}]});
    let report=preview(config,&[("data/filters/1.txt",b"! fixture\n|pool.test^$dnsrewrite=192.0.2.20\n|pool.test^$dnsrewrite=2001:db8::20\n||private.test^$dnsrewrite=192.0.2.30\ntracking.test\ncancelled.test\n"),("filters/2.txt",b"@@|pool.test|$dnsrewrite=NOERROR;A;192.0.2.10\n|pool.test^$dnsrewrite=192.0.2.40\n@@|cancelled.test|$dnsrewrite\n")]);
    assert!(report.ready, "{:?}", report.issues);
    assert_eq!(
        report
            .publishers
            .iter()
            .filter(|publisher| publisher.policy == report.config.policies[0].name)
            .count(),
        2
    );
    assert!(
        report
            .publishers
            .iter()
            .all(|publisher| !publisher.needs_download)
    );
    assert!(report.config.filter_sources.is_empty());
    assert_eq!(report.config.policies[0].dns_records.len(), 5);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.field == "filters[0].contents.lines[1]"
                && issue.message.contains("became native"))
    );
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.field == "filters[1].contents.lines[0]"
                && issue.message.contains("exception was resolved"))
    );
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.message.contains("frozen import snapshot"))
    );
    for policy in &report.config.policies {
        assert!(
            policy
                .lists
                .iter()
                .all(|list| !list.rules.contains("dnsrewrite"))
        );
        assert!(policy.dns_records.iter().all(|record| record.ttl == 27));
    }
    let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
    for client in ["127.0.0.1", "127.0.0.2"] {
        let policy = snapshot.select(client.parse().unwrap()).policy;
        let answers = policy.rewrite("pool.test", RecordType::A).unwrap();
        assert_eq!(answers.len(), 2);
        assert!(matches!(&answers[0].data,RData::A(ip) if ip.0.octets()[3]==20));
        assert!(matches!(&answers[1].data,RData::A(ip) if ip.0.octets()[3]==40));
        assert_eq!(
            policy.rewrite("pool.test", RecordType::AAAA).unwrap().len(),
            1
        );
        assert!(
            policy
                .rewrite("child.private.test", RecordType::TXT)
                .unwrap()
                .is_empty()
        );
        assert!(!policy.has_rewrite("cancelled.test"));
        assert_eq!(
            snapshot
                .explain(client.parse().unwrap(), "cancelled.test")
                .unwrap()
                .decision
                .action,
            Action::Block
        );
    }
    let off = snapshot.select("127.0.0.3".parse().unwrap()).policy;
    assert!(!off.has_rewrite("pool.test"));
}
#[test]
fn bundled_rewrites_keep_pause_disable_and_disabled_feed_semantics() {
    for protection in [true, false] {
        for filtering in [true, false] {
            let config = json!({"filtering":{"protection_enabled":protection,"filtering_enabled":filtering},"filters":[{"id":1,"enabled":true},{"id":2,"enabled":false}],"user_rules":["|pool.test^$dnsrewrite=192.0.2.10"]});
            let report=preview(config,&[("filters/1.txt",b"@@|pool.test^$dnsrewrite=192.0.2.10\n||private.test^$dnsrewrite=2001:db8::20\ntracking.test"),("filters/2.txt",b"||bad.test^$dnsrewrite=NOERROR;NAPTR;private-fixture-secret")]);
            assert!(report.ready, "{:?}", report.issues);
            let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
            assert_eq!(
                snapshot.policies()[0].has_rewrite("private.test"),
                filtering
            );
            assert!(!snapshot.policies()[0].has_rewrite("pool.test"));
            assert_eq!(
                snapshot
                    .explain("127.0.0.1".parse().unwrap(), "tracking.test")
                    .unwrap()
                    .decision
                    .action,
                if protection && filtering {
                    Action::Block
                } else {
                    Action::Allow
                }
            );
        }
    }
}
#[test]
fn unsupported_or_missing_feed_effects_clear_custom_and_other_feed_rewrites() {
    for value in [
        "||bad.test^$dnsrewrite=NOERROR;NAPTR;private-fixture-secret",
        "@@|private.test^$dnsrewrite",
        "||child.private.test^$dnsrewrite=192.0.2.30",
    ] {
        let mut config = source();
        config["user_rules"] = json!(["||private.test^$dnsrewrite=192.0.2.10"]);
        let report = preview(
            config,
            &[
                (
                    "filters/1.txt",
                    b"|pool.test^$dnsrewrite=192.0.2.20\ntracking.test",
                ),
                ("filters/2.txt", value.as_bytes()),
            ],
        );
        assert!(!report.ready);
        assert!(report.config.policies[0].dns_records.is_empty());
        assert!(
            !serde_json::to_string(&report.issues)
                .unwrap()
                .contains("private-fixture-secret")
        );
        assert!(
            report.config.policies[0]
                .lists
                .iter()
                .any(|list| list.rules.contains("tracking.test"))
        );
    }
    for protection in [true, false] {
        let mut config = source();
        config["filtering"]["protection_enabled"] = json!(protection);
        config["user_rules"] = json!(["|custom.test^$dnsrewrite=192.0.2.10"]);
        let report = preview(
            config,
            &[("filters/1.txt", b"|pool.test^$dnsrewrite=192.0.2.20")],
        );
        assert!(!report.ready);
        assert!(report.config.policies[0].dns_records.is_empty());
    }
}
#[test]
fn global_declaration_owner_and_line_budgets_span_custom_rules_and_all_feeds() {
    for extra in [false, true] {
        let mut config = source();
        config["user_rules"] = json!(
            (0..256)
                .map(|i| format!("@@|p{i}.test^$dnsrewrite"))
                .collect::<Vec<_>>()
        );
        let one = (0..128)
            .map(|i| format!("|p{i}.test^$dnsrewrite=192.0.2.10\n"))
            .collect::<String>();
        let mut two = (128..256)
            .map(|i| format!("|p{i}.test^$dnsrewrite=192.0.2.10\n"))
            .collect::<String>();
        if extra {
            two.push_str("@@|p0.test^$dnsrewrite\n");
        }
        let report = preview(
            config,
            &[
                ("filters/1.txt", one.as_bytes()),
                ("filters/2.txt", two.as_bytes()),
            ],
        );
        assert_eq!(report.ready, !extra, "{:?}", report.issues);
        assert!(report.config.policies[0].dns_records.is_empty());
        assert!(report.issues.len() <= 200);
        if extra {
            assert!(report.blockers > 0);
        }
    }
    let mut config = source();
    config["user_rules"] = json!(
        (0..256)
            .map(|i| format!("@@|p{i}.test^$dnsrewrite"))
            .collect::<Vec<_>>()
    );
    let report = preview(
        config,
        &[
            ("filters/1.txt", b"@@|new.test^$dnsrewrite"),
            ("filters/2.txt", b"! empty"),
        ],
    );
    assert!(!report.ready);
    let long = format!("||{}.test^$dnsrewrite=192.0.2.10", "x".repeat(4096));
    let report = preview(
        source(),
        &[
            ("filters/1.txt", long.as_bytes()),
            ("filters/2.txt", b"! empty"),
        ],
    );
    assert!(!report.ready);
    assert!(report.issues.iter().any(
        |issue| issue.field == "filters[0].contents.lines[0]" && issue.message.contains("4096")
    ));
}
#[test]
fn feed_only_imports_apply_schema_and_ttl_layout_guards() {
    for (version, container, ready) in [
        (25, "dns", true),
        (34, "filtering", true),
        (34, "dns", false),
        (25, "filtering", false),
    ] {
        let mut config = json!({"schema_version":version,"filters":[{"id":1,"enabled":true}]});
        config[container] = json!({"blocked_response_ttl":31});
        let report = preview(
            config,
            &[("filters/1.txt", b"||private.test^$dnsrewrite=192.0.2.10")],
        );
        assert_eq!(report.ready, ready, "{:?}", report.issues);
        assert_eq!(
            report.config.policies[0].dns_records.len(),
            if ready { 2 } else { 0 }
        );
        assert!(
            report.config.policies[0]
                .dns_records
                .iter()
                .all(|record| record.ttl == 31)
        );
    }
}
#[test]
fn ambiguous_archive_files_and_source_identities_are_not_selected_arbitrarily() {
    let ambiguous = preview(
        json!({"filters":[{"id":1,"enabled":true}]}),
        &[
            ("filters/1.txt", b"|pool.test^$dnsrewrite=192.0.2.10"),
            ("data/filters/1.txt", b"|other.test^$dnsrewrite=192.0.2.20"),
        ],
    );
    assert!(!ambiguous.ready);
    assert!(ambiguous.config.policies[0].dns_records.is_empty());
    assert!(
        ambiguous
            .issues
            .iter()
            .any(|issue| issue.message.contains("Multiple archive files"))
    );
    for (configuration, diagnostic) in [
        (
            json!({"filters":[{"id":1,"enabled":true},{"id":1,"enabled":true}]}),
            "Repeated filter IDs",
        ),
        (
            json!({"filters":[{"id":1,"enabled":false,"url":"https://publisher.test/same"},{"id":2,"enabled":true,"url":"https://publisher.test/same"}]}),
            "Repeated filter IDs",
        ),
        (
            json!({"filters":[{"id":0,"enabled":true}]}),
            "Nonpositive filter IDs",
        ),
        (
            json!({"filters":[{"id":-1,"enabled":true}]}),
            "Nonpositive filter IDs",
        ),
    ] {
        let report = preview(
            configuration,
            &[
                ("filters/1.txt", b"|pool.test^$dnsrewrite=192.0.2.10"),
                ("filters/2.txt", b"|pool.test^$dnsrewrite=192.0.2.10"),
                ("filters/0.txt", b"|pool.test^$dnsrewrite=192.0.2.10"),
                ("filters/-1.txt", b"|pool.test^$dnsrewrite=192.0.2.10"),
            ],
        );
        assert!(!report.ready);
        assert!(report.config.policies[0].dns_records.is_empty());
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.message.contains(diagnostic)),
            "{:?}",
            report.issues
        );
    }
    let inactive = preview(
        json!({"filtering":{"filtering_enabled":false},"filters":[{"id":1,"enabled":true},{"id":1,"enabled":true}]}),
        &[
            ("filters/1.txt", b"|pool.test^$dnsrewrite=192.0.2.10"),
            ("data/filters/1.txt", b"|other.test^$dnsrewrite=192.0.2.20"),
        ],
    );
    assert!(inactive.ready, "{:?}", inactive.issues);
    assert!(inactive.config.policies[0].dns_records.is_empty());
    // Omitted activation needs its own guard even with an unambiguous file.
    let report = preview(
        json!({"filters":[{"id":1}]}),
        &[("filters/1.txt", b"|pool.test^$dnsrewrite=192.0.2.10")],
    );
    assert!(!report.ready);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.message.contains("explicit enabled: true"))
    );
}
#[test]
fn separate_allow_engine_and_whitelist_effects_remain_explicit_blockers() {
    let config =
        json!({"filters":[{"id":1,"enabled":true}],"whitelist_filters":[{"id":2,"enabled":true}]});
    for text in [b"safe.test".as_slice(), b"@@|pool.test^$dnsrewrite"] {
        let report = preview(
            config.clone(),
            &[
                ("filters/1.txt", b"|pool.test^$dnsrewrite=192.0.2.10"),
                ("filters/2.txt", text),
            ],
        );
        assert!(!report.ready);
        assert!(report.config.policies[0].dns_records.is_empty());
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.field == "whitelist_filters")
        );
    }
}
#[test]
fn invalid_active_feed_encoding_fails_without_interpreting_or_exposing_its_contents() {
    let config = json!({"filters":[{"id":1,"enabled":true}]});
    let input = archive(config, &[("filters/1.txt", b"\xffprivate-fixture-secret")]);
    let error = migration::preview(Source::Adguard, &input, PolicyConfigSet::default())
        .err()
        .unwrap();
    assert!(error.contains("UTF-8") && !error.contains("private-fixture-secret"));
    let report = preview(
        json!({"filtering":{"filtering_enabled":false},"filters":[{"id":1,"enabled":true}]}),
        &[("filters/1.txt", b"\xffprivate-fixture-secret")],
    );
    assert!(report.ready);
}
