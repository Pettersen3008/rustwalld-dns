#![allow(clippy::unwrap_used)]
use hickory_proto::rr::{RData, RecordType};
use rustwalld_dns::migration::{self, Source};
use rustwalld_dns_filter::Action;
use rustwalld_dns_policy::{PolicyConfigSet, PolicySnapshot};
fn preview(value: serde_json::Value) -> migration::Report {
    migration::preview(
        Source::Adguard,
        &serde_json::to_vec(&value).unwrap(),
        PolicyConfigSet::default(),
    )
    .unwrap()
}
fn blocked(rules: &[&str]) {
    let report = preview(serde_json::json!({"user_rules":rules}));
    assert!(!report.ready, "{rules:?}");
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.severity == migration::Severity::Blocker)
    );
    assert!(
        report.config.policies[0].dns_records.is_empty(),
        "{rules:?}"
    );
}
#[test]
fn literal_shorthand_and_full_addresses_preserve_exact_suffix_types_ttl_and_allow_priority() {
    let report = preview(
        serde_json::json!({"filtering":{"blocked_response_ttl":42,"rewrites_enabled":false},"user_rules":["||private.test^$dnsrewrite=192.0.2.10","||private.test^$dnsrewrite=NOERROR;AAAA;2001:db8::a","|exact.test|$dnsrewrite=NOERROR;A;192.0.2.20","|other.test^$dnsrewrite=2001:db8::b","||private.test^","@@||private.test^","||tracking.test^"],"clients":{"persistent":[{"name":"Inherited","ids":["127.0.0.2"],"use_global_settings":true,"filtering_enabled":false},{"name":"Off","ids":["127.0.0.3"],"use_global_settings":false,"filtering_enabled":false}]}}),
    );
    assert!(report.ready, "{:?}", report.issues);
    assert_eq!(report.config.policies[0].dns_records.len(), 6);
    assert!(
        report.config.policies[0]
            .dns_records
            .iter()
            .all(|record| record.ttl == 42)
    );
    assert!(
        report.config.policies[0]
            .lists
            .iter()
            .all(|list| !list.rules.contains("dnsrewrite"))
    );
    let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
    for client in ["127.0.0.1", "127.0.0.2"] {
        let policy = snapshot.select(client.parse().unwrap()).policy;
        for name in ["private.test", "nas.private.test", "apps.nas.private.test"] {
            assert!(
                matches!(&policy.rewrite(name,RecordType::A).unwrap()[0].data,RData::A(ip) if ip.0.octets()[3]==10)
            );
            assert!(
                matches!(&policy.rewrite(name,RecordType::AAAA).unwrap()[0].data,RData::AAAA(ip) if ip.0.segments()[7]==10)
            );
            assert!(policy.rewrite(name, RecordType::TXT).unwrap().is_empty());
            assert!(
                snapshot
                    .explain_query(client.parse().unwrap(), name, RecordType::A)
                    .unwrap()
                    .rewrite
            );
        }
        assert!(!policy.has_rewrite("badprivate.test"));
        assert!(!policy.has_rewrite("child.exact.test"));
        assert!(policy.has_rewrite("exact.test"));
        assert_eq!(
            snapshot
                .explain(client.parse().unwrap(), "tracking.test")
                .unwrap()
                .decision
                .action,
            Action::Block
        );
    }
    let off = snapshot.select("127.0.0.3".parse().unwrap()).policy;
    assert!(!off.has_rewrite("private.test"));
    assert!(!off.has_rewrite("nas.private.test"));
}
#[test]
fn protection_pause_retains_patterns_but_filtering_disable_suppresses_patterns_and_legacy_records()
{
    for protection in [true, false] {
        for filtering in [true, false] {
            let report = preview(
                serde_json::json!({"filtering":{"protection_enabled":protection,"filtering_enabled":filtering,"rewrites":[{"domain":"legacy.test","answer":"192.0.2.20"}]},"user_rules":["||private.test^$dnsrewrite=192.0.2.10","tracking.test"],"clients":{"persistent":[{"name":"Off","ids":["127.0.0.2"],"use_global_settings":false,"filtering_enabled":false}]}}),
            );
            assert!(report.ready, "{:?}", report.issues);
            let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
            assert_eq!(
                snapshot.policies()[0].has_rewrite("private.test"),
                filtering
            );
            assert_eq!(snapshot.policies()[0].has_rewrite("legacy.test"), filtering);
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
            let off = snapshot.select("127.0.0.2".parse().unwrap()).policy;
            assert!(!off.has_rewrite("legacy.test"));
            assert!(!off.has_rewrite("private.test"));
        }
    }
    let report = preview(
        serde_json::json!({"filtering":{"filtering_enabled":false},"user_rules":["||private.test^$dnsrewrite=192.0.2.10"],"clients":{"persistent":[{"name":"On","ids":["127.0.0.2"],"use_global_settings":false,"filtering_enabled":true}]}}),
    );
    assert!(!report.ready);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.field == "clients.persistent[0].filtering_enabled")
    );
}
#[test]
fn pattern_source_ttl_default_zero_and_limits_are_distinct_from_soa_defaults() {
    for ttl in [
        None,
        Some(serde_json::json!(0)),
        Some(serde_json::json!(86400)),
    ] {
        let mut value = serde_json::json!({"user_rules":["|private.test^$dnsrewrite=192.0.2.10"],"filtering":{}});
        if let Some(ttl) = &ttl {
            value["filtering"]["blocked_response_ttl"] = ttl.clone();
        }
        let report = preview(value);
        assert!(report.ready);
        assert_eq!(
            report.config.policies[0].dns_records[0].ttl,
            ttl.and_then(|v| v.as_u64()).unwrap_or(10) as u32
        );
    }
    for ttl in [
        serde_json::json!(null),
        serde_json::json!(-1),
        serde_json::json!("10"),
        serde_json::json!(true),
        serde_json::json!(86401),
        serde_json::json!(1.5),
    ] {
        let report = preview(
            serde_json::json!({"user_rules":["|private.test^$dnsrewrite=192.0.2.10"],"filtering":{"blocked_response_ttl":ttl}}),
        );
        assert!(!report.ready);
        assert!(report.config.policies[0].dns_records.is_empty());
    }
}
#[test]
fn unsupported_patterns_and_effects_block_all_extracted_rewrites_without_echoing_values() {
    for rule in [
        "||other.test^$dnsrewrite=REFUSED",
        "||other.test^$dnsrewrite=NXDOMAIN;;",
        "||other.test^$dnsrewrite=NOERROR;;",
        "||other.test^$dnsrewrite=alias.test",
        "||other.test^$dnsrewrite=NOERROR;NAPTR;private-fixture-secret",
        "@@||private.test^$dnsrewrite=NOERROR;NAPTR;private-fixture-secret",
        "@@||private.test^$dnsrewrite,dnstype=A",
        "@@||private.test^$dnsrewrite=192.0.2.10,badfilter",
        "||private.test^$dnsrewrite=192.0.2.10,badfilter",
        "||other.test^$client=127.0.0.1,dnsrewrite=192.0.2.20",
        "||other.test^$dnsrewrite=192.0.2.20,dnstype=A",
        "||other.test^$dnsrewrite=192.0.2.20,ctag=user_child",
        "||other.test^$dnsrewrite=NOERROR;AAAA;192.0.2.1",
        "||other.test^$dnsrewrite=NOERROR;A;2001:db8::1",
        "||other.test^$dnsrewrite=noerror;A;192.0.2.1",
        "other.test$dnsrewrite=192.0.2.1",
        "||part*.test^$dnsrewrite=192.0.2.1",
        "/.*test/$dnsrewrite=192.0.2.1",
        "/[a-z']+\\.test/$dnsrewrite=NOERROR;TXT;value/",
        "/[a-z']+\\.test/$client=127.0.0.1,dnsrewrite=NOERROR;TXT;value/",
        "||bücher.test^$dnsrewrite=192.0.2.1",
        "||other.test.^$dnsrewrite=192.0.2.1",
        "|| other.test^$dnsrewrite=192.0.2.1",
        "||other.test ^$dnsrewrite=192.0.2.1",
        "| other.test|$dnsrewrite=192.0.2.1",
        "||other.test^$dnsrewrite=::ffff:192.0.2.1",
    ] {
        let report = preview(
            serde_json::json!({"user_rules":["||private.test^$dnsrewrite=192.0.2.10",rule,"tracking.test"]}),
        );
        assert!(!report.ready, "{rule}");
        assert!(report.config.policies[0].dns_records.is_empty(), "{rule}");
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.field == "user_rules[1]")
        );
        assert!(
            !serde_json::to_string(&report.issues)
                .unwrap()
                .contains("private-fixture-secret")
        );
        assert!(
            report.config.policies[0].lists[0]
                .rules
                .contains("tracking.test")
        );
    }
}
#[test]
fn duplicate_overlapping_and_mixed_patterns_are_rejected_in_either_order() {
    for rule in [
        "||private.test^$dnsrewrite=192.0.2.10",
        "||private.test^$dnsrewrite=192.0.2.20",
        "|private.test^$dnsrewrite=2001:db8::1",
        "||deep.private.test^$dnsrewrite=2001:db8::1",
        "|deep.private.test^$dnsrewrite=192.0.2.20",
    ] {
        blocked(&["||private.test^$dnsrewrite=192.0.2.10", rule]);
        blocked(&[rule, "||private.test^$dnsrewrite=192.0.2.10"]);
    }
    let report = preview(
        serde_json::json!({"user_rules":["|private.test^$dnsrewrite=192.0.2.10","||deep.private.test^$dnsrewrite=192.0.2.20"]}),
    );
    assert!(report.ready, "{:?}", report.issues); // disjoint exact parent and suffix child
}
#[test]
fn legacy_owner_alias_target_and_separate_whitelist_priorities_require_review() {
    for domain in ["private.test", "x.private.test", "*.private.test", "*.test"] {
        let report = preview(
            serde_json::json!({"filtering":{"rewrites":[{"domain":domain,"answer":"192.0.2.20"}]},"user_rules":["||private.test^$dnsrewrite=192.0.2.10"]}),
        );
        assert!(!report.ready, "{domain}");
        assert!(
            report.config.policies[0]
                .dns_records
                .iter()
                .all(|record| record.domain == domain)
        );
    }
    let report = preview(
        serde_json::json!({"filtering":{"rewrites":[{"domain":"alias.test","answer":"private.test"}]},"user_rules":["|private.test^$dnsrewrite=192.0.2.10"]}),
    );
    assert!(!report.ready);
    let report = preview(
        serde_json::json!({"whitelist_filters":[{"id":1,"enabled":true,"url":"https://publisher.test/list"}],"user_rules":["||private.test^$dnsrewrite=192.0.2.10"]}),
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
#[test]
fn bounded_pattern_import_keeps_source_paths_comments_and_multiline_failures() {
    let report = preview(
        serde_json::json!({"user_rules":["# ||private.test^$dnsrewrite=192.0.2.10","! comment $dnsrewrite","|ok.test^$dnsrewrite=192.0.2.10\n@@||private.test^$dnsrewrite=REFUSED"]}),
    );
    assert!(!report.ready);
    assert!(report.config.policies[0].dns_records.is_empty());
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.field == "user_rules[2].lines[1]")
    );
    for count in [256, 257, 513] {
        let rules: Vec<_> = (0..count)
            .map(|index| format!("||host{index}.test^$dnsrewrite=192.0.2.10"))
            .collect();
        let report = preview(serde_json::json!({"user_rules":rules}));
        assert_eq!(report.ready, count == 256);
        assert_eq!(
            report.config.policies[0].dns_records.len(),
            if count == 256 { 512 } else { 0 }
        );
        assert!(report.issues.len() <= 200);
    }
    blocked(&[&format!(
        "||{}.test^$dnsrewrite=192.0.2.10",
        "x".repeat(4096)
    )]);
}
#[test]
fn old_dns_settings_layout_keeps_literal_pattern_ttl_and_new_source_names_stay_native_only() {
    let report = preview(
        serde_json::json!({"schema_version":25,"dns":{"blocked_response_ttl":35},"user_rules":["||PRIVATE.test^$dnsrewrite=192.0.2.10"]}),
    );
    assert!(report.ready, "{:?}", report.issues);
    assert!(
        report.config.policies[0]
            .dns_records
            .iter()
            .all(|r| r.ttl == 35 && r.domain.to_ascii_lowercase() == r.domain)
    );
    let mut native = PolicyConfigSet::default();
    native.policies[0].lists = vec![rustwalld_dns_filter::ListInput {
        name: "native".into(),
        action: Action::Block,
        syntax: rustwalld_dns_filter::RuleSyntax::AdguardV6,
        rules: "||private.test^$dnsrewrite=192.0.2.10".into(),
    }];
    assert!(PolicySnapshot::compile(native, 1).is_err());
}

#[test]
fn explicit_or_mixed_control_ttl_layouts_never_activate_ambiguous_pattern_answers() {
    for value in [
        serde_json::json!({"schema_version":34,"dns":{"blocked_response_ttl":35}}),
        serde_json::json!({"schema_version":34,"dns":{"filtering_enabled":false}}),
        serde_json::json!({"schema_version":25,"filtering":{"blocked_response_ttl":35}}),
        serde_json::json!({"schema_version":25,"filtering":{"protection_enabled":false}}),
        serde_json::json!({"dns":{"blocked_response_ttl":35},"filtering":{"blocked_response_ttl":17}}),
        serde_json::json!({"dns":{"filtering_enabled":false},"filtering":{}}),
    ] {
        let mut value = value;
        value["user_rules"] = serde_json::json!(["||private.test^$dnsrewrite=192.0.2.10"]);
        let report = preview(value);
        assert!(!report.ready, "{:?}", report.issues);
        assert!(report.config.policies[0].dns_records.is_empty());
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.message.contains("control/TTL layouts"))
        );
    }
}

#[test]
fn address_expansion_and_oversized_legacy_input_keep_the_combined_record_budget() {
    let mut rules = Vec::new();
    for index in 0..256 {
        rules.push(format!("||host{index}.test^$dnsrewrite=192.0.2.10"));
        rules.push(format!("||host{index}.test^$dnsrewrite=2001:db8::a"));
    }
    let report = preview(serde_json::json!({"user_rules":rules}));
    assert!(report.ready);
    assert_eq!(report.config.policies[0].dns_records.len(), 1024);
    let clients:Vec<_>=(0..9).map(|index|serde_json::json!({"name":format!("Client{index}"),"ids":[format!("127.0.0.{}",index+2)]})).collect();
    let source = serde_json::to_vec(
        &serde_json::json!({"user_rules":rules,"clients":{"persistent":clients}}),
    )
    .unwrap();
    let error = migration::preview(Source::Adguard, &source, PolicyConfigSet::default())
        .err()
        .unwrap();
    assert!(error.contains("10000"));
    let legacy:Vec<_>=(0..10001).map(|index|serde_json::json!({"domain":format!("legacy{index}.outside.test"),"answer":"192.0.2.20"})).collect();
    let source=serde_json::to_vec(&serde_json::json!({"filtering":{"rewrites":legacy},"user_rules":["||private.test^$dnsrewrite=192.0.2.10"]})).unwrap();
    let error = migration::preview(Source::Adguard, &source, PolicyConfigSet::default())
        .err()
        .unwrap();
    assert!(error.contains("10000"));
}

#[test]
fn source_owner_whitespace_never_broadens_legacy_exact_or_wildcard_matching() {
    for owner in [
        " legacy.test",
        "legacy.test ",
        "*. legacy.test",
        "*.legacy.test ",
        "\u{a0}legacy.test",
    ] {
        let report = preview(
            serde_json::json!({"filtering":{"rewrites":[{"domain":owner,"answer":"192.0.2.20"}]}}),
        );
        assert!(!report.ready, "{owner:?}");
        assert!(report.config.policies[0].dns_records.is_empty());
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.field == "filtering.rewrites[0]")
        );
    }
}

#[test]
fn paused_protection_preserves_supported_bundled_patterns_and_blocks_unknown_effects() {
    use std::io::{Cursor, Write};
    let configuration = serde_json::json!({"filtering":{"protection_enabled":false},"filters":[{"id":1,"enabled":true,"url":"https://publisher.test/list"}]});
    let missing = preview(configuration.clone());
    assert!(!missing.ready);
    assert!(
        missing
            .issues
            .iter()
            .any(|issue| issue.field == "filters[0]"
                && issue.severity == migration::Severity::Blocker)
    );
    for (contents, ready) in [
        ("ads.test\n", true),
        ("||private.test^$dnsrewrite=192.0.2.10\n", true),
        ("@@||private.test^$dnsrewrite\n", true),
        (
            "||private.test^$dnsrewrite=NOERROR;NAPTR;private-fixture-secret\n",
            false,
        ),
    ] {
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file("AdGuardHome.yaml", options).unwrap();
        zip.write_all(&serde_json::to_vec(&configuration).unwrap())
            .unwrap();
        zip.start_file("data/filters/1.txt", options).unwrap();
        zip.write_all(contents.as_bytes()).unwrap();
        let input = zip.finish().unwrap().into_inner();
        let report =
            migration::preview(Source::Adguard, &input, PolicyConfigSet::default()).unwrap();
        assert_eq!(report.ready, ready, "{:?}", report.issues);
        assert!(
            !serde_json::to_string(&report.issues)
                .unwrap()
                .contains("private-fixture-secret")
        );
    }
}

#[test]
fn ordinary_hostnames_regex_anchors_and_quoted_clients_do_not_become_rewrite_candidates() {
    let report = preview(
        serde_json::json!({"user_rules":["/dnsrewrite$/","@@/dnsrewrite$/","||dnsrewrite.test^$dnstype=A","||x.test^$client='Name\\,dnsrewrite=value'"],"clients":{"persistent":[{"name":"Name,dnsrewrite=value","ids":["127.0.0.2"]}]}}),
    );
    assert!(report.ready, "{:?}", report.issues);
    assert!(
        report
            .config
            .policies
            .iter()
            .all(|policy| policy.dns_records.is_empty())
    );
    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.field.starts_with("user_rules["))
    );
    let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
    assert_eq!(
        snapshot
            .explain_query(
                "127.0.0.1".parse().unwrap(),
                "dnsrewrite.test",
                RecordType::A
            )
            .unwrap()
            .decision
            .action,
        Action::Block
    );
    assert_eq!(
        snapshot
            .explain("127.0.0.2".parse().unwrap(), "x.test")
            .unwrap()
            .decision
            .action,
        Action::Block
    );
}

#[test]
fn exact_address_sets_preserve_both_families_ttl_and_native_rrset_limits() {
    for count in [32, 33] {
        let mut rules = Vec::new();
        for value in 1..=count {
            rules.push(format!("|PRIVATE.test|$dnsrewrite=192.0.2.{value}"));
            rules.push(format!(
                "|private.test^$dnsrewrite=NOERROR;AAAA;2001:db8::{value:x}"
            ));
        }
        let report = preview(
            serde_json::json!({"filtering":{"blocked_response_ttl":23},"user_rules":rules}),
        );
        assert_eq!(report.ready, count == 32, "{:?}", report.issues);
        if count == 33 {
            assert!(report.config.policies[0].dns_records.is_empty());
            continue;
        }
        assert_eq!(report.config.policies[0].dns_records.len(), 64);
        let policy = PolicySnapshot::compile(report.config, 1).unwrap();
        for kind in [RecordType::A, RecordType::AAAA] {
            let records = policy.policies()[0].rewrite("private.test", kind).unwrap();
            assert_eq!(records.len(), 32);
            assert!(records.iter().all(|record| record.ttl == 23));
        }
        assert!(
            policy.policies()[0]
                .rewrite("private.test", RecordType::TXT)
                .unwrap()
                .is_empty()
        );
        assert!(!policy.policies()[0].has_rewrite("child.private.test"));
    }
    blocked(&[
        "|private.test^$dnsrewrite=192.0.2.10",
        "|PRIVATE.test|$dnsrewrite=NOERROR;A;192.0.2.10",
    ]);
}
#[test]
fn same_coverage_value_exceptions_are_order_independent_and_family_specific() {
    let rules = [
        "|private.test^$dnsrewrite=192.0.2.10",
        "|PRIVATE.test|$dnsrewrite=NOERROR;A;192.0.2.20",
        "|private.test^$dnsrewrite=2001:db8::10",
        "|private.test|$dnsrewrite=2001:db8::20",
        "@@|private.test|$dnsrewrite=NOERROR;A;192.0.2.10",
        "@@|private.test^$dnsrewrite=2001:0db8:0:0:0:0:0:10",
        "@@|disjoint.test^$dnsrewrite",
        "@@|private.test^$dnsrewrite=192.0.2.99",
        "private.test",
    ];
    for reverse in [false, true] {
        let mut rules = rules.to_vec();
        if reverse {
            rules.reverse();
        }
        let report = preview(serde_json::json!({"user_rules":rules}));
        assert!(report.ready, "{:?}", report.issues);
        assert_eq!(report.config.policies[0].dns_records.len(), 2);
        assert!(
            !report.config.policies[0].lists[0]
                .rules
                .contains("dnsrewrite")
        );
        let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
        let policy = &snapshot.policies()[0];
        assert!(
            matches!(&policy.rewrite("private.test",RecordType::A).unwrap()[0].data,RData::A(ip) if ip.0.octets()[3]==20)
        );
        assert!(
            matches!(&policy.rewrite("private.test",RecordType::AAAA).unwrap()[0].data,RData::AAAA(ip) if ip.0.segments()[7]==0x20)
        );
    }
}
#[test]
fn whole_set_exceptions_restore_ordinary_filtering_without_creating_allow_rules() {
    for mask in ["|private.test^", "||private.test^"] {
        for suffix in ["", "="] {
            for reverse in [false, true] {
                let mut rules = vec![
                    format!("{mask}$dnsrewrite=192.0.2.10"),
                    format!("{mask}$dnsrewrite=2001:db8::10"),
                    format!("@@{mask}$dnsrewrite{suffix}"),
                    "||private.test^".into(),
                ];
                if reverse {
                    rules.reverse();
                }
                let report = preview(serde_json::json!({"user_rules":rules}));
                assert!(report.ready, "{:?}", report.issues);
                assert!(report.config.policies[0].dns_records.is_empty());
                let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
                for name in ["private.test", "child.private.test"] {
                    assert!(!snapshot.policies()[0].has_rewrite(name));
                    assert_eq!(
                        snapshot
                            .explain("127.0.0.1".parse().unwrap(), name)
                            .unwrap()
                            .decision
                            .action,
                        Action::Block
                    );
                }
            }
        }
    }
    let report = preview(
        serde_json::json!({"user_rules":["|private.test^$dnsrewrite=192.0.2.10","@@|private.test|$dnsrewrite=192.0.2.10"]}),
    );
    assert!(report.ready);
    let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
    assert!(!snapshot.policies()[0].has_rewrite("private.test"));
    assert_eq!(
        snapshot
            .explain("127.0.0.1".parse().unwrap(), "private.test")
            .unwrap()
            .decision
            .action,
        Action::Allow
    );
}
#[test]
fn suffix_value_exceptions_resolve_before_native_family_limits_and_keep_nodata() {
    let report = preview(
        serde_json::json!({"user_rules":["||private.test^$dnsrewrite=192.0.2.10","||private.test^$dnsrewrite=192.0.2.20","||private.test^$dnsrewrite=2001:db8::10","@@||private.test^$dnsrewrite=192.0.2.10","@@||private.test^$dnsrewrite=2001:db8::10"]}),
    );
    assert!(report.ready, "{:?}", report.issues);
    assert_eq!(report.config.policies[0].dns_records.len(), 2);
    let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
    for name in ["private.test", "child.private.test"] {
        assert!(
            matches!(&snapshot.policies()[0].rewrite(name,RecordType::A).unwrap()[0].data,RData::A(ip) if ip.0.octets()[3]==20)
        );
        assert!(
            snapshot.policies()[0]
                .rewrite(name, RecordType::AAAA)
                .unwrap()
                .is_empty()
        );
    }
}
#[test]
fn partial_exception_coverage_is_blocked_even_when_values_do_not_match_or_other_rules_cancel() {
    for (positive, exception) in [
        ("||private.test^", "|private.test^"),
        ("|private.test^", "||private.test^"),
        ("||private.test^", "|child.private.test^"),
        ("|child.private.test^", "||private.test^"),
        ("||private.test^", "||child.private.test^"),
    ] {
        for value in ["", "=192.0.2.99"] {
            let rules = [
                format!("{positive}$dnsrewrite=192.0.2.10"),
                format!("@@{exception}$dnsrewrite{value}"),
                format!("@@{positive}$dnsrewrite"),
            ];
            blocked(&rules.iter().map(String::as_str).collect::<Vec<_>>());
            blocked(&rules.iter().rev().map(String::as_str).collect::<Vec<_>>());
        }
    }
    let report = preview(
        serde_json::json!({"user_rules":["|private.test^$dnsrewrite=192.0.2.10","@@||child.private.test^$dnsrewrite","@@||badprivate.test^$dnsrewrite"]}),
    );
    assert!(report.ready, "{:?}", report.issues);
}
#[test]
fn exceptions_keep_declaration_and_owner_budgets_and_activation_controls() {
    for count in [256, 257, 513] {
        let rules: Vec<_> = (0..count)
            .map(|index| format!("@@|p{index}.test^$dnsrewrite"))
            .collect();
        let report = preview(serde_json::json!({"user_rules":rules}));
        assert_eq!(report.ready, count == 256);
        assert!(report.config.policies[0].dns_records.is_empty());
        assert!(report.issues.len() <= 200);
    }
    for protection in [true, false] {
        for enabled in [true, false] {
            let report = preview(
                serde_json::json!({"filtering":{"protection_enabled":protection,"filtering_enabled":enabled},"user_rules":["|private.test^$dnsrewrite=192.0.2.10","|private.test^$dnsrewrite=192.0.2.20","@@|private.test^$dnsrewrite=192.0.2.10"],"clients":{"persistent":[{"name":"Off","ids":["127.0.0.2"],"use_global_settings":false,"filtering_enabled":false}]}}),
            );
            assert!(report.ready, "{:?}", report.issues);
            assert_eq!(
                report.config.policies[0].dns_records.len(),
                usize::from(enabled)
            );
            assert!(report.config.policies[1].dns_records.is_empty());
        }
    }
}
