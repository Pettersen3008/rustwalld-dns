#![allow(clippy::unwrap_used)]
use hickory_proto::rr::{RData, RecordType};
use rustwalld_dns::migration::{self, Source};
use rustwalld_dns_filter::Action;
use rustwalld_dns_policy::{LocalData, PolicyConfigSet, PolicySnapshot};
use serde_json::{Value, json};
use std::io::{Cursor, Write};
fn preview(rules: &[&str]) -> migration::Report {
    migration::preview(
        Source::Adguard,
        &serde_json::to_vec(&json!({"filtering":{"blocked_response_ttl":37},"user_rules":rules}))
            .unwrap(),
        PolicyConfigSet::default(),
    )
    .unwrap()
}
fn blocked(rules: &[&str]) {
    let report = preview(rules);
    assert!(!report.ready, "{rules:?}");
    assert!(
        report.config.policies[0].dns_records.is_empty(),
        "{rules:?}"
    );
    assert!(
        !serde_json::to_string(&report.issues)
            .unwrap()
            .contains("private-fixture-secret")
    );
}
fn archive(configuration: Value, text: &str) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("AdGuardHome.yaml", options).unwrap();
    zip.write_all(&serde_json::to_vec(&configuration).unwrap())
        .unwrap();
    zip.start_file("data/filters/7.txt", options).unwrap();
    zip.write_all(text.as_bytes()).unwrap();
    zip.finish().unwrap().into_inner()
}
#[test]
fn exact_typed_sets_coexist_with_addresses_and_preserve_requested_type_ttl_and_nodata() {
    let report = preview(&[
        "|service.test^$dnsrewrite=192.0.2.10",
        "|service.test^$dnsrewrite=2001:db8::10",
        "|service.test^$dnsrewrite=NOERROR;TXT;v=spf1 -all;fixture",
        "|service.test^$dnsrewrite=NOERROR;PTR;NAS.home.arpa.",
        "|service.test^$dnsrewrite=NOERROR;MX;10 Mail.home.arpa",
        "|service.test^$dnsrewrite=NOERROR;SRV;1 2 8443 Service.home.arpa",
        "service.test",
    ]);
    assert!(report.ready, "{:?}", report.issues);
    assert_eq!(report.config.policies[0].dns_records.len(), 6);
    let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
    let policy = &snapshot.policies()[0];
    for kind in [
        RecordType::A,
        RecordType::AAAA,
        RecordType::TXT,
        RecordType::PTR,
        RecordType::MX,
        RecordType::SRV,
    ] {
        let answers = policy.rewrite("service.test", kind).unwrap();
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].ttl, 37);
        assert_eq!(answers[0].record_type(), kind);
    }
    let RData::TXT(text) = &policy.rewrite("service.test", RecordType::TXT).unwrap()[0].data else {
        panic!("TXT expected")
    };
    assert_eq!(text.txt_data.len(), 1);
    assert_eq!(text.txt_data[0].as_ref(), b"v=spf1 -all;fixture");
    let RData::PTR(target) = &policy.rewrite("service.test", RecordType::PTR).unwrap()[0].data
    else {
        panic!("PTR expected")
    };
    assert_eq!(target.0.to_ascii(), "nas.home.arpa.");
    let RData::MX(mx) = &policy.rewrite("service.test", RecordType::MX).unwrap()[0].data else {
        panic!("MX expected")
    };
    assert_eq!(mx.preference, 10);
    assert_eq!(mx.exchange.to_ascii(), "mail.home.arpa.");
    let RData::SRV(srv) = &policy.rewrite("service.test", RecordType::SRV).unwrap()[0].data else {
        panic!("SRV expected")
    };
    assert_eq!((srv.priority, srv.weight, srv.port), (1, 2, 8443));
    assert_eq!(srv.target.to_ascii(), "service.home.arpa.");
    assert!(
        policy
            .rewrite("service.test", RecordType::HTTPS)
            .unwrap()
            .is_empty()
    );
    assert!(!policy.has_rewrite("child.service.test"));
}
#[test]
fn txt_and_ptr_value_exceptions_preserve_source_string_equality_and_order_independence() {
    let rules = [
        "|pool.test^$dnsrewrite=NOERROR;TXT;first",
        "|pool.test|$dnsrewrite=NOERROR;TXT;second",
        "@@|pool.test^$dnsrewrite=NOERROR;TXT;first",
        "|pool.test^$dnsrewrite=NOERROR;PTR;NAS.home.arpa",
        "@@|pool.test|$dnsrewrite=NOERROR;PTR;NAS.home.arpa.",
    ];
    for reverse in [false, true] {
        let mut rules = rules.to_vec();
        if reverse {
            rules.reverse();
        }
        let report = preview(&rules);
        assert!(report.ready, "{:?}", report.issues);
        assert_eq!(report.config.policies[0].dns_records.len(), 1);
        assert!(
            matches!(&report.config.policies[0].dns_records[0].data,LocalData::Txt{text} if text=="second")
        );
    }
    // Source PTR comparisons are case-sensitive even though DNS target identity is not.
    let report = preview(&[
        "|pool.test^$dnsrewrite=NOERROR;PTR;NAS.home.arpa",
        "@@|pool.test|$dnsrewrite=NOERROR;PTR;nas.home.arpa.",
    ]);
    assert!(report.ready);
    assert_eq!(report.config.policies[0].dns_records.len(), 1);
    blocked(&[
        "|pool.test^$dnsrewrite=NOERROR;PTR;NAS.home.arpa",
        "|pool.test|$dnsrewrite=NOERROR;PTR;nas.home.arpa.",
    ]);
    let report = preview(&[
        "|pool.test^$dnsrewrite=NOERROR;PTR;NAS.home.arpa",
        "|pool.test|$dnsrewrite=NOERROR;PTR;nas.home.arpa.",
        "@@|pool.test^$dnsrewrite=NOERROR;PTR;nas.home.arpa",
    ]);
    assert!(report.ready);
    assert_eq!(report.config.policies[0].dns_records.len(), 1);
}
#[test]
fn whole_exceptions_restore_ordinary_blocking_but_mx_srv_value_exceptions_require_review() {
    let rules = [
        "|pool.test^$dnsrewrite=NOERROR;TXT;fixture",
        "|pool.test^$dnsrewrite=NOERROR;PTR;nas.test",
        "|pool.test^$dnsrewrite=NOERROR;MX;10 mail.test",
        "|pool.test^$dnsrewrite=NOERROR;SRV;0 0 8443 app.test",
        "@@|pool.test|$dnsrewrite",
        "pool.test",
    ];
    let report = preview(&rules);
    assert!(report.ready, "{:?}", report.issues);
    assert!(report.config.policies[0].dns_records.is_empty());
    let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
    assert_eq!(
        snapshot
            .explain("127.0.0.1".parse().unwrap(), "pool.test")
            .unwrap()
            .decision
            .action,
        Action::Block
    );
    for exception in [
        "@@|pool.test^$dnsrewrite=NOERROR;MX;10 mail.test",
        "@@|pool.test^$dnsrewrite=NOERROR;SRV;0 0 8443 app.test",
    ] {
        blocked(&[
            "|pool.test^$dnsrewrite=NOERROR;TXT;fixture",
            exception,
            "@@|pool.test^$dnsrewrite",
        ]);
    }
}
#[test]
fn unsupported_typed_forms_never_become_broader_answers_or_echo_unknown_values() {
    for value in [
        "|other.test^$dnsrewrite=NOERROR;TXT;private-fixture-secret,client=127.0.0.2",
        "|other.test^$dnsrewrite=NOERROR;TXT;private-fixture-secret\\,text",
        "|other.test^$dnsrewrite=NOERROR;TXT;\"private-fixture-secret\"",
        "|other.test^$dnsrewrite=NOERROR;TXT;private-fixture-secret$dnstype=TXT",
        "|other.test^$dnsrewrite=NOERROR;TXT; private-fixture-secret",
        "|other.test^$dnsrewrite=NOERROR;TXT;private-fixture-secret ",
        "|other.test^$dnsrewrite=NOERROR;TXT;unicode-ø",
        "|other.test^$dnsrewrite=NOERROR;TXT;tab\tvalue",
        "|other.test^$dnsrewrite=NOERROR;PTR;host.test..",
        "|other.test^$dnsrewrite=NOERROR;PTR;_host.test",
        "|other.test^$dnsrewrite=NOERROR;PTR;xn--a.test",
        "|other.test^$dnsrewrite=NOERROR;MX;10 xn--a.test",
        "|other.test^$dnsrewrite=NOERROR;SRV;1 2 53 xn--a.test",
        "|other.test^$dnsrewrite=NOERROR;PTR;bücher.test",
        "|other.test^$dnsrewrite=NOERROR;PTR;-host.test",
        "|other.test^$dnsrewrite=NOERROR;MX;10 mail.test.",
        "|other.test^$dnsrewrite=NOERROR;MX;0 .",
        "|other.test^$dnsrewrite=NOERROR;MX;65536 mail.test",
        "|other.test^$dnsrewrite=NOERROR;MX;+1 mail.test",
        "|other.test^$dnsrewrite=NOERROR;MX;10  mail.test",
        "|other.test^$dnsrewrite=NOERROR;SRV;1 2 65536 host.test",
        "|other.test^$dnsrewrite=NOERROR;SRV;1 2 -1 host.test",
        "|other.test^$dnsrewrite=NOERROR;SRV;1 2 3 host.test extra",
        "|other.test^$dnsrewrite=NOERROR;SRV;1 2 3 host.test.",
        "|other.test^$dnsrewrite=NOERROR;CNAME;host.test",
        "|other.test^$dnsrewrite=REFUSED;TXT;private-fixture-secret",
    ] {
        blocked(&["|pool.test^$dnsrewrite=192.0.2.10", value]);
    }
}
#[test]
fn exact_rrset_limits_and_canonical_duplicates_apply_per_type() {
    for (mask, expansion) in [("|", 1), ("||", 2)] {
        for count in [32, 33] {
            let mut rules = Vec::new();
            for i in 0..count {
                for value in [
                    format!("TXT;fixture{i}"),
                    format!("PTR;host{i}.test"),
                    format!("MX;{i} mail.test"),
                    format!("SRV;{i} 0 8443 app.test"),
                ] {
                    rules.push(format!("{mask}pool.test^$dnsrewrite=NOERROR;{value}"));
                }
            }
            let report = preview(&rules.iter().map(String::as_str).collect::<Vec<_>>());
            assert_eq!(report.ready, count == 32, "{:?}", report.issues);
            assert_eq!(
                report.config.policies[0].dns_records.len(),
                if count == 32 { 128 * expansion } else { 0 }
            );
            if count == 32 {
                let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
                for kind in [
                    RecordType::TXT,
                    RecordType::PTR,
                    RecordType::MX,
                    RecordType::SRV,
                ] {
                    assert_eq!(
                        snapshot.policies()[0]
                            .rewrite("pool.test", kind)
                            .unwrap()
                            .len(),
                        32
                    );
                }
            }
        }
    }
    for pair in [
        ["NOERROR;TXT;value", "NOERROR;TXT;value"],
        ["NOERROR;MX;10 MAIL.test", "NOERROR;MX;10 mail.test"],
        ["NOERROR;SRV;1 2 53 APP.test", "NOERROR;SRV;1 2 53 app.test"],
    ] {
        let a = format!("|pool.test^$dnsrewrite={}", pair[0]);
        let b = format!("|pool.test|$dnsrewrite={}", pair[1]);
        blocked(&[&a, &b]);
    }
}
#[test]
fn txt_source_single_string_boundaries_and_srv_numeric_root_targets_are_preserved() {
    for length in [0, 255, 256] {
        let rule = format!("|pool.test^$dnsrewrite=NOERROR;TXT;{}", "x".repeat(length));
        let empty_exception = preview(&[
            "|pool.test^$dnsrewrite=NOERROR;TXT;",
            "|pool.test|$dnsrewrite=NOERROR;TXT;kept",
            "@@|pool.test^$dnsrewrite=NOERROR;TXT;",
        ]);
        assert!(empty_exception.ready, "{:?}", empty_exception.issues);
        assert_eq!(empty_exception.config.policies[0].dns_records.len(), 1);
        assert!(
            matches!(&empty_exception.config.policies[0].dns_records[0].data,LocalData::Txt {text} if text=="kept")
        );
        let report = preview(&[&rule]);
        assert_eq!(report.ready, length <= 255);
        if length <= 255 {
            let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
            let RData::TXT(txt) = &snapshot.policies()[0]
                .rewrite("pool.test", RecordType::TXT)
                .unwrap()[0]
                .data
            else {
                panic!("TXT expected")
            };
            assert_eq!(txt.txt_data.len(), 1);
            assert_eq!(txt.txt_data[0].len(), length);
        }
    }
    let report = preview(&[
        "|mx.test^$dnsrewrite=NOERROR;MX;65535 MAIL.test",
        "|srv.test^$dnsrewrite=NOERROR;SRV;65535 65535 65535 APP.test",
        "|off.test^$dnsrewrite=NOERROR;SRV;0 0 0 .",
    ]);
    assert!(report.ready, "{:?}", report.issues);
    let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
    let RData::SRV(root) = &snapshot.policies()[0]
        .rewrite("off.test", RecordType::SRV)
        .unwrap()[0]
        .data
    else {
        panic!("SRV expected")
    };
    assert!(root.target.is_root());
}
#[test]
fn typed_bundled_effects_keep_cross_source_exceptions_activation_and_client_settings() {
    for suffix in [false, true] {
        for protection in [true, false] {
            for filtering in [true, false] {
                let configuration = json!({"filtering":{"blocked_response_ttl":0,"protection_enabled":protection,"filtering_enabled":filtering,"rewrites_enabled":false},"filters":[{"id":7,"enabled":true}],"user_rules":["|pool.test^$dnsrewrite=NOERROR;TXT;removed","@@|pool.test^$dnsrewrite=NOERROR;PTR;NAS.test."],"clients":{"persistent":[{"name":"Off","ids":["127.0.0.2"],"use_global_settings":false,"filtering_enabled":false}]}});
                let mut configuration = configuration;
                if suffix {
                    for rule in configuration["user_rules"].as_array_mut().unwrap() {
                        *rule = Value::String(
                            rule.as_str().unwrap().replace("|pool.test", "||pool.test"),
                        );
                    }
                }
                let text = "|pool.test^$dnsrewrite=NOERROR;TXT;kept\n|pool.test^$dnsrewrite=NOERROR;PTR;NAS.test\n|pool.test^$dnsrewrite=NOERROR;MX;10 mail.test\n|pool.test^$dnsrewrite=NOERROR;SRV;0 0 8443 app.test\n@@|pool.test^$dnsrewrite=NOERROR;TXT;removed\ntracking.test\n";
                let data = archive(
                    configuration,
                    &text.replace(
                        "|pool.test",
                        if suffix { "||pool.test" } else { "|pool.test" },
                    ),
                );
                let report =
                    migration::preview(Source::Adguard, &data, PolicyConfigSet::default()).unwrap();
                assert!(report.ready, "{:?}", report.issues);
                assert_eq!(
                    report.config.policies[0].dns_records.len(),
                    if filtering {
                        if suffix { 6 } else { 3 }
                    } else {
                        0
                    }
                );
                assert!(report.config.policies[1].dns_records.is_empty());
                assert!(
                    report.config.policies[0]
                        .dns_records
                        .iter()
                        .all(|record| record.ttl == 0)
                );
                let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
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
}
#[test]
fn typed_coverage_still_blocks_partial_masks_legacy_priority_and_allow_engine_ambiguity() {
    blocked(&[
        "|pool.test^$dnsrewrite=NOERROR;TXT;value",
        "@@||pool.test^$dnsrewrite",
    ]);
    blocked(&[
        "|child.pool.test^$dnsrewrite=NOERROR;TXT;value",
        "||pool.test^$dnsrewrite=192.0.2.10",
    ]);
    let report = preview(&[
        "|pool.test^$dnsrewrite=NOERROR;TXT;value",
        "||child.pool.test^$dnsrewrite=192.0.2.10",
    ]);
    assert!(report.ready);
    for configuration in [
        json!({"filtering":{"rewrites":[{"domain":"alias.test","answer":"pool.test"}]}}),
        json!({"whitelist_filters":[{"id":7,"enabled":true}]}),
    ] {
        let mut value = configuration;
        value["user_rules"] = json!(["|pool.test^$dnsrewrite=NOERROR;TXT;value"]);
        let report = migration::preview(
            Source::Adguard,
            &serde_json::to_vec(&value).unwrap(),
            PolicyConfigSet::default(),
        )
        .unwrap();
        assert!(!report.ready);
        assert!(
            report.config.policies[0]
                .dns_records
                .iter()
                .all(|record| record.domain != "pool.test")
        );
    }
}

#[test]
fn suffix_typed_sets_and_exceptions_preserve_apex_descendants_and_missing_types() {
    let rules = [
        "||typed.test^$dnsrewrite=NOERROR;TXT;first",
        "||typed.test^$dnsrewrite=NOERROR;TXT;second",
        "||typed.test^$dnsrewrite=NOERROR;PTR;NAS.home.arpa",
        "||typed.test^$dnsrewrite=NOERROR;PTR;kept.home.arpa.",
        "||typed.test^$dnsrewrite=NOERROR;MX;10 mail.home.arpa",
        "||typed.test^$dnsrewrite=NOERROR;SRV;1 2 8443 service.home.arpa",
        "@@||typed.test^$dnsrewrite=NOERROR;TXT;first",
        "@@||typed.test^$dnsrewrite=NOERROR;PTR;NAS.home.arpa.",
    ];
    for reverse in [false, true] {
        let mut rules = rules.to_vec();
        if reverse {
            rules.reverse();
        }
        let report = preview(&rules);
        assert!(report.ready, "{:?}", report.issues);
        assert_eq!(report.config.policies[0].dns_records.len(), 8);
        let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
        let policy = &snapshot.policies()[0];
        for name in ["typed.test", "x.typed.test", "a.b.typed.test"] {
            for kind in [
                RecordType::TXT,
                RecordType::PTR,
                RecordType::MX,
                RecordType::SRV,
            ] {
                let records = policy.rewrite(name, kind).unwrap();
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].ttl, 37);
            }
            for kind in [
                RecordType::A,
                RecordType::AAAA,
                RecordType::CNAME,
                RecordType::HTTPS,
            ] {
                assert!(policy.rewrite(name, kind).unwrap().is_empty());
            }
        }
        for name in ["badtyped.test", "typed.test.other", r"x\.typed.test"] {
            assert!(!policy.has_rewrite(name));
        }
    }
    let report = preview(&[
        "||typed.test^$dnsrewrite=NOERROR;TXT;first",
        "@@||typed.test^$dnsrewrite",
        "||typed.test^",
    ]);
    assert!(report.ready);
    assert!(report.config.policies[0].dns_records.is_empty());
    let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
    assert_eq!(
        snapshot
            .explain("127.0.0.1".parse().unwrap(), "x.typed.test")
            .unwrap()
            .decision
            .action,
        Action::Block
    );
}
#[test]
fn typed_suffix_conflicts_never_leave_partial_records() {
    for rule in [
        "|typed.test^$dnsrewrite=NOERROR;TXT;exact",
        "|child.typed.test^$dnsrewrite=NOERROR;TXT;overlap",
        "@@|typed.test^$dnsrewrite",
        "@@||child.typed.test^$dnsrewrite=NOERROR;TXT;different",
        "@@||typed.test^$dnsrewrite=NOERROR;MX;10 mail.test",
        "||typed.test^$dnsrewrite=NOERROR;TXT;kept",
        "||typed.test^$dnsrewrite=NOERROR;PTR;xn--a.test",
        "||typed.test^$dnsrewrite=NOERROR;TXT;private-fixture-secret,client=127.0.0.2",
        "||typed.test^$dnsrewrite=NOERROR;TXT;trailing ",
    ] {
        blocked(&["||typed.test^$dnsrewrite=NOERROR;TXT;kept", rule]);
    }
    // A/AAAA suffix limits stay one per family even alongside typed sets.
    blocked(&[
        "||typed.test^$dnsrewrite=NOERROR;TXT;kept",
        "||typed.test^$dnsrewrite=192.0.2.1",
        "||typed.test^$dnsrewrite=192.0.2.2",
    ]);
}
