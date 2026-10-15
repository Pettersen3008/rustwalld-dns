#![allow(clippy::unwrap_used)]
use hickory_proto::rr::{RData, RecordType};
use rustwalld_dns::migration::{self, Source};
use rustwalld_dns_policy::{PolicyConfigSet, PolicySnapshot};
use serde_json::{Value, json};
use std::io::{Cursor, Write};
fn preview(value: Value) -> migration::Report {
    migration::preview(
        Source::Adguard,
        &serde_json::to_vec(&value).unwrap(),
        PolicyConfigSet::default(),
    )
    .unwrap()
}
fn rules(rules: &[&str]) -> migration::Report {
    preview(json!({"filtering":{"blocked_response_ttl":31},"user_rules":rules}))
}
fn blocked(entries: &[&str]) {
    let report = rules(entries);
    assert!(!report.ready, "{entries:?}");
    assert!(report.config.policies[0].dns_records.is_empty());
    assert!(
        !serde_json::to_string(&report.issues)
            .unwrap()
            .contains("private-fixture-secret")
    );
}
fn archive(value: Value, text: &str) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("AdGuardHome.yaml", options).unwrap();
    zip.write_all(&serde_json::to_vec(&value).unwrap()).unwrap();
    zip.start_file("data/filters/7.txt", options).unwrap();
    zip.write_all(text.as_bytes()).unwrap();
    zip.finish().unwrap().into_inner()
}
#[test]
fn literal_service_mode_imports_preserve_exact_suffix_rrsets_root_ttl_and_nodata() {
    let report = rules(&[
        "|exact.test^$dnsrewrite=NOERROR;HTTPS;1 .",
        "|exact.test|$dnsrewrite=NOERROR;SVCB;65535 SERVICE.home.arpa",
        "||suffix.test^$dnsrewrite=NOERROR;HTTPS;1 .",
        "||suffix.test^$dnsrewrite=NOERROR;HTTPS;2 other.test",
        "||suffix.test^$dnsrewrite=NOERROR;SVCB;3 service.test",
        "||suffix.test^$dnsrewrite=192.0.2.10",
    ]);
    assert!(report.ready, "{:?}", report.issues);
    assert_eq!(report.config.policies[0].dns_records.len(), 10);
    let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
    let policy = &snapshot.policies()[0];
    for (name, count) in [
        ("exact.test", 1),
        ("suffix.test", 2),
        ("a.b.suffix.test", 2),
    ] {
        let values = policy.rewrite(name, RecordType::HTTPS).unwrap();
        assert_eq!(values.len(), count);
        assert!(values.iter().all(|value| value.ttl == 31));
        let RData::HTTPS(value) = &values[0].data else {
            panic!("HTTPS expected")
        };
        assert_eq!(value.svc_priority, 1);
        assert!(value.target_name.is_root() && value.svc_params.is_empty());
        assert!(policy.rewrite(name, RecordType::TXT).unwrap().is_empty());
    }
    assert!(
        policy
            .rewrite("child.exact.test", RecordType::HTTPS)
            .is_none()
    );
    assert_eq!(
        policy
            .rewrite("a.b.suffix.test", RecordType::A)
            .unwrap()
            .len(),
        1
    );
    let RData::SVCB(value) = &policy.rewrite("exact.test", RecordType::SVCB).unwrap()[0].data
    else {
        panic!("SVCB expected")
    };
    assert_eq!(value.svc_priority, 65535);
    assert_eq!(value.target_name.to_ascii(), "service.home.arpa.");
}
#[test]
fn whole_exceptions_remove_both_service_types_but_value_exceptions_are_blockers() {
    for mask in ["|", "||"] {
        let positive = format!("{mask}service.test^$dnsrewrite=NOERROR;HTTPS;1 .");
        let svcb = format!("{mask}service.test^$dnsrewrite=NOERROR;SVCB;2 service.test");
        let bare = format!("@@{mask}service.test^$dnsrewrite");
        for entries in [
            [positive.as_str(), svcb.as_str(), bare.as_str()],
            [bare.as_str(), svcb.as_str(), positive.as_str()],
        ] {
            let report = rules(&entries);
            assert!(report.ready, "{:?}", report.issues);
            assert!(report.config.policies[0].dns_records.is_empty());
        }
        for kind in ["HTTPS", "SVCB"] {
            let except = format!("@@{mask}service.test^$dnsrewrite=NOERROR;{kind};1 .");
            blocked(&[&positive, &except, &bare]);
        }
    }
}
#[test]
fn unsupported_service_binding_forms_clear_all_extracted_answers_without_disclosure() {
    for kind in ["HTTPS", "SVCB"] {
        for value in [
            "65536 .",
            "+1 .",
            "-1 .",
            "1",
            "1  .",
            "1 service.test ",
            "1 service.test.",
            "1 xn--a.test",
            "1 bücher.test",
            "1 . alpn=h2",
            "1 . port=65536",
            "1 . ech=private-fixture-secret",
            "1 . mandatory=alpn",
            "1 . dohpath=private-fixture-secret",
            "1 . ipv4hint=192.0.2.10",
            "1 . key65444=private-fixture-secret",
            "1 . ,client=127.0.0.2",
            "1 .\\,private-fixture-secret",
        ] {
            let rule = format!("||service.test^$dnsrewrite=NOERROR;{kind};{value}");
            blocked(&["|safe.test^$dnsrewrite=192.0.2.10", &rule]);
        }
    }
}
#[test]
fn service_mode_limits_and_canonical_duplicates_apply_per_type_and_mask() {
    for mask in ["|", "||"] {
        for count in [32, 33] {
            let entries: Vec<String> = (1..=count)
                .flat_map(|priority| {
                    [
                        format!("{mask}service.test^$dnsrewrite=NOERROR;HTTPS;{priority} ."),
                        format!("{mask}service.test^$dnsrewrite=NOERROR;SVCB;{priority} ."),
                    ]
                })
                .collect();
            let report = rules(&entries.iter().map(String::as_str).collect::<Vec<_>>());
            assert_eq!(report.ready, count == 32, "{:?}", report.issues);
            assert_eq!(
                report.config.policies[0].dns_records.len(),
                if count == 32 {
                    if mask == "||" { 128 } else { 64 }
                } else {
                    0
                }
            );
        }
        let first = format!("{mask}service.test^$dnsrewrite=NOERROR;HTTPS;1 SERVICE.test");
        let second = format!("{mask}service.test^$dnsrewrite=NOERROR;HTTPS;1 service.test");
        blocked(&[&first, &second]);
    }
}
#[test]
fn bundled_service_mode_effects_preserve_activation_inheritance_and_cross_source_cancellation() {
    for filtering in [false, true] {
        for protection in [false, true] {
            let config = json!({"filtering":{"blocked_response_ttl":0,"protection_enabled":protection,"filtering_enabled":filtering,"rewrites_enabled":false},"filters":[{"id":7,"enabled":true}],"user_rules":["||cancelled.test^$dnsrewrite=NOERROR;HTTPS;1 ."],"clients":{"persistent":[{"name":"Off","ids":["127.0.0.2"],"use_global_settings":false,"filtering_enabled":false}]}});
            let report=migration::preview(Source::Adguard,&archive(config,"@@||cancelled.test^$dnsrewrite\n||service.test^$dnsrewrite=NOERROR;HTTPS;1 .\n||service.test^$dnsrewrite=NOERROR;SVCB;2 service.test\ntracking.test"),PolicyConfigSet::default()).unwrap();
            assert!(report.ready, "{:?}", report.issues);
            assert!(report.config.filter_sources.is_empty());
            assert_eq!(
                report.config.policies[0].dns_records.len(),
                if filtering { 4 } else { 0 }
            );
            assert!(report.config.policies[1].dns_records.is_empty());
            assert!(
                report.config.policies[0]
                    .dns_records
                    .iter()
                    .all(|record| record.ttl == 0)
            );
        }
    }
}
#[test]
fn service_mode_masks_keep_overlap_legacy_alias_and_whitelist_guards() {
    blocked(&[
        "||service.test^$dnsrewrite=NOERROR;HTTPS;1 .",
        "@@|child.service.test^$dnsrewrite",
    ]);
    blocked(&[
        "||service.test^$dnsrewrite=NOERROR;HTTPS;1 .",
        "|child.service.test^$dnsrewrite=NOERROR;SVCB;2 .",
    ]);
    for value in [
        json!({"filtering":{"rewrites":[{"domain":"alias.test","answer":"child.service.test"}]}}),
        json!({"whitelist_filters":[{"id":7,"enabled":true}]}),
    ] {
        let mut value = value;
        value["user_rules"] = json!(["||service.test^$dnsrewrite=NOERROR;HTTPS;1 ."]);
        let report = preview(value);
        assert!(!report.ready);
        assert!(
            report.config.policies[0]
                .dns_records
                .iter()
                .all(|record| record.domain != "service.test" && record.domain != "*.service.test")
        );
    }
}

#[test]
fn alias_mode_imports_preserve_zero_root_type_and_source_controls() {
    for mask in ["|", "||"] {
        for filtering in [true, false] {
            let entries = [
                format!("{mask}alias.test^$dnsrewrite=NOERROR;HTTPS;0 ENDPOINT.home.arpa"),
                format!("{mask}alias.test^$dnsrewrite=NOERROR;SVCB;0 ."),
                format!("{mask}alias.test^$dnsrewrite=192.0.2.1"),
            ];
            let report = preview(
                json!({"filtering":{"blocked_response_ttl":0,"filtering_enabled":filtering,"protection_enabled":false},"user_rules":entries}),
            );
            assert!(report.ready, "{:?}", report.issues);
            assert_eq!(
                report.config.policies[0].dns_records.len(),
                if filtering {
                    if mask == "||" { 6 } else { 3 }
                } else {
                    0
                }
            );
            if !filtering {
                continue;
            }
            let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
            let policy = &snapshot.policies()[0];
            for name in if mask == "||" {
                vec!["alias.test", "child.alias.test", "a.b.alias.test"]
            } else {
                vec!["alias.test"]
            } {
                for kind in [RecordType::HTTPS, RecordType::SVCB] {
                    let records = policy.rewrite(name, kind).unwrap();
                    assert_eq!(records.len(), 1);
                    assert_eq!(records[0].ttl, 0);
                    let value = match &records[0].data {
                        RData::HTTPS(v) => &v.0,
                        RData::SVCB(v) => v,
                        other => panic!("{other:?}"),
                    };
                    assert_eq!(value.svc_priority, 0);
                    assert!(value.svc_params.is_empty());
                    assert_eq!(
                        value.target_name.to_ascii(),
                        if kind == RecordType::HTTPS {
                            "endpoint.home.arpa."
                        } else {
                            "."
                        }
                    );
                    assert!(policy.rewrite_forward(name, kind).is_none());
                }
                assert_eq!(policy.rewrite(name, RecordType::A).unwrap().len(), 1);
                assert!(policy.rewrite(name, RecordType::TXT).unwrap().is_empty());
            }
        }
    }
    let report=migration::preview(Source::Adguard,&archive(json!({"filters":[{"id":7,"enabled":true}],"user_rules":["||cancelled.test^$dnsrewrite=NOERROR;HTTPS;0 endpoint.test"]}),"@@||cancelled.test^$dnsrewrite\n||alias.test^$dnsrewrite=NOERROR;SVCB;0 ."),PolicyConfigSet::default()).unwrap();
    assert!(report.ready, "{:?}", report.issues);
    assert_eq!(report.config.policies[0].dns_records.len(), 2);
    assert!(
        report.config.policies[0]
            .dns_records
            .iter()
            .all(|r| r.domain.ends_with("alias.test"))
    );
}
#[test]
fn alias_mode_conflicts_clear_every_extracted_effect_after_whole_exception_resolution() {
    for mask in ["|", "||"] {
        for kind in ["HTTPS", "SVCB"] {
            let first = format!("{mask}alias.test^$dnsrewrite=NOERROR;{kind};0 endpoint.test");
            for value in ["0 other.test", "1 .", "0 ENDPOINT.test", "0 alias.test"] {
                let second = format!("{mask}alias.test^$dnsrewrite=NOERROR;{kind};{value}");
                for reverse in [false, true] {
                    let pair = if reverse {
                        [&second, &first]
                    } else {
                        [&first, &second]
                    };
                    blocked(&["|safe.test^$dnsrewrite=192.0.2.1", pair[0], pair[1]]);
                    let except = format!("@@{mask}alias.test^$dnsrewrite");
                    let report = rules(&[pair[0], pair[1], &except]);
                    assert!(report.ready, "{:?}", report.issues);
                    assert!(report.config.policies[0].dns_records.is_empty());
                }
            }
            let self_alias = format!("{mask}alias.test^$dnsrewrite=NOERROR;{kind};0 ALIAS.test");
            blocked(&[&self_alias]);
            if mask == "||" {
                blocked(&[&format!(
                    "{mask}alias.test^$dnsrewrite=NOERROR;{kind};0 a.b.alias.test"
                )]);
            }
            let except = format!("@@{mask}alias.test^$dnsrewrite=NOERROR;{kind};0 .");
            blocked(&[&first, &except]);
            blocked(&[&format!(
                "{mask}alias.test^$dnsrewrite=NOERROR;{kind};0 . port=private-fixture-secret"
            )]);
        }
    }
}

#[test]
fn service_port_imports_preserve_wire_values_and_whole_exceptions_across_sources() {
    for kind in ["HTTPS", "SVCB"] {
        for mask in ["|", "||"] {
            let entries = [
                format!("{mask}port.test^$dnsrewrite=NOERROR;{kind};1 ."),
                format!("{mask}port.test^$dnsrewrite=NOERROR;{kind};1 . port=0"),
                format!("{mask}port.test^$dnsrewrite=NOERROR;{kind};1 . port=65535"),
            ];
            let report = rules(&entries.iter().map(String::as_str).collect::<Vec<_>>());
            assert!(report.ready, "{:?}", report.issues);
            let snapshot = PolicySnapshot::compile(report.config, 1).unwrap();
            for name in if mask == "||" {
                vec!["port.test", "a.b.port.test"]
            } else {
                vec!["port.test"]
            } {
                let values = snapshot.policies()[0]
                    .rewrite(name, kind.parse().unwrap())
                    .unwrap();
                assert_eq!(values.len(), 3);
                for (value, port) in values.iter().zip([None, Some(0), Some(65535)]) {
                    let binding = match &value.data {
                        RData::HTTPS(v) => &v.0,
                        RData::SVCB(v) => v,
                        other => panic!("{other:?}"),
                    };
                    assert_eq!(value.ttl, 31);
                    assert_eq!(
                        binding.svc_params,
                        port.map(|p| (
                            hickory_proto::rr::rdata::svcb::SvcParamKey::Port,
                            hickory_proto::rr::rdata::svcb::SvcParamValue::Port(p)
                        ))
                        .into_iter()
                        .collect::<Vec<_>>()
                    );
                }
            }
            let exception = format!("@@{mask}port.test^$dnsrewrite");
            let report = rules(&[&entries[0], &entries[1], &exception]);
            assert!(report.ready);
            assert!(report.config.policies[0].dns_records.is_empty());
            let duplicate = format!("{mask}port.test^$dnsrewrite=NOERROR;{kind};1 . port=00000");
            blocked(&[&entries[1], &duplicate]);
        }
    }
    let report=migration::preview(Source::Adguard,&archive(json!({"filtering":{"blocked_response_ttl":0,"protection_enabled":false},"filters":[{"id":7,"enabled":true}],"user_rules":["||cancelled.test^$dnsrewrite=NOERROR;HTTPS;1 . port=8443"]}),"@@||cancelled.test^$dnsrewrite\n||port.test^$dnsrewrite=NOERROR;SVCB;1 ENDPOINT.test port=443"),PolicyConfigSet::default()).unwrap();
    assert!(report.ready, "{:?}", report.issues);
    assert_eq!(report.config.policies[0].dns_records.len(), 2);
    assert!(
        report.config.policies[0]
            .dns_records
            .iter()
            .all(|r| r.ttl == 0 && serde_json::to_value(&r.data).unwrap()["params"]["port"] == 443)
    );
}
#[test]
fn malformed_service_ports_never_emit_partial_effects_or_drop_unknown_parameters() {
    for kind in ["HTTPS", "SVCB"] {
        for value in [
            "1 . port=",
            "1 . port=-1",
            "1 . port=+1",
            "1 . port=65536",
            "1 . port=1.5",
            "1 . port=443 port=8443",
            "1 . PORT=443",
            "1 . port=443 alpn=h2",
            "1 . alpn=h2 port=443",
            "1 . port=443 ",
            "1 .  port=443",
            "1 . port=443,client=127.0.0.2",
            "1 . port=\"443\"",
            "1 . port=private-fixture-secret",
            "0 . port=0",
        ] {
            let rule = format!("||port.test^$dnsrewrite=NOERROR;{kind};{value}");
            blocked(&["|safe.test^$dnsrewrite=192.0.2.1", &rule]);
            blocked(&[&rule, "@@||port.test^$dnsrewrite"]);
        }
        blocked(&[&format!(
            "@@||port.test^$dnsrewrite=NOERROR;{kind};1 . port=443"
        )]);
    }
}
