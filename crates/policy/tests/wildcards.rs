#![allow(clippy::unwrap_used)]
use hickory_proto::rr::{RData, RecordType};
use rustwalld_dns_filter::{Action, ListInput};
use rustwalld_dns_policy::{
    AddressFamily, LocalData, LocalRecord, PolicyConfigSet, PolicySnapshot, SafeSearchConfig,
};
fn local(domain: &str, data: LocalData) -> LocalRecord {
    LocalRecord {
        domain: domain.into(),
        ttl: 60,
        data,
    }
}
fn configuration() -> PolicyConfigSet {
    let mut config = PolicyConfigSet::default();
    config.policies[0].lists = vec![ListInput {
        name: "privacy".into(),
        action: Action::Block,
        rules: "lab.test".into(),
        syntax: Default::default(),
    }];
    config.policies[0].dns_records = vec![
        local(
            "*.LAB.TEST.",
            LocalData::A {
                address: "192.0.2.10".parse().unwrap(),
            },
        ),
        local(
            "*.lab.test",
            LocalData::Aaaa {
                address: "2001:db8::a".parse().unwrap(),
            },
        ),
        local(
            "*.deep.lab.test",
            LocalData::A {
                address: "192.0.2.20".parse().unwrap(),
            },
        ),
        local(
            "service.deep.lab.test",
            LocalData::A {
                address: "192.0.2.30".parse().unwrap(),
            },
        ),
        local(
            "pass.lab.test",
            LocalData::Passthrough {
                family: AddressFamily::Aaaa,
            },
        ),
        local(
            "text.lab.test",
            LocalData::Txt {
                text: "local".into(),
            },
        ),
        local(
            "alias.lab.test",
            LocalData::Cname {
                target: "external.test".into(),
            },
        ),
    ];
    config
}
#[test]
fn wildcard_family_precedence_apex_boundaries_and_exact_overrides_are_question_specific() {
    let snapshot = PolicySnapshot::compile(configuration(), 1).unwrap();
    let policy = &snapshot.policies()[0];
    for (name, kind, marker) in [
        ("x.lab.test", RecordType::A, 10),
        ("x.deep.lab.test", RecordType::A, 20),
        ("service.deep.lab.test", RecordType::A, 30),
        ("deep.lab.test", RecordType::A, 10),
        ("x.deep.lab.test", RecordType::AAAA, 10),
        ("service.deep.lab.test", RecordType::AAAA, 10),
    ] {
        let records = policy.rewrite(name, kind).unwrap();
        assert_eq!(records.len(), 1);
        match &records[0].data {
            RData::A(ip) => assert_eq!(ip.0.octets()[3], marker),
            RData::AAAA(ip) => assert_eq!(ip.0.segments()[7], u16::from(marker)),
            other => panic!("unexpected {other:?}"),
        }
        assert!(
            snapshot
                .explain_query("127.0.0.1".parse().unwrap(), name, kind)
                .unwrap()
                .rewrite
        );
    }
    for name in [
        "lab.test",
        "badlab.test",
        "child.badlab.test",
        "lab.test.other",
    ] {
        assert!(!policy.has_rewrite(name));
        assert!(policy.rewrite(name, RecordType::A).is_none());
    }
    for kind in [
        RecordType::A,
        RecordType::AAAA,
        RecordType::TXT,
        RecordType::MX,
        RecordType::CNAME,
        RecordType::DS,
        RecordType::Unknown(65400),
    ] {
        if matches!(kind, RecordType::A | RecordType::AAAA) {
            continue;
        }
        assert!(policy.rewrite("x.lab.test", kind).unwrap().is_empty());
    }
    assert!(
        policy
            .rewrite("text.lab.test", RecordType::A)
            .unwrap()
            .is_empty()
    );
    assert!(
        policy
            .rewrite("pass.lab.test", RecordType::A)
            .unwrap()
            .is_empty()
    );
    assert!(policy.rewrite("pass.lab.test", RecordType::AAAA).is_none());
    let explanation = snapshot
        .explain_query(
            "127.0.0.1".parse().unwrap(),
            "pass.lab.test",
            RecordType::AAAA,
        )
        .unwrap();
    assert!(!explanation.rewrite);
    assert_eq!(explanation.decision.action, Action::Block);
    assert!(
        policy
            .rewrite_forward("alias.lab.test", RecordType::A)
            .is_some()
    );
}
#[test]
fn escaped_dots_do_not_create_false_wildcard_label_boundaries() {
    let snapshot = PolicySnapshot::compile(configuration(), 1).unwrap();
    let policy = &snapshot.policies()[0];
    let value = policy.rewrite(r"x\.deep.lab.test", RecordType::A).unwrap();
    assert!(matches!(&value[0].data,RData::A(ip) if ip.0.octets()[3]==10));
    let value = policy.rewrite(r"x\\.deep.lab.test", RecordType::A).unwrap();
    assert!(matches!(&value[0].data,RData::A(ip) if ip.0.octets()[3]==20));
    assert!(policy.rewrite(r"x\.lab.test", RecordType::A).is_none());
}
#[test]
fn wildcard_validation_blocks_ambiguous_families_types_alias_targets_and_safesearch_overlap() {
    for data in [
        LocalData::Cname {
            target: "external.test".into(),
        },
        LocalData::Passthrough {
            family: AddressFamily::A,
        },
    ] {
        let mut config = PolicyConfigSet::default();
        config.policies[0].dns_records = vec![local("*.lab.test", data)];
        assert!(
            PolicySnapshot::compile(config, 1)
                .unwrap_err()
                .to_string()
                .contains("wildcard owners support only")
        );
    }
    let mut config = configuration();
    config.policies[0].dns_records.push(local(
        "*.lab.test",
        LocalData::A {
            address: "192.0.2.99".parse().unwrap(),
        },
    ));
    assert!(
        PolicySnapshot::compile(config, 1)
            .unwrap_err()
            .to_string()
            .contains("one address per family")
    );
    for target in ["x.lab.test", "service.deep.lab.test"] {
        let mut config = configuration();
        config.policies[0].dns_records.push(local(
            "outer.test",
            LocalData::Cname {
                target: target.into(),
            },
        ));
        assert!(
            PolicySnapshot::compile(config, 1)
                .unwrap_err()
                .to_string()
                .contains("CNAME chain targets under wildcard")
        );
    }
    for owner in ["*", "*.*.test", "prefix*.test", "*.bad..test", "*.test.*"] {
        let mut config = PolicyConfigSet::default();
        config.policies[0].dns_records = vec![local(
            owner,
            LocalData::A {
                address: "192.0.2.1".parse().unwrap(),
            },
        )];
        assert!(PolicySnapshot::compile(config, 1).is_err(), "{owner}");
    }
    let mut config = PolicyConfigSet::default();
    config.policies[0].safe_search = Some(SafeSearchConfig {
        google: true,
        ..Default::default()
    });
    config.policies[0].dns_records = vec![local(
        "*.google.com",
        LocalData::A {
            address: "192.0.2.1".parse().unwrap(),
        },
    )];
    assert!(
        PolicySnapshot::compile(config, 1)
            .unwrap_err()
            .to_string()
            .contains("SafeSearch owner/target conflicts")
    );
    let mut config = configuration();
    config.policies[0].safe_search = Some(SafeSearchConfig {
        google: true,
        ..Default::default()
    });
    assert!(PolicySnapshot::compile(config, 1).is_ok());
}
#[test]
fn wildcard_data_roundtrips_and_assertions_gate_real_family_outcomes() {
    let mut config = configuration();
    config.assertions = vec![
        rustwalld_dns_policy::Assertion {
            client: "127.0.0.1".parse().unwrap(),
            domain: "x.lab.test".into(),
            qtype: 1,
            expected: Action::Allow,
        },
        rustwalld_dns_policy::Assertion {
            client: "127.0.0.1".parse().unwrap(),
            domain: "lab.test".into(),
            qtype: 1,
            expected: Action::Block,
        },
    ];
    let serialized = serde_json::to_string(&config).unwrap();
    let snapshot = PolicySnapshot::compile(serde_json::from_str(&serialized).unwrap(), 4).unwrap();
    assert!(snapshot.policies()[0].has_rewrite_for("x.lab.test", RecordType::AAAA));
    config.assertions[1].expected = Action::Allow;
    assert!(PolicySnapshot::compile(config, 5).is_err());
}

#[test]
fn typed_suffix_rrsets_select_complete_overrides_and_preserve_template_data() {
    let mut config = configuration();
    for data in [
        LocalData::Txt {
            text: "first".into(),
        },
        LocalData::Txt {
            text: "second".into(),
        },
        LocalData::Ptr {
            target: "NAS.home.arpa".into(),
        },
        LocalData::Mx {
            preference: 10,
            exchange: "mail.home.arpa".into(),
        },
        LocalData::Srv {
            priority: 1,
            weight: 2,
            port: 8443,
            target: ".".into(),
        },
    ] {
        config.policies[0]
            .dns_records
            .push(local("*.typed.lab.test", data));
    }
    let snapshot = PolicySnapshot::compile(config, 1).unwrap();
    let policy = &snapshot.policies()[0];
    for name in [
        "x.typed.lab.test",
        "a.b.typed.lab.test",
        r"x\.label.typed.lab.test",
    ] {
        for (kind, count) in [
            (RecordType::TXT, 2),
            (RecordType::PTR, 1),
            (RecordType::MX, 1),
            (RecordType::SRV, 1),
        ] {
            let answers = policy.rewrite(name, kind).unwrap();
            assert_eq!(answers.len(), count);
            assert!(
                answers
                    .iter()
                    .all(|record| record.name.to_ascii() == "*.typed.lab.test."
                        && record.ttl == 60
                        && record.record_type() == kind)
            );
        }
        // A typed wildcard overrides all types, including an ancestor address.
        for kind in [
            RecordType::A,
            RecordType::AAAA,
            RecordType::CNAME,
            RecordType::HTTPS,
        ] {
            assert!(policy.rewrite(name, kind).unwrap().is_empty());
        }
    }
    for name in [
        "typed.lab.test",
        "x.badtyped.lab.test",
        r"x\.typed.lab.test",
    ] {
        assert!(policy.rewrite(name, RecordType::TXT).unwrap().is_empty());
        assert_eq!(policy.rewrite(name, RecordType::A).unwrap().len(), 1);
    }
    // The deeper address-only wildcard overrides
    // a parent typed owner with NODATA for non-address types, as for exact owners.
    let mut config = PolicyConfigSet::default();
    config.policies[0].dns_records = vec![
        local(
            "*.lab.test",
            LocalData::Txt {
                text: "parent".into(),
            },
        ),
        local(
            "*.deep.lab.test",
            LocalData::A {
                address: "192.0.2.1".parse().unwrap(),
            },
        ),
        local(
            "exact.lab.test",
            LocalData::Txt {
                text: "exact".into(),
            },
        ),
    ];
    let snapshot = PolicySnapshot::compile(config, 2).unwrap();
    let policy = &snapshot.policies()[0];
    assert!(
        policy
            .rewrite("x.deep.lab.test", RecordType::TXT)
            .unwrap()
            .is_empty()
    );
    assert!(
        policy
            .rewrite("exact.lab.test", RecordType::A)
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        &policy.rewrite("deep.lab.test", RecordType::TXT).unwrap()[0].data,
        RData::TXT(_)
    ));
}
#[test]
fn typed_wildcards_keep_rrset_budgets_ttl_duplicates_and_alias_guards() {
    for count in [32, 33] {
        let mut config = PolicyConfigSet::default();
        config.policies[0].dns_records = (0..count)
            .map(|i| {
                local(
                    "*.lab.test",
                    LocalData::Txt {
                        text: format!("record{i}"),
                    },
                )
            })
            .collect();
        let result = PolicySnapshot::compile(config, 1);
        assert_eq!(result.is_ok(), count == 32);
    }
    let mut config = PolicyConfigSet::default();
    config.policies[0].dns_records = vec![local(
        "*.lab.test",
        LocalData::Txt {
            text: "record".into(),
        },
    )];
    for (text, ttl) in [("record", 60), ("different", 61)] {
        let mut next = config.clone();
        next.policies[0].dns_records.push(LocalRecord {
            domain: "*.lab.test".into(),
            ttl,
            data: LocalData::Txt { text: text.into() },
        });
        assert!(PolicySnapshot::compile(next, 2).is_err());
    }
    config.policies[0].dns_records.push(local(
        "alias.test",
        LocalData::Cname {
            target: "x.lab.test".into(),
        },
    ));
    assert!(
        PolicySnapshot::compile(config, 2)
            .unwrap_err()
            .to_string()
            .contains("CNAME chain targets under wildcard")
    );
}
