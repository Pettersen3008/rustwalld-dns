#![allow(clippy::unwrap_used)]
use hickory_proto::rr::RecordType;
use rustwalld_dns_filter::{Action, ListInput};
use rustwalld_dns_policy::{
    AddressFamily, LocalData, LocalRecord, PolicyConfigSet, PolicySnapshot, Rewrite,
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
        rules: "=split.test\n=alias.test\n=sub.split.test".into(),
        syntax: Default::default(),
    }];
    config.policies[0].dns_records = vec![
        local(
            "SPLIT.TEST.",
            LocalData::A {
                address: "192.0.2.10".parse().unwrap(),
            },
        ),
        local(
            "split.test",
            LocalData::Aaaa {
                address: "2001:db8::10".parse().unwrap(),
            },
        ),
        local(
            "split.test",
            LocalData::Passthrough {
                family: AddressFamily::Aaaa,
            },
        ),
        local(
            "alias.test",
            LocalData::Cname {
                target: "split.test".into(),
            },
        ),
        local(
            "outer.test",
            LocalData::Cname {
                target: "alias.test".into(),
            },
        ),
    ];
    config
}
#[test]
fn normalized_exact_family_directives_resume_filters_and_suppress_terminal_alias_chains() {
    let mut config = configuration();
    config.assertions = vec![
        rustwalld_dns_policy::Assertion {
            client: "127.0.0.1".parse().unwrap(),
            domain: "split.test".into(),
            qtype: 1,
            expected: Action::Allow,
        },
        rustwalld_dns_policy::Assertion {
            client: "127.0.0.1".parse().unwrap(),
            domain: "split.test".into(),
            qtype: 28,
            expected: Action::Block,
        },
    ];
    let serialized = serde_json::to_string(&config).unwrap();
    assert!(serialized.contains("\"type\":\"PASSTHROUGH\""));
    let snapshot = PolicySnapshot::compile(serde_json::from_str(&serialized).unwrap(), 1).unwrap();
    let policy = &snapshot.policies()[0];
    for name in ["split.test", "alias.test", "outer.test"] {
        assert!(policy.has_rewrite(name));
        assert!(!policy.has_rewrite_for(name, RecordType::AAAA));
        assert!(policy.has_rewrite_for(name, RecordType::A));
        assert!(policy.has_rewrite_for(name, RecordType::MX));
    }
    assert!(policy.rewrite("sub.split.test", RecordType::A).is_none());
    assert_eq!(
        policy.rewrite("split.test", RecordType::A).unwrap().len(),
        1
    );
    assert!(
        policy
            .rewrite("split.test", RecordType::MX)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        policy.rewrite("outer.test", RecordType::A).unwrap().len(),
        3
    );
    for (name, kind, rewrite, action) in [
        ("split.test", RecordType::A, true, Action::Allow),
        ("split.test", RecordType::AAAA, false, Action::Block),
        ("alias.test", RecordType::AAAA, false, Action::Block),
        ("outer.test", RecordType::AAAA, false, Action::Allow),
        ("sub.split.test", RecordType::A, false, Action::Block),
    ] {
        let explanation = snapshot
            .explain_query("127.0.0.1".parse().unwrap(), name, kind)
            .unwrap();
        assert_eq!(explanation.rewrite, rewrite);
        assert_eq!(explanation.decision.action, action);
    }
}
#[test]
fn directives_override_legacy_addresses_and_are_order_independent() {
    let mut config = PolicyConfigSet::default();
    config.policies[0].rewrites.push(Rewrite {
        domain: "legacy.test".into(),
        addresses: vec!["192.0.2.2".parse().unwrap(), "2001:db8::2".parse().unwrap()],
        ttl: 60,
    });
    config.policies[0].dns_records = vec![local(
        "legacy.test",
        LocalData::Passthrough {
            family: AddressFamily::A,
        },
    )];
    let mut both = config.clone();
    both.policies[0].dns_records.push(local(
        "legacy.test",
        LocalData::Passthrough {
            family: AddressFamily::Aaaa,
        },
    ));
    let both = PolicySnapshot::compile(both, 2).unwrap();
    assert!(
        both.policies()[0]
            .rewrite("legacy.test", RecordType::A)
            .is_none()
    );
    assert!(
        both.policies()[0]
            .rewrite("legacy.test", RecordType::AAAA)
            .is_none()
    );
    assert!(
        both.policies()[0]
            .rewrite("legacy.test", RecordType::MX)
            .unwrap()
            .is_empty()
    );
    let snapshot = PolicySnapshot::compile(config, 1).unwrap();
    assert!(
        snapshot.policies()[0]
            .rewrite("legacy.test", RecordType::A)
            .is_none()
    );
    assert_eq!(
        snapshot.policies()[0]
            .rewrite("legacy.test", RecordType::AAAA)
            .unwrap()
            .len(),
        1
    );
    let mut config = configuration();
    for generation in 1..=2 {
        let snapshot = PolicySnapshot::compile(config.clone(), generation).unwrap();
        assert!(
            snapshot.policies()[0]
                .rewrite("split.test", RecordType::AAAA)
                .is_none()
        );
        config.policies[0].dns_records.reverse();
    }
}
#[test]
fn duplicate_directives_and_ambiguous_cname_owners_fail_before_publication() {
    let mut config = configuration();
    config.policies[0].dns_records.push(local(
        "SPLIT.test.",
        LocalData::Passthrough {
            family: AddressFamily::Aaaa,
        },
    ));
    assert!(
        PolicySnapshot::compile(config, 1)
            .unwrap_err()
            .to_string()
            .contains("duplicate family")
    );
    for reverse in [false, true] {
        let mut config = configuration();
        config.policies[0].dns_records.push(local(
            "alias.test",
            LocalData::Passthrough {
                family: AddressFamily::A,
            },
        ));
        if reverse {
            config.policies[0].dns_records.reverse();
        }
        assert!(
            PolicySnapshot::compile(config, 1)
                .unwrap_err()
                .to_string()
                .contains("CNAME owner")
        );
    }
}
