#![allow(clippy::unwrap_used)]
use hickory_proto::rr::{RData, RecordType};
use rustwalld_dns_policy::{LocalData, LocalRecord, PolicyConfigSet, PolicySnapshot};
fn record(domain: &str, data: LocalData) -> LocalRecord {
    LocalRecord {
        domain: domain.into(),
        ttl: 31,
        data,
    }
}
#[test]
fn service_binding_records_roundtrip_select_types_and_preserve_root_and_priority() {
    let mut config = PolicyConfigSet::default();
    config.policies[0].dns_records = vec![
        record(
            "*.lab.test",
            LocalData::Https {
                priority: 1,
                target: ".".into(),
                params: Default::default(),
            },
        ),
        record(
            "*.lab.test",
            LocalData::Svcb {
                priority: 65535,
                target: "SERVICE.home.arpa".into(),
                params: Default::default(),
            },
        ),
        record(
            "exact.lab.test",
            LocalData::Https {
                priority: 2,
                target: "exact.home.arpa".into(),
                params: Default::default(),
            },
        ),
    ];
    let value = serde_json::to_value(&config).unwrap();
    assert_eq!(
        value["policies"][0]["dns_records"][0]["data"]["type"],
        "HTTPS"
    );
    let snapshot = PolicySnapshot::compile(serde_json::from_value(value).unwrap(), 1).unwrap();
    let policy = &snapshot.policies()[0];
    let records = policy.rewrite("deep.lab.test", RecordType::HTTPS).unwrap();
    let RData::HTTPS(https) = &records[0].data else {
        panic!("HTTPS expected")
    };
    assert_eq!(https.svc_priority, 1);
    assert!(https.target_name.is_root() && https.svc_params.is_empty());
    assert_eq!(records[0].name.to_ascii(), "*.lab.test.");
    assert_eq!(records[0].ttl, 31);
    let RData::SVCB(svcb) = &policy.rewrite("deep.lab.test", RecordType::SVCB).unwrap()[0].data
    else {
        panic!("SVCB expected")
    };
    assert_eq!(svcb.svc_priority, 65535);
    assert_eq!(svcb.target_name.to_ascii(), "service.home.arpa.");
    assert!(svcb.svc_params.is_empty());
    for kind in [
        RecordType::A,
        RecordType::AAAA,
        RecordType::TXT,
        RecordType::CNAME,
    ] {
        assert!(policy.rewrite("deep.lab.test", kind).unwrap().is_empty());
    }
    assert!(policy.rewrite("lab.test", RecordType::HTTPS).is_none());
    assert!(policy.rewrite("badlab.test", RecordType::HTTPS).is_none());
    assert!(
        policy
            .rewrite("exact.lab.test", RecordType::SVCB)
            .unwrap()
            .is_empty()
    );
}
#[test]
fn service_binding_admission_rejects_params_duplicates_mixed_ttl_and_overflow() {
    for kind in ["HTTPS", "SVCB"] {
        assert!(
            serde_json::from_value::<LocalData>(
                serde_json::json!({"type":kind,"priority":1,"target":".","params":[]})
            )
            .is_err()
        );
        for count in [32, 33] {
            let mut config = PolicyConfigSet::default();
            config.policies[0].dns_records = (1..=count)
                .map(|priority| {
                    record(
                        "*.lab.test",
                        if kind == "HTTPS" {
                            LocalData::Https {
                                priority,
                                target: ".".into(),
                                params: Default::default(),
                            }
                        } else {
                            LocalData::Svcb {
                                priority,
                                target: ".".into(),
                                params: Default::default(),
                            }
                        },
                    )
                })
                .collect();
            assert_eq!(PolicySnapshot::compile(config, 1).is_ok(), count == 32);
        }
    }
    for (domain, data, ttl) in [
        (
            "*.LAB.TEST",
            LocalData::Https {
                priority: 1,
                target: "SERVICE.test".into(),
                params: Default::default(),
            },
            31,
        ),
        (
            "*.lab.test",
            LocalData::Https {
                priority: 2,
                target: "service.test".into(),
                params: Default::default(),
            },
            32,
        ),
        (
            "*.lab.test",
            LocalData::Cname {
                target: "service.test".into(),
            },
            31,
        ),
        (
            "*.lab.test",
            LocalData::Https {
                priority: 1,
                target: "xn--a.test".into(),
                params: Default::default(),
            },
            31,
        ),
    ] {
        let mut config = PolicyConfigSet::default();
        config.policies[0].dns_records = vec![
            record(
                "*.lab.test",
                LocalData::Https {
                    priority: 1,
                    target: "service.test".into(),
                    params: Default::default(),
                },
            ),
            LocalRecord {
                domain: domain.into(),
                ttl,
                data,
            },
        ];
        assert!(PolicySnapshot::compile(config, 1).is_err());
    }
}

#[test]
fn alias_mode_is_type_specific_and_rejects_ambiguous_rrsets_and_self_targets() {
    for kind in ["HTTPS", "SVCB"] {
        let data = |priority, target: &str| {
            serde_json::from_value::<LocalData>(
                serde_json::json!({"type":kind,"priority":priority,"target":target}),
            )
            .unwrap()
        };
        for owner in ["exact.test", "*.test"] {
            for target in [".", "endpoint.home.arpa"] {
                let mut config = PolicyConfigSet::default();
                config.policies[0].dns_records = vec![
                    record(owner, data(0, target)),
                    record(
                        owner,
                        LocalData::A {
                            address: "192.0.2.1".parse().unwrap(),
                        },
                    ),
                ];
                let value = serde_json::to_value(&config).unwrap();
                let snapshot =
                    PolicySnapshot::compile(serde_json::from_value(value).unwrap(), 1).unwrap();
                let policy = &snapshot.policies()[0];
                let name = if owner.starts_with('*') {
                    "a.b.test"
                } else {
                    owner
                };
                let records = policy.rewrite(name, kind.parse().unwrap()).unwrap();
                let binding = match &records[0].data {
                    RData::HTTPS(v) => &v.0,
                    RData::SVCB(v) => v,
                    other => panic!("{other:?}"),
                };
                assert_eq!(binding.svc_priority, 0);
                assert_eq!(
                    binding.target_name.to_ascii(),
                    if target == "." {
                        ".".into()
                    } else {
                        format!("{target}.")
                    }
                );
                assert!(binding.svc_params.is_empty());
                assert_eq!(policy.rewrite(name, RecordType::A).unwrap().len(), 1);
                assert!(policy.rewrite(name, RecordType::CNAME).unwrap().is_empty());
                assert!(
                    policy
                        .rewrite_forward(name, kind.parse().unwrap())
                        .is_none()
                );
            }
            for other in [data(0, "other.home.arpa"), data(1, ".")] {
                for reverse in [false, true] {
                    let mut entries = vec![
                        record(owner, data(0, "endpoint.home.arpa")),
                        record(owner, other.clone()),
                    ];
                    if reverse {
                        entries.reverse();
                    }
                    let mut config = PolicyConfigSet::default();
                    config.policies[0].dns_records = entries;
                    assert!(
                        PolicySnapshot::compile(config, 1)
                            .unwrap_err()
                            .to_string()
                            .contains("one record per owner/type")
                    );
                }
            }
        }
        for (owner, target) in [
            ("exact.test", "EXACT.TEST"),
            ("*.test", "child.test"),
            ("*.test", "a.b.TEST"),
        ] {
            let mut config = PolicyConfigSet::default();
            config.policies[0].dns_records = vec![record(owner, data(0, target))];
            assert!(
                PolicySnapshot::compile(config, 1)
                    .unwrap_err()
                    .to_string()
                    .contains("own exact or synthesized")
            );
        }
        // Wildcard does not include its apex; a service can point there.
        let mut config = PolicyConfigSet::default();
        config.policies[0].dns_records = vec![record("*.test", data(0, "test"))];
        assert!(PolicySnapshot::compile(config, 1).is_ok());
    }
    let mut config = PolicyConfigSet::default();
    config.policies[0].dns_records = vec![
        record(
            "service.test",
            LocalData::Https {
                priority: 0,
                target: "endpoint.test".into(),
                params: Default::default(),
            },
        ),
        record(
            "service.test",
            LocalData::Svcb {
                priority: 1,
                target: ".".into(),
                params: Default::default(),
            },
        ),
    ];
    assert!(PolicySnapshot::compile(config, 1).is_ok());
}

#[test]
fn service_ports_are_typed_optional_and_never_silently_ignored_in_alias_mode() {
    for kind in ["HTTPS", "SVCB"] {
        for port in [None, Some(0), Some(1), Some(65535)] {
            let mut data = serde_json::json!({"type":kind,"priority":1,"target":"."});
            if let Some(port) = port {
                data["params"] = serde_json::json!({"port":port});
            }
            let data: LocalData = serde_json::from_value(data).unwrap();
            assert_eq!(
                serde_json::to_value(&data).unwrap().get("params").is_some(),
                port.is_some()
            );
            let mut config = PolicyConfigSet::default();
            config.policies[0].dns_records = vec![record("*.port.test", data)];
            let snapshot = PolicySnapshot::compile(config, 1).unwrap();
            let values = snapshot.policies()[0]
                .rewrite("child.port.test", kind.parse().unwrap())
                .unwrap();
            let service = match &values[0].data {
                RData::HTTPS(v) => &v.0,
                RData::SVCB(v) => v,
                other => panic!("{other:?}"),
            };
            let expected = port
                .map(|value| {
                    (
                        hickory_proto::rr::rdata::svcb::SvcParamKey::Port,
                        hickory_proto::rr::rdata::svcb::SvcParamValue::Port(value),
                    )
                })
                .into_iter()
                .collect::<Vec<_>>();
            assert_eq!(service.svc_params, expected);
            assert!(service.target_name.is_root());
            if let Some(port) = port {
                config = PolicyConfigSet::default();
                config.policies[0].dns_records=vec![record("port.test",serde_json::from_value(serde_json::json!({"type":kind,"priority":0,"target":".","params":{"port":port}})).unwrap())];
                assert!(
                    PolicySnapshot::compile(config, 1)
                        .unwrap_err()
                        .to_string()
                        .contains("AliasMode does not support service parameters")
                );
            }
        }
        assert!(serde_json::from_str::<LocalData>(&format!(r#"{{"type":"{kind}","priority":1,"target":".","params":{{"port":443,"port":8443}}}}"#)).is_err());
        let empty: LocalData = serde_json::from_value(
            serde_json::json!({"type":kind,"priority":0,"target":".","params":{}}),
        )
        .unwrap();
        assert!(
            serde_json::to_value(&empty)
                .unwrap()
                .get("params")
                .is_none()
        );
        for params in [
            serde_json::json!([]),
            serde_json::json!(null),
            serde_json::json!({"port":-1}),
            serde_json::json!({"port":65536}),
            serde_json::json!({"port":1.5}),
            serde_json::json!({"port":"443"}),
            serde_json::json!({"port":443,"alpn":["h2"]}),
            serde_json::json!({"unknown":"private-fixture-secret"}),
        ] {
            assert!(
                serde_json::from_value::<LocalData>(
                    serde_json::json!({"type":kind,"priority":1,"target":".","params":params})
                )
                .is_err()
            );
        }
    }
}
#[test]
fn service_rrsets_distinguish_explicit_port_zero_default_and_other_ports() {
    for kind in ["HTTPS", "SVCB"] {
        let data = |port| {
            serde_json::from_value::<LocalData>(
                serde_json::json!({"type":kind,"priority":1,"target":".","params":{"port":port}}),
            )
            .unwrap()
        };
        let mut config = PolicyConfigSet::default();
        config.policies[0].dns_records = vec![
            record("port.test", data(None::<u16>)),
            record("port.test", data(Some(0))),
            record("port.test", data(Some(443))),
        ];
        assert!(PolicySnapshot::compile(config.clone(), 1).is_ok());
        config.policies[0]
            .dns_records
            .push(record("PORT.test", data(Some(443))));
        assert!(PolicySnapshot::compile(config, 1).is_err());
    }
}
