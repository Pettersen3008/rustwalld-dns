#![allow(clippy::unwrap_used)]
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{Name, RData, RecordType},
};
use rustwalld_dns_core::{Engine, EngineConfig, Prepared, PublicationTarget, Telemetry, Transport};
use rustwalld_dns_policy::{LocalData, LocalRecord, PolicyConfigSet, PolicySnapshot};
fn query(name: &str, kind: RecordType) -> Vec<u8> {
    let mut value = Message::query();
    value.metadata.recursion_desired = true;
    value.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    value.to_vec().unwrap()
}
fn local(engine: &Engine, name: &str, kind: RecordType, transport: Transport) -> Message {
    let Prepared::Reply(bytes) =
        engine.prepare(&query(name, kind), "127.0.0.1".parse().unwrap(), transport)
    else {
        panic!("local service records must not forward")
    };
    Message::from_vec(&bytes).unwrap()
}
#[tokio::test]
async fn service_binding_wire_values_owner_case_shadow_and_large_sets_remain_local_and_bounded() {
    let mut config = PolicyConfigSet::default();
    // Never contacted: prepare must finish every fixture synchronously.
    config.upstreams[0].addresses = vec!["127.0.0.1:9".parse().unwrap()];
    config.policies[0].dns_records = vec![
        LocalRecord {
            domain: "*.service.test".into(),
            ttl: 31,
            data: LocalData::Https {
                priority: 1,
                target: ".".into(),
                params: Default::default(),
            },
        },
        LocalRecord {
            domain: "*.service.test".into(),
            ttl: 31,
            data: LocalData::Svcb {
                priority: 65535,
                target: "ENDPOINT.home.arpa".into(),
                params: Default::default(),
            },
        },
    ];
    config.policies[0].dns_records.extend([
        LocalRecord {
            domain: "origin.test".into(),
            ttl: 31,
            data: LocalData::Https {
                priority: 1,
                target: ".".into(),
                params: Default::default(),
            },
        },
        LocalRecord {
            domain: "alias.test".into(),
            ttl: 31,
            data: LocalData::Cname {
                target: "origin.test".into(),
            },
        },
    ]);
    let (telemetry, mut events) = Telemetry::channel(64);
    let (engine, controller) = Engine::controlled(
        PolicySnapshot::compile(config.clone(), 1).unwrap(),
        EngineConfig::default(),
        telemetry,
    );
    let aliased = local(&engine, "alias.test", RecordType::HTTPS, Transport::Tcp);
    assert_eq!(aliased.answers.len(), 2);
    assert_eq!(aliased.answers[1].name.to_ascii(), "origin.test.");
    assert!(
        matches!(&aliased.answers[1].data, RData::HTTPS(value) if value.target_name.is_root() && value.svc_params.is_empty())
    );
    let _ = events.recv().await.unwrap();
    for (generation, change) in [
        (2, "identical"),
        (3, "ttl"),
        (4, "priority"),
        (5, "target"),
        (6, "mode"),
        (7, "port"),
    ] {
        let mut next = config.clone();
        match change {
            "port" => {
                if let LocalData::Https { params, .. } = &mut next.policies[0].dns_records[0].data {
                    params.port = Some(0);
                }
            }
            "ttl" => next.policies[0].dns_records[0].ttl = 17,
            "mode" => {
                next.policies[0].dns_records[0].data = LocalData::Https {
                    priority: 0,
                    target: ".".into(),
                    params: Default::default(),
                }
            }
            "priority" => {
                next.policies[0].dns_records[0].data = LocalData::Https {
                    priority: 2,
                    target: ".".into(),
                    params: Default::default(),
                }
            }
            "target" => {
                next.policies[0].dns_records[0].data = LocalData::Https {
                    priority: 1,
                    target: "endpoint.home.arpa".into(),
                    params: Default::default(),
                }
            }
            _ => {}
        }
        controller
            .prepare(
                PolicySnapshot::compile(next, generation).unwrap(),
                PublicationTarget::Shadow,
                controller.version(),
            )
            .unwrap()
            .commit();
        for transport in [Transport::Udp, Transport::Tcp] {
            for name in ["Child.Service.Test", "a.b.service.test"] {
                for kind in [RecordType::HTTPS, RecordType::SVCB] {
                    let wire = local(&engine, name, kind, transport);
                    assert_eq!(wire.response_code, ResponseCode::NoError);
                    assert_eq!(wire.answers.len(), 1);
                    assert_eq!(wire.answers[0].name.to_ascii(), format!("{name}."));
                    assert_eq!(wire.answers[0].ttl, 31);
                    let binding = match &wire.answers[0].data {
                        RData::HTTPS(value) => &value.0,
                        RData::SVCB(value) => value,
                        other => panic!("unexpected {other:?}"),
                    };
                    assert!(binding.svc_params.is_empty());
                    assert_eq!(
                        binding.svc_priority,
                        if kind == RecordType::HTTPS { 1 } else { 65535 }
                    );
                    if kind == RecordType::HTTPS {
                        assert!(binding.target_name.is_root());
                    } else {
                        assert_eq!(binding.target_name.to_ascii(), "endpoint.home.arpa.");
                    }
                    assert_eq!(
                        events.recv().await.unwrap().shadow.unwrap().differs,
                        kind == RecordType::HTTPS && change != "identical"
                    );
                }
                for kind in [
                    RecordType::A,
                    RecordType::AAAA,
                    RecordType::CNAME,
                    RecordType::TXT,
                ] {
                    assert!(local(&engine, name, kind, transport).answers.is_empty());
                    let _ = events.recv().await.unwrap();
                }
            }
        }
    }
    let mut next = config.clone();
    next.policies[0].dns_records = (1..=32)
        .map(|priority| LocalRecord {
            domain: "*.service.test".into(),
            ttl: 31,
            data: LocalData::Https {
                priority,
                target: "very-long-service-name.home.arpa".into(),
                params: Default::default(),
            },
        })
        .collect();
    controller
        .prepare(
            PolicySnapshot::compile(next, 8).unwrap(),
            PublicationTarget::Active,
            controller.version(),
        )
        .unwrap()
        .commit();
    let udp = local(
        &engine,
        "deep.service.test",
        RecordType::HTTPS,
        Transport::Udp,
    );
    assert!(udp.metadata.truncation);
    assert!(udp.to_vec().unwrap().len() <= 1232);
    let tcp = local(
        &engine,
        "deep.service.test",
        RecordType::HTTPS,
        Transport::Tcp,
    );
    assert!(!tcp.metadata.truncation);
    assert_eq!(tcp.answers.len(), 32);
    for wire in [udp, tcp] {
        assert!(
            wire.answers
                .iter()
                .all(|record| record.name.to_ascii() == "deep.service.test.")
        );
    }
}

#[test]
fn alias_mode_wire_is_returned_without_chasing_or_changing_other_types() {
    let mut config = PolicyConfigSet::default();
    config.upstreams[0].addresses = vec!["127.0.0.1:9".parse().unwrap()];
    for domain in ["alias.test", "*.alias.test"] {
        for data in [
            LocalData::Https {
                priority: 0,
                target: "ENDPOINT.home.arpa".into(),
                params: Default::default(),
            },
            LocalData::Svcb {
                priority: 0,
                target: ".".into(),
                params: Default::default(),
            },
            LocalData::A {
                address: "192.0.2.1".parse().unwrap(),
            },
        ] {
            config.policies[0].dns_records.push(LocalRecord {
                domain: domain.into(),
                ttl: 0,
                data,
            });
        }
    }
    config.policies[0].dns_records.push(LocalRecord {
        domain: "cname.test".into(),
        ttl: 31,
        data: LocalData::Cname {
            target: "alias.test".into(),
        },
    });
    let (telemetry, _) = Telemetry::channel(1);
    let engine = Engine::with_config(
        PolicySnapshot::compile(config, 1).unwrap(),
        EngineConfig::default(),
        telemetry,
    );
    for transport in [Transport::Udp, Transport::Tcp] {
        for name in [
            "Alias.Test",
            "Child.Alias.Test",
            "a.b.alias.test",
            "cname.test",
        ] {
            for kind in [RecordType::HTTPS, RecordType::SVCB] {
                let reply = local(&engine, name, kind, transport);
                assert_eq!(reply.response_code, ResponseCode::NoError);
                assert!(reply.additionals.is_empty());
                let terminal = reply.answers.last().unwrap();
                assert_eq!(
                    reply.answers.len(),
                    if name == "cname.test" { 2 } else { 1 }
                );
                assert_eq!(
                    terminal.name.to_ascii(),
                    if name == "cname.test" || name == "Alias.Test" {
                        "alias.test.".into()
                    } else {
                        format!("{name}.")
                    }
                );
                assert_eq!(terminal.ttl, 0);
                let value = match &terminal.data {
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
            }
            let a = local(&engine, name, RecordType::A, transport);
            assert!(
                matches!(&a.answers.last().unwrap().data,RData::A(value) if value.0.to_string()=="192.0.2.1")
            );
            let txt = local(&engine, name, RecordType::TXT, transport);
            assert_eq!(txt.response_code, ResponseCode::NoError);
            assert_eq!(txt.answers.len(), usize::from(name == "cname.test"));
        }
    }
}

#[test]
fn service_ports_encode_exactly_once_with_concrete_owners_and_no_endpoint_io() {
    use hickory_proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
    for port in [0, 1, 65535] {
        let mut config = PolicyConfigSet::default();
        config.upstreams[0].addresses = vec!["127.0.0.1:9".parse().unwrap()];
        for owner in ["origin.test", "*.port.test"] {
            for data in [
                LocalData::Https {
                    priority: 1,
                    target: ".".into(),
                    params: rustwalld_dns_policy::ServiceParams { port: Some(port) },
                },
                LocalData::Svcb {
                    priority: 65535,
                    target: "endpoint.test".into(),
                    params: rustwalld_dns_policy::ServiceParams { port: Some(port) },
                },
            ] {
                config.policies[0].dns_records.push(LocalRecord {
                    domain: owner.into(),
                    ttl: 0,
                    data,
                });
            }
        }
        config.policies[0].dns_records.push(LocalRecord {
            domain: "alias.test".into(),
            ttl: 31,
            data: LocalData::Cname {
                target: "origin.test".into(),
            },
        });
        let (telemetry, _) = Telemetry::channel(1);
        let engine = Engine::with_config(
            PolicySnapshot::compile(config, 1).unwrap(),
            EngineConfig::default(),
            telemetry,
        );
        for transport in [Transport::Udp, Transport::Tcp] {
            for name in [
                "origin.test",
                "alias.test",
                "Child.Port.Test",
                "a.b.port.test",
            ] {
                for kind in [RecordType::HTTPS, RecordType::SVCB] {
                    let reply = local(&engine, name, kind, transport);
                    assert_eq!(reply.response_code, ResponseCode::NoError);
                    assert!(reply.additionals.is_empty());
                    assert_eq!(
                        reply.answers.len(),
                        if name == "alias.test" { 2 } else { 1 }
                    );
                    let record = reply.answers.last().unwrap();
                    assert_eq!(
                        record.name.to_ascii(),
                        if name == "alias.test" {
                            "origin.test.".into()
                        } else {
                            format!("{name}.")
                        }
                    );
                    assert_eq!(record.ttl, 0);
                    let binding = match &record.data {
                        RData::HTTPS(v) => &v.0,
                        RData::SVCB(v) => v,
                        other => panic!("{other:?}"),
                    };
                    assert_eq!(
                        binding.svc_params,
                        vec![(SvcParamKey::Port, SvcParamValue::Port(port))]
                    );
                    assert_eq!(
                        binding.svc_priority,
                        if kind == RecordType::HTTPS { 1 } else { 65535 }
                    );
                    assert_eq!(
                        binding.target_name.to_ascii(),
                        if kind == RecordType::HTTPS {
                            "."
                        } else {
                            "endpoint.test."
                        }
                    );
                }
                let nodata = local(&engine, name, RecordType::A, transport);
                assert_eq!(nodata.response_code, ResponseCode::NoError);
                assert_eq!(nodata.answers.len(), usize::from(name == "alias.test"));
            }
        }
    }
}
