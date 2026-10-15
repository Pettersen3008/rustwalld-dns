#![allow(clippy::unwrap_used)]
use hickory_proto::rr::{Name, RecordType};
use rustwalld_dns_policy::{
    DomainRoute, DsRouting, PolicyConfigSet, PolicySnapshot, UpstreamProfile,
};

fn configuration() -> PolicyConfigSet {
    let mut config = PolicyConfigSet::default();
    for (index, domain) in ["test", "child.test", "sub.child.test", "sibling.test"]
        .into_iter()
        .enumerate()
    {
        let name = format!("route-{index}");
        config.upstreams.push(UpstreamProfile {
            name: name.clone(),
            addresses: vec![format!("127.0.0.1:{}", 15000 + index).parse().unwrap()],
            timeout_ms: 100,
            transport: Default::default(),
        });
        config.policies[0].routes.push(DomainRoute {
            domain: domain.into(),
            upstream: name,
        });
    }
    config
}
#[test]
fn parent_ds_selection_matches_hickory_parent_without_changing_other_types() {
    let mut config = configuration();
    let native = PolicySnapshot::compile(config.clone(), 1).unwrap();
    config.policies[0].ds_routing = DsRouting::Parent;
    let parent = PolicySnapshot::compile(config, 2).unwrap();
    let native = &native.policies()[0];
    let parent = &parent.policies()[0];
    for domain in [
        ".",
        "test.",
        "child.test.",
        "sub.child.test.",
        "deep.sub.child.test.",
        "sibling.test.",
        "child.other.",
        "badchild.test.",
        "CHILD.TEST.",
        "a\\.b.child.test.",
        "*.child.test.",
    ] {
        let name = Name::from_ascii(domain).unwrap();
        assert_eq!(
            parent.upstream_for_query(&name, RecordType::DS),
            native.upstream_for(&name.base_name()),
            "{domain}"
        );
        assert_eq!(parent.upstream_for(&name), native.upstream_for(&name));
        for kind in [
            RecordType::A,
            RecordType::AAAA,
            RecordType::NS,
            RecordType::SOA,
            RecordType::DNSKEY,
            RecordType::CNAME,
            RecordType::Unknown(65400),
        ] {
            assert_eq!(
                parent.upstream_for_query(&name, kind),
                native.upstream_for(&name),
                "{domain} {kind}"
            );
        }
        assert_eq!(
            native.upstream_for_query(&name, RecordType::DS),
            native.upstream_for(&name)
        );
    }
}
#[test]
fn routing_defaults_roundtrip_and_typed_explanations_preserve_alias_and_policy_scope() {
    let mut config = configuration();
    let old = serde_json::to_value(&config).unwrap();
    assert!(old["policies"][0].get("ds_routing").is_none());
    assert_eq!(
        serde_json::from_value::<PolicyConfigSet>(old)
            .unwrap()
            .policies[0]
            .ds_routing,
        DsRouting::Question
    );
    config.policies[0].ds_routing = DsRouting::Parent;
    config.policies[0]
        .dns_records
        .push(rustwalld_dns_policy::LocalRecord {
            domain: "alias.test".into(),
            ttl: 60,
            data: rustwalld_dns_policy::LocalData::Cname {
                target: "child.test".into(),
            },
        });
    let mut other = config.policies[0].clone();
    other.name = "native".into();
    other.ds_routing = DsRouting::Question;
    config.policies.push(other);
    config.bindings.push(rustwalld_dns_policy::Binding {
        name: "Native".into(),
        network: "127.0.0.2/32".parse().unwrap(),
        policy: "native".into(),
        filter_tags: Vec::new(),
        metadata: None,
    });
    let wire = serde_json::to_value(&config).unwrap();
    assert_eq!(wire["policies"][0]["ds_routing"], "parent");
    let snapshot = PolicySnapshot::compile(serde_json::from_value(wire).unwrap(), 1).unwrap();
    for domain in ["child.test", "alias.test"] {
        assert_eq!(
            snapshot
                .explain("127.0.0.1".parse().unwrap(), domain)
                .unwrap()
                .upstream,
            "route-1"
        );
        assert_eq!(
            snapshot
                .explain_query("127.0.0.1".parse().unwrap(), domain, RecordType::DS)
                .unwrap()
                .upstream,
            "route-0"
        );
        assert_eq!(
            snapshot
                .explain_query("127.0.0.2".parse().unwrap(), domain, RecordType::DS)
                .unwrap()
                .upstream,
            "route-1"
        );
    }
    let mut invalid = serde_json::to_value(configuration()).unwrap();
    invalid["policies"][0]["ds_routing"] = serde_json::json!("invalid");
    assert!(serde_json::from_value::<PolicyConfigSet>(invalid).is_err());
}
