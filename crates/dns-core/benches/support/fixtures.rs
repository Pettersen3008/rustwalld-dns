#![allow(clippy::unwrap_used)]
use dns_core::{Engine, reply, telemetry::Telemetry};
use filtering::{Action, ListInput};
use hickory_proto::{
    op::{Edns, Message, Query, ResponseCode},
    rr::{Name, RData, Record, RecordType, rdata::A},
};
use policy::{PolicyConfigSet, PolicySnapshot};
use resolver::response_cache::CacheKey;
use std::time::Instant;
pub fn setup(exception_domain: Option<&str>) -> (Engine, Vec<u8>, Vec<u8>) {
    let mut config = PolicyConfigSet {
        bindings: [
            ("127.0.0.0/8", "Loopback network"),
            ("127.0.0.1/32", "Work laptop"),
            ("2001:db8::/32", "IPv6 network"),
            ("2001:db8::1/128", "IPv6 laptop"),
        ]
        .into_iter()
        .map(|(network, name)| policy::Binding {
            network: network.parse().unwrap(),
            name: name.into(),
            policy: "default".into(),
            metadata: Some(policy::BindingMetadata {
                group: Some("g".repeat(128)),
                owner: Some("o".repeat(128)),
                vlan: Some(4094),
                tags: (0..16).map(|index| format!("{index:032}")).collect(),
                note: Some("n".repeat(1024)),
            }),
        })
        .collect(),
        ..Default::default()
    };
    config.policies[0].lists.push(ListInput {
        name: "bench".into(),
        action: Action::Block,
        rules: "blocked.test".into(),
    });
    // These warmed fixtures must never contact public DNS, even if a cache
    // regression makes an unexpected miss. Zero lookups are asserted below.
    config.upstreams[0].addresses = vec!["127.0.0.1:9".parse().unwrap()];
    config.upstreams[0].timeout_ms = 50;
    if let Some(domain) = exception_domain {
        config.policies[0]
            .temporary_exceptions
            .push(policy::TemporaryException {
                name: "bench-exception".into(),
                domain: domain.into(),
                expires_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + 3600,
            });
        if domain == "cached.test" {
            config.policies[0].lists[0].rules.push_str("\ncached.test");
        }
    }
    let (telemetry, _receiver) = Telemetry::channel(1);
    let engine = Engine::new(
        PolicySnapshot::compile(config, 1).unwrap(),
        1000,
        1000,
        32,
        telemetry,
    );
    let mut request = Message::query();
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(
        Name::from_ascii("cached.test.").unwrap(),
        RecordType::A,
    ));
    let mut response = reply(&request, ResponseCode::NoError);
    response.add_answer(Record::from_rdata(
        request.queries[0].name().clone(),
        3600,
        RData::A(A("192.0.2.1".parse().unwrap())),
    ));
    engine.resolver.cache.insert(
        CacheKey::new(&request, 0, 1).unwrap(),
        response,
        Instant::now(),
    );
    let cached = request.to_vec().unwrap();
    request.queries[0].set_name(Name::from_ascii("blocked.test.").unwrap());
    (engine, request.to_vec().unwrap(), cached)
}
pub fn dnssec_cache(long_name: bool) -> (Engine, Vec<u8>) {
    let (engine, _, cached) = setup(None);
    let mut request = Message::from_vec(&cached).unwrap();
    if long_name {
        request.queries[0].set_name(
            Name::from_labels([
                vec![b'A'; 63],
                vec![b'B'; 63],
                vec![b'C'; 63],
                vec![b'D'; 61],
            ])
            .unwrap(),
        );
    }
    request.metadata.checking_disabled = true;
    let mut edns = Edns::new();
    edns.set_max_payload(4096);
    edns.set_dnssec_ok(true);
    request.edns = Some(edns);
    let key = CacheKey::new(&request, 0, 1).unwrap();
    let mut response = reply(&request, ResponseCode::NoError);
    // Match canonical upstream owner casing while preserving the client's
    // original question on encoding, including long names that allocate.
    response.queries[0] = key.query.clone();
    response.add_answer(Record::from_rdata(
        key.query.name().clone(),
        3600,
        RData::A(A("192.0.2.1".parse().unwrap())),
    ));
    assert!(engine.resolver.cache.insert(key, response, Instant::now()));
    (engine, request.to_vec().unwrap())
}
pub fn rewrite() -> (Engine, Vec<u8>) {
    let (engine, blocked, _) = setup(None);
    let mut config = engine.active.load().config.clone();
    config.policies[0].rewrites.push(policy::Rewrite {
        domain: "blocked.test".into(),
        addresses: vec!["192.0.2.2".parse().unwrap()],
        ttl: 60,
    });
    engine.active.store(std::sync::Arc::new(
        PolicySnapshot::compile(config, 2).unwrap(),
    ));
    (engine, blocked)
}
