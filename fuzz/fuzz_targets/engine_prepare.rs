#![no_main]
//! The synchronous query path: parsing, validation, policy, local answers and
//! reply encoding. Cache misses are returned for forwarding, never sent.
use hickory_proto::op::{Message, MessageType};
use libfuzzer_sys::fuzz_target;
use rustwalld_dns_core::{
    Engine, EngineConfig, ListInput, PolicyConfigSet, PolicySnapshot, Prepared, Rewrite,
    Telemetry, Transport,
};
use rustwalld_dns_filter::Action;
use std::sync::OnceLock;

static ENGINE: OnceLock<Engine> = OnceLock::new();

fn engine() -> &'static Engine {
    ENGINE.get_or_init(|| {
        let mut config = PolicyConfigSet::default();
        // Never contacted: prepare() does no network I/O.
        config.upstreams[0].addresses = vec!["127.0.0.1:9".parse().unwrap()];
        config.policies[0].lists = vec![
            ListInput {
                name: "deny".into(),
                action: Action::Block,
                rules: "blocked.test\n=exact.test\nads.example".into(),
            },
            ListInput {
                name: "allow".into(),
                action: Action::Allow,
                rules: "@@ok.blocked.test".into(),
            },
        ];
        config.policies[0].rewrites = vec![Rewrite {
            domain: "local.test".into(),
            addresses: vec!["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
            ttl: 60,
        }];
        let (telemetry, _events) = Telemetry::channel(1);
        Engine::with_config(
            PolicySnapshot::compile(config, 1).unwrap(),
            EngineConfig::default(),
            telemetry,
        )
    })
}

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 4096 {
        return;
    }
    for transport in [Transport::Udp, Transport::Tcp] {
        let Prepared::Reply(reply) = engine().prepare(bytes, "127.0.0.1".parse().unwrap(), transport)
        else {
            continue;
        };
        // Only parsed queries are answered, and every reply is well formed.
        let request = Message::from_vec(bytes).expect("reply to an unparseable request");
        let response = Message::from_vec(&reply).expect("engine reply does not parse");
        assert_eq!(response.metadata.id, request.metadata.id);
        assert_eq!(response.metadata.message_type, MessageType::Response);
        assert!(response.queries.len() <= 1);
        if transport == Transport::Udp {
            assert!(reply.len() <= 1232);
        }
    }
});
