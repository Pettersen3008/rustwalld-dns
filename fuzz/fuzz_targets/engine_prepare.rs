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
        config.upstreams.push(rustwalld_dns_policy::UpstreamProfile{name:"child".into(),addresses:vec!["127.0.0.1:10".parse().unwrap()],timeout_ms:100,transport:Default::default()});
        config.policies[0].ds_routing=rustwalld_dns_policy::DsRouting::Parent;
        config.policies[0].routes=vec![rustwalld_dns_policy::DomainRoute{domain:"child.test".into(),upstream:"child".into()},rustwalld_dns_policy::DomainRoute{domain:"test".into(),upstream:"default".into()}];
        config.policies[0].safe_search=Some(rustwalld_dns_policy::SafeSearchConfig{google:true,bing:true,duckduckgo:true,youtube:rustwalld_dns_policy::YouTubeMode::Strict,..Default::default()});
        config.policies[0].blocked_services=Some(rustwalld_dns_policy::BlockedServices{catalog_version:1,ids:vec!["youtube".into(),"tiktok".into(),"reddit".into(),"discord".into()], schedule: None });
        config.policies[0].lists = vec![
            ListInput { syntax: Default::default(),
                name: "deny".into(),
                action: Action::Block,
                rules: "blocked.test\n=exact.test\nads.example".into(),
            },
            ListInput { syntax: Default::default(),
                name: "allow".into(),
                action: Action::Allow,
                rules: "@@ok.blocked.test".into(),
            },
        ];
        config.policies[0].lists.push(ListInput { syntax: rustwalld_dns_filter::RuleSyntax::AdguardV6, name:"typed".into(),action:Action::Block,rules:"||typed.test^$dnstype=AAAA,denyallow=safe.typed.test,client=127.0.0.1,ctag=user_child\n/^192\\.0\\.2\\.1$/$dnstype=A".into() });
        config.bindings.push(rustwalld_dns_policy::Binding{name:"Tagged".into(),network:"127.0.0.1/32".parse().unwrap(),policy:"default".into(),filter_tags:vec!["user_child".into()],metadata:None});
        config.policies[0].rewrites = vec![Rewrite {
            domain: "local.test".into(),
            addresses: vec!["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
            ttl: 60,
        }];
        config.policies[0].dns_records = vec![
            rustwalld_dns_policy::LocalRecord { domain: "local.test".into(), ttl: 60, data: rustwalld_dns_policy::LocalData::Passthrough { family: rustwalld_dns_policy::AddressFamily::Aaaa } },
            rustwalld_dns_policy::LocalRecord { domain: "passthrough.test".into(), ttl: 60, data: rustwalld_dns_policy::LocalData::Passthrough { family: rustwalld_dns_policy::AddressFamily::A } },
            rustwalld_dns_policy::LocalRecord { domain: "alias-pass.test".into(), ttl: 60, data: rustwalld_dns_policy::LocalData::Cname { target: "passthrough.test".into() } },
        ];
        for (domain, address) in [("*.wild.test", "192.0.2.10"), ("*.deep.wild.test", "192.0.2.20")] {
            config.policies[0].dns_records.push(rustwalld_dns_policy::LocalRecord { domain: domain.into(), ttl: 60, data: rustwalld_dns_policy::LocalData::A { address: address.parse().unwrap() } });
        }
        for data in [
            rustwalld_dns_policy::LocalData::Txt { text: "x".repeat(255) },
            rustwalld_dns_policy::LocalData::Ptr { target: "nas.home.arpa".into() },
            rustwalld_dns_policy::LocalData::Mx { preference: 10, exchange: "mail.home.arpa".into() },
            rustwalld_dns_policy::LocalData::Srv { priority: 1, weight: 2, port: 8443, target: ".".into() },
        ] {
            config.policies[0].dns_records.push(rustwalld_dns_policy::LocalRecord { domain: "*.typed.wild.test".into(), ttl: 31, data });
        }
        for data in [
            rustwalld_dns_policy::LocalData::Https { priority: 1, target: ".".into(), params: Default::default(),
},
            rustwalld_dns_policy::LocalData::Svcb { priority: 65535, target: "endpoint.home.arpa".into(), params: Default::default(),
},
        ] {
            config.policies[0].dns_records.push(rustwalld_dns_policy::LocalRecord { domain: "*.binding.test".into(), ttl: 31, data });
        }
        for data in [
            rustwalld_dns_policy::LocalData::Https { priority: 0, target: "endpoint.home.arpa".into(), params: Default::default(),
},
            rustwalld_dns_policy::LocalData::Svcb { priority: 0, target: ".".into(), params: Default::default(),
},
        ] {
            config.policies[0].dns_records.push(rustwalld_dns_policy::LocalRecord { domain: "*.alias-binding.test".into(), ttl: 0, data });
        }
        for data in [
            rustwalld_dns_policy::LocalData::Https { priority: 1, target: ".".into(), params: rustwalld_dns_policy::ServiceParams { port: Some(0) } },
            rustwalld_dns_policy::LocalData::Svcb { priority: 65535, target: "endpoint.home.arpa".into(), params: rustwalld_dns_policy::ServiceParams { port: Some(65535) } },
        ] { config.policies[0].dns_records.push(rustwalld_dns_policy::LocalRecord { domain: "*.port.test".into(), ttl: 0, data }); }
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
