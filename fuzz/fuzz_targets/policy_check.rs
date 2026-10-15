#![no_main]
use rustwalld_dns_filter::{Action, ListInput};
use libfuzzer_sys::fuzz_target;
use rustwalld_dns_policy::{
    Assertion, Binding, BindingMetadata, PolicyConfigSet, PolicySnapshot, Rewrite,
    TemporaryException,
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{SystemTime, UNIX_EPOCH},
};

fuzz_target!(|input: &str| {
    if input.len() > 4096 {
        return;
    }
    let local = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut config = PolicyConfigSet::default();
    config.upstreams[0].addresses = vec![SocketAddr::new(local, 9)];
    config.policies[0].lists = vec![
        ListInput { syntax: Default::default(),
            name: "deny".into(),
            action: Action::Block,
            rules: "ads.test\nnas.test\n=bücher.test\n".repeat(20),
        },
        ListInput { syntax: Default::default(),
            name: "allow".into(),
            action: Action::Allow,
            rules: "=safe.ads.test".into(),
        },
    ];
    config.policies[0].rewrites = vec![Rewrite {
        domain: "nas.test".into(),
        addresses: vec![local],
        ttl: 60,
    }];
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mode = input.as_bytes().first().copied().unwrap_or(0) % 6;
    let mut annotations = input.lines();
    config.bindings = vec![Binding {
        name: "fuzz-client".into(),
        network: "127.0.0.1/32".parse().unwrap(),
        policy: "default".into(),
        metadata: if input.len() % 3 == 0 {
            None
        } else {
            Some(BindingMetadata {
                group: annotations.next().map(str::to_owned),
                owner: annotations.next().map(str::to_owned),
                vlan: match input.as_bytes().first().copied().unwrap_or(0) % 4 {
                    0 => None,
                    1 => Some(1),
                    2 => Some(4095),
                    _ => Some(4094),
                },
                note: annotations.next().map(str::to_owned),
                tags: annotations.take(17).map(str::to_owned).collect(),
            })
        },
    }];
    config.policies[0].temporary_exceptions = vec![TemporaryException {
        clients: vec![], include_subdomains: false,
        name: "repair".into(),
        domain: if mode == 5 {
            input.split('\n').next().unwrap_or("").into()
        } else {
            "ADS.TEST.".into()
        },
        expires_at: match mode {
            0 | 5 => now + 60,
            1 => 1,
            2 => 0,
            3 => u64::MAX,
            _ => now + 8 * 86400,
        },
    }];
    config.assertions = input
        .split('\n')
        .take(16)
        .enumerate()
        .map(|(index, domain)| Assertion {
            client: if index % 3 == 2 {
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
            } else {
                local
            },
            domain: domain.into(),
            expected: if domain.len() % 2 == 0 {
                Action::Allow
            } else {
                Action::Block
            },
        })
        .collect();
    let report = match PolicySnapshot::check(config.clone()) {
        Ok(report) => report,
        Err(_) => {
            assert!(PolicySnapshot::compile(config, 1).is_err());
            return;
        }
    };
    assert_eq!(report.basis, "permanent_policy");
    assert_eq!(report.assertions, config.assertions.len());
    assert_eq!(
        report.failed,
        report
            .results
            .iter()
            .filter(|result| result.failure.is_some())
            .count()
    );
    assert_eq!(report.valid, PolicySnapshot::compile(config, 1).is_ok());
    for result in report.results {
        if let Some(trace) = result.trace {
            if let Some(rule) = trace.rule {
                assert!(rule.sources.len() <= 16);
                assert!(rule.total_sources >= rule.sources.len());
            }
        }
    }
});
