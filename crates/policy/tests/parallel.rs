#![cfg(feature = "parallel")]
#![allow(clippy::unwrap_used)]
use rustwalld_dns_filter::{Action, ListInput, ParallelCompiler};
use rustwalld_dns_policy::{Assertion, PolicyConfigSet, PolicySnapshot, Rewrite};
use std::fmt::Write;
fn config() -> PolicyConfigSet {
    let mut config = PolicyConfigSet::default();
    config.upstreams[0].addresses = vec!["127.0.0.1:9".parse().unwrap()];
    let mut rules = String::from("example\n@@=safe.example\nbücher.test\n");
    for i in 0..40000 {
        writeln!(rules, "=rule{i}.test").unwrap();
    }
    config.policies[0].lists.push(ListInput {
        name: "rules".into(),
        action: Action::Block,
        rules,
    });
    config.policies[0].rewrites.push(Rewrite {
        domain: "nas.test".into(),
        addresses: vec!["192.0.2.1".parse().unwrap()],
        ttl: 60,
    });
    config.assertions = [
        ("rule123.test", Action::Block),
        ("safe.example", Action::Allow),
        ("nas.test", Action::Allow),
        ("bücher.test", Action::Block),
    ]
    .into_iter()
    .map(|(domain, expected)| Assertion {
        client: "127.0.0.1".parse().unwrap(),
        domain: domain.into(),
        expected,
    })
    .collect();
    let mut second = config.policies[0].clone();
    second.name = "second".into();
    second.lists.push(ListInput {
        name: "allowed".into(),
        action: Action::Allow,
        rules: "test".into(),
    });
    config.policies.push(second);
    config.bindings.push(rustwalld_dns_policy::Binding {
        name: "second-client".into(),
        network: "127.0.0.2/32".parse().unwrap(),
        policy: "second".into(),
        metadata: None,
    });
    config
}
#[test]
fn complete_policy_checks_and_provenance_match_and_assertions_gate_both_paths() {
    for workers in [2, 4] {
        let compiler = ParallelCompiler::new(workers).unwrap();
        let config = config();
        let serial = PolicySnapshot::compile(config.clone(), 7).unwrap();
        let parallel = PolicySnapshot::compile_parallel(config.clone(), 7, &compiler).unwrap();
        assert_eq!(parallel.generation(), 7);
        assert_eq!(
            serde_json::to_value(serial.config()).unwrap(),
            serde_json::to_value(parallel.config()).unwrap()
        );
        let client = "127.0.0.1".parse().unwrap();
        for client in [client, "127.0.0.2".parse().unwrap()] {
            for domain in [
                "rule123.test",
                "safe.example",
                "nas.test",
                "xn--bcher-kva.test",
                "x.example",
                "allowed.test",
            ] {
                assert_eq!(
                    serde_json::to_value(serial.explain(client, domain).unwrap()).unwrap(),
                    serde_json::to_value(parallel.explain(client, domain).unwrap()).unwrap()
                );
            }
        }
        for failed in [false, true] {
            let mut config = config.clone();
            if failed {
                config.assertions[0].expected = Action::Allow;
            }
            assert_eq!(
                serde_json::to_value(PolicySnapshot::check(config.clone()).unwrap()).unwrap(),
                serde_json::to_value(
                    PolicySnapshot::check_parallel(config.clone(), &compiler).unwrap()
                )
                .unwrap()
            );
            let serial = PolicySnapshot::compile(config.clone(), 8);
            let parallel = PolicySnapshot::compile_parallel(config, 8, &compiler);
            assert_eq!(serial.is_err(), failed);
            assert_eq!(parallel.is_err(), failed);
            if failed {
                assert_eq!(
                    serial.err().unwrap().to_string(),
                    parallel.err().unwrap().to_string()
                );
            }
        }
        let mut invalid = config.clone();
        invalid.policies[0].lists[0]
            .rules
            .push_str("bad$modifier\n");
        assert_eq!(
            PolicySnapshot::compile(invalid.clone(), 9)
                .err()
                .unwrap()
                .to_string(),
            PolicySnapshot::compile_parallel(invalid, 9, &compiler)
                .err()
                .unwrap()
                .to_string()
        );
        assert!(PolicySnapshot::compile_parallel(config.clone(), 0, &compiler).is_err());
        // A failed compilation leaves the reusable pool available for the next generation.
        assert!(PolicySnapshot::compile_parallel(config, 10, &compiler).is_ok());
    }
}
#[test]
fn shared_owned_pool_supports_independently_admitted_callers() {
    let compiler = ParallelCompiler::new(2).unwrap();
    std::thread::scope(|scope| {
        let a = scope.spawn(|| PolicySnapshot::compile_parallel(config(), 1, &compiler).unwrap());
        let b = scope.spawn(|| PolicySnapshot::compile_parallel(config(), 2, &compiler).unwrap());
        assert_eq!(a.join().unwrap().generation(), 1);
        assert_eq!(b.join().unwrap().generation(), 2);
    });
}
