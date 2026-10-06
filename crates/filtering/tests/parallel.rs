#![cfg(feature = "parallel")]
#![allow(clippy::unwrap_used)]
use rustwalld_dns_filter::{Action, FilterSnapshot, ListInput, ParallelCompiler};
use std::fmt::Write;

fn compare(lists: &[ListInput], max_rules: usize, max_bytes: usize) {
    let expected = FilterSnapshot::compile(lists, max_rules, max_bytes);
    for workers in [1, 2, 4] {
        let compiler = ParallelCompiler::new(workers).unwrap();
        let actual = compiler.compile(lists, max_rules, max_bytes);
        match (&expected, &actual) {
            (Ok(expected), Ok(actual)) => {
                assert_eq!(
                    serde_json::to_value(expected.rules()).unwrap(),
                    serde_json::to_value(actual.rules()).unwrap()
                );
                assert_eq!(
                    serde_json::to_value(&expected.stats).unwrap(),
                    serde_json::to_value(&actual.stats).unwrap()
                );
                assert_eq!(expected.payload_bytes(), actual.payload_bytes());
                assert_eq!(expected.effective_rules(), actual.effective_rules());
                for rule in expected.rules() {
                    assert_eq!(
                        expected.evaluate(&rule.domain),
                        actual.evaluate(&rule.domain)
                    );
                    let child = format!("child.{}", rule.domain);
                    assert_eq!(expected.evaluate(&child), actual.evaluate(&child));
                }
                for domain in [
                    "allowed.invalid",
                    "a\\.b.example",
                    "a\\\\b.example",
                    "",
                    "safe.example",
                ] {
                    assert_eq!(expected.evaluate(domain), actual.evaluate(domain));
                }
            }
            (Err(expected), Err(actual)) => assert_eq!(expected.to_string(), actual.to_string()),
            _ => {
                panic!("sequential and {workers}-worker results differ: {expected:?} / {actual:?}")
            }
        }
    }
}

#[test]
fn ordering_sources_hosts_idna_and_cross_batch_redundancy() {
    let mut rules = "# comment\r\n! header\r\n\nEXAMPLE.\n@@=safe.example\n0.0.0.0 hosts.example second.example\nbücher.example\n0.0.0.0 partial.example bad$domain\n".to_owned();
    for i in 0usize..40000 {
        writeln!(rules, "=child{i}.example").unwrap();
        if i.is_multiple_of(1000) {
            writeln!(rules, "example").unwrap();
        }
    }
    rules.push_str("@@safe.example\n=CHILD0.example.\n# tail\n");
    let lists = [
        ListInput {
            name: "first".into(),
            action: Action::Block,
            rules,
        },
        ListInput {
            name: "second".into(),
            action: Action::Allow,
            rules: "=safe.example\n@@safe.example\n@@EXAMPLE.".into(),
        },
    ];
    compare(&lists, 100000, usize::MAX);
    let expected = FilterSnapshot::compile(&lists, 100000, usize::MAX).unwrap();
    assert_eq!(expected.rule(0).unwrap().domain.as_ref(), "example");
    assert_eq!(expected.rule(0).unwrap().sources[0].line, 4);
    assert_eq!(expected.stats[0].invalid, 1);
    assert!(
        expected
            .rules()
            .iter()
            .all(|rule| rule.domain.as_ref() != "partial.example")
    );
    assert!(
        expected
            .rule(expected.evaluate("child0.example").rule.unwrap())
            .unwrap()
            .action
            == Action::Allow
    );
}

#[test]
fn raw_expanded_byte_and_list_name_limits_keep_legacy_results() {
    for rules in [
        "",
        "! ignored\n# ignored\n",
        "bad$modifier\na.example\n",
        "0.0.0.0 a.example b.example c.example\na.example\n",
        "a.example\nA.EXAMPLE.\n@@a.example\n",
    ] {
        let list = ListInput {
            name: "fixture".into(),
            action: Action::Block,
            rules: rules.into(),
        };
        for max_rules in 0..=6 {
            for max_bytes in [
                0,
                list.rules.len().saturating_sub(1),
                list.rules.len(),
                usize::MAX,
            ] {
                compare(std::slice::from_ref(&list), max_rules, max_bytes);
            }
        }
    }
    let rules = "=fixture.example\n".repeat(10000);
    for max_rules in [0, 1, 8191, 8192, 8193, 9999, 10000, 10001] {
        compare(
            &[ListInput {
                name: "batch".into(),
                action: Action::Block,
                rules: rules.clone(),
            }],
            max_rules,
            usize::MAX,
        );
    }
    for names in [["", "other"], ["duplicate", "duplicate"]] {
        let lists = names.map(|name| ListInput {
            name: name.into(),
            action: Action::Block,
            rules: "example".into(),
        });
        compare(&lists, 0, usize::MAX);
        compare(&lists, 100, usize::MAX);
    }
}

#[test]
fn oversized_hosts_line_and_worker_bounds() {
    assert!(ParallelCompiler::new(0).is_err());
    assert!(ParallelCompiler::new(5).is_err());
    let mut rules = "0.0.0.0".to_owned();
    for i in 0..60000 {
        write!(rules, " long-host-{i}.example").unwrap();
    }
    let list = ListInput {
        name: "oversized".into(),
        action: Action::Block,
        rules,
    };
    compare(std::slice::from_ref(&list), 0, usize::MAX);
    compare(std::slice::from_ref(&list), 10, usize::MAX);
    compare(&[list], 100000, usize::MAX);
}
