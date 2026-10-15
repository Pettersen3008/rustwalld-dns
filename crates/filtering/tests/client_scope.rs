#![allow(clippy::unwrap_used)]
use rustwalld_dns_filter::{
    Action, ClientContext, CompileError, FilterSnapshot, ListInput, RuleSyntax,
};
fn compile(rules: &str) -> FilterSnapshot {
    FilterSnapshot::compile(
        &[ListInput {
            name: "v5".into(),
            syntax: RuleSyntax::AdguardV5,
            action: Action::Block,
            rules: rules.into(),
        }],
        1000,
        1024 * 1024,
    )
    .unwrap()
}
fn client<'a>(ip: &str, name: Option<&'a str>) -> ClientContext<'a> {
    ClientContext {
        ip: ip.parse().unwrap(),
        name,
    }
}
#[test]
fn network_name_negative_and_response_types_are_scoped_to_actual_clients() {
    let filters = compile(
        "||test^$client=192.0.2.1|2001:db8::/32|Kids|~192.0.2.9,dnstype=AAAA,denyallow=safe.test\n@@||allow.test^$client=Kids\n/^192\\.0\\.2\\.10$/$client=Kids,dnstype=A",
    );
    for (ip, name, expected) in [
        ("192.0.2.1", None, Action::Block),
        ("192.0.2.2", Some("Kids"), Action::Block),
        ("192.0.2.2", Some("kids"), Action::Allow),
        ("192.0.2.9", Some("Kids"), Action::Allow),
        ("2001:db8::1", None, Action::Block),
        ("2001:db9::1", None, Action::Allow),
        ("::ffff:192.0.2.1", None, Action::Block),
    ] {
        let ctx = client(ip, name);
        assert_eq!(
            filters.evaluate_client("track.test", 28, ctx).action,
            expected
        );
        assert_eq!(
            filters.evaluate_client("track.test", 1, ctx).action,
            Action::Allow
        );
        assert_eq!(
            filters.evaluate_client("safe.test", 28, ctx).action,
            Action::Allow
        );
    }
    assert_eq!(
        filters
            .evaluate_client("allow.test", 28, client("192.0.2.2", Some("Kids")))
            .action,
        Action::Allow
    );
    assert_eq!(
        filters
            .evaluate_value_client("192.0.2.10", 1, client("192.0.2.2", Some("Kids")))
            .action,
        Action::Block
    );
    assert_eq!(
        filters
            .evaluate_value_client("192.0.2.10", 1, client("192.0.2.2", Some("Other")))
            .action,
        Action::Allow
    );
    assert_eq!(
        filters.evaluate_type("track.test", 28).action,
        Action::Allow
    );
    assert_eq!(
        compile("||test^$client=~192.0.2.1")
            .evaluate_type("track.test", 1)
            .action,
        Action::Allow
    );
}
#[test]
fn quotes_escaped_separators_dollars_and_canonical_identity_preserve_source_names() {
    let filters = compile(
        r#"||test^$client='Frank\'s laptop'|~"Mary\, Jane"|"pipe\|value"|dollar\$value|192.0.2.129/24
||test^$client=192.0.2.0/24|dollar\$value|"pipe\|value"|~"Mary\, Jane"|'Frank\'s laptop'"#,
    );
    assert_eq!(filters.rules().len(), 1);
    for name in ["Frank's laptop", "pipe|value", "dollar$value"] {
        assert_eq!(
            filters
                .evaluate_client("track.test", 1, client("198.51.100.1", Some(name)))
                .action,
            Action::Block
        );
    }
    assert_eq!(
        filters
            .evaluate_client("track.test", 1, client("192.0.2.1", Some("Mary, Jane")))
            .action,
        Action::Allow
    );
    let json = serde_json::to_value(filters.rules()).unwrap();
    assert!(
        json[0]["client"]["include"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("192.0.2.0/24"))
    );
    for syntax in [
        RuleSyntax::Native,
        RuleSyntax::Adguard,
        RuleSyntax::AdguardV2,
        RuleSyntax::AdguardV3,
        RuleSyntax::AdguardV4,
    ] {
        let old = FilterSnapshot::compile(
            &[ListInput {
                name: "old".into(),
                syntax,
                action: Action::Block,
                rules: "||test^$client=192.0.2.1".into(),
            }],
            10,
            10000,
        )
        .unwrap();
        assert_eq!(old.stats[0].invalid, 1);
    }
}
#[test]
fn malformed_duplicate_modifiers_and_independent_budgets_are_publication_blockers() {
    for value in [
        "",
        "~",
        "a||b",
        "a|",
        "a,client=b",
        "a,badfilter",
        "a,important",
        "a,unknown=b",
        "'\u{202e}hidden'",
        "' '",
    ] {
        assert_eq!(
            compile(&format!("||test^$client={value}")).stats[0].invalid,
            1,
            "{value}"
        );
    }
    assert_eq!(
        compile(&format!(
            "||test^$client={}",
            vec!["192.0.2.1"; 65].join("|")
        ))
        .stats[0]
            .invalid,
        1
    );
    let rules = (0..513)
        .map(|n| format!("||n{n}.test^$client=192.0.2.1\n"))
        .collect::<String>();
    assert!(matches!(
        FilterSnapshot::compile(
            &[ListInput {
                name: "v5".into(),
                syntax: RuleSyntax::AdguardV5,
                action: Action::Block,
                rules
            }],
            20000,
            4 * 1024 * 1024
        ),
        Err(CompileError::Limit)
    ));
    let rules = (0..512)
        .map(|n| {
            format!(
                "||n{n}.test^$client={}\n",
                (0..17)
                    .map(|i| format!("name{n}-{i}"))
                    .collect::<Vec<_>>()
                    .join("|")
            )
        })
        .collect::<String>();
    assert!(matches!(
        FilterSnapshot::compile(
            &[ListInput {
                name: "v5".into(),
                syntax: RuleSyntax::AdguardV5,
                action: Action::Block,
                rules
            }],
            20000,
            4 * 1024 * 1024
        ),
        Err(CompileError::Limit)
    ));
}
#[test]
fn equal_cache_classes_imply_equal_predicates_at_boundaries_and_across_families() {
    let filters = compile(
        "||test^$client=192.0.2.1|192.0.2.8/30|2001:db8::/127|2001:db8::ffff/128|Kids\n||test^$client=0.0.0.0/0|::/0|~192.0.2.9|~Adults\n||test^$client=255.255.255.255|ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    );
    let mut contexts = Vec::new();
    for ip in [
        "0.0.0.0",
        "192.0.2.0",
        "192.0.2.1",
        "192.0.2.2",
        "192.0.2.7",
        "192.0.2.8",
        "192.0.2.9",
        "192.0.2.10",
        "192.0.2.11",
        "192.0.2.12",
        "255.255.255.255",
        "::",
        "::1",
        "2001:db8::",
        "2001:db8::1",
        "2001:db8::2",
        "2001:db8::fffe",
        "2001:db8::ffff",
        "2001:db8::1:0",
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    ] {
        for name in [None, Some("Kids"), Some("Adults"), Some("unknown")] {
            contexts.push(client(ip, name));
        }
    }
    for left in &contexts {
        for right in &contexts {
            if filters.client_partition(*left) == filters.client_partition(*right) {
                for rule in filters.rules() {
                    assert_eq!(
                        rule.client().unwrap().matches(*left),
                        rule.client().unwrap().matches(*right)
                    );
                }
            }
        }
    }
    assert_eq!(
        filters.client_partition(client("192.0.2.1", None)),
        filters.client_partition(client("::ffff:192.0.2.1", None))
    );
    assert_eq!(
        compile("||test^$client=Kids").client_partition(client("192.0.2.1", Some("Kids"))),
        compile("||test^$client=Kids").client_partition(client("198.51.100.1", Some("Kids")))
    );
    assert_eq!(
        compile("||test^").client_partition(client("192.0.2.1", Some("Kids"))),
        0
    );
}
#[cfg(feature = "parallel")]
#[test]
fn serial_parallel_rules_contexts_and_partitions_are_identical() {
    let inputs = [ListInput {
        name: "v5".into(),
        syntax: RuleSyntax::AdguardV5,
        action: Action::Block,
        rules: (0..40000)
            .map(|n| format!("||n{n}.test^\n"))
            .collect::<String>()
            + "||test^$client=192.0.2.0/24|Kids\n/^192\\.0\\.2\\.1$/$client=~Kids,dnstype=A\n||cancel.test^\n||cancel.test^$badfilter",
    }];
    let serial = FilterSnapshot::compile(&inputs, 50000, 4 * 1024 * 1024).unwrap();
    let parallel = rustwalld_dns_filter::ParallelCompiler::new(2)
        .unwrap()
        .compile(&inputs, 50000, 4 * 1024 * 1024)
        .unwrap();
    assert_eq!(
        serde_json::to_value(serial.rules()).unwrap(),
        serde_json::to_value(parallel.rules()).unwrap()
    );
    for ctx in [
        client("192.0.2.1", Some("Kids")),
        client("198.51.100.1", None),
    ] {
        assert_eq!(serial.client_partition(ctx), parallel.client_partition(ctx));
        for kind in [1, 28, 5, 65] {
            assert_eq!(
                serial.evaluate_client("test", kind, ctx),
                parallel.evaluate_client("test", kind, ctx)
            );
            assert_eq!(
                serial.evaluate_value_client("192.0.2.1", kind, ctx),
                parallel.evaluate_value_client("192.0.2.1", kind, ctx)
            );
        }
    }
}

#[test]
fn merged_network_and_name_matching_agrees_with_a_direct_predicate_model() {
    use rustwalld_dns_filter::ClientValue;
    let rules = "||test^$client=192.0.2.128/25|192.0.2.0/25|192.0.2.64/26|2001:db8::/127|2001:db8::2/127|Kids|~192.0.2.9|~2001:db8::1|~Adults";
    let filters = compile(rules);
    let selector = filters.rules()[0].client().unwrap();
    let simple = |values: &[ClientValue], ctx: ClientContext<'_>| {
        values.iter().any(|value| match value {
            ClientValue::Network(net) => net.contains(&ctx.ip.to_canonical()),
            ClientValue::Name(name) => ctx.name == Some(name.as_ref()),
        })
    };
    for octet in 0..=255 {
        for ip in [format!("192.0.2.{octet}"), format!("2001:db8::{octet:x}")] {
            for name in [None, Some("Kids"), Some("Adults")] {
                let ctx = client(&ip, name);
                let expected = !simple(selector.exclude(), ctx)
                    && (selector.include().is_empty() || simple(selector.include(), ctx));
                assert_eq!(selector.matches(ctx), expected);
            }
        }
    }
    let mut seed = 42u128;
    for index in 0..20000 {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let ip = if index % 2 == 0 {
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(seed as u32))
        } else {
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(seed))
        };
        for name in [None, Some("Kids"), Some("Adults"), Some("kids")] {
            let ctx = ClientContext { ip, name };
            let expected = !simple(selector.exclude(), ctx)
                && (selector.include().is_empty() || simple(selector.include(), ctx));
            assert_eq!(selector.matches(ctx), expected);
        }
    }
}
