#![allow(clippy::unwrap_used)]
use rustwalld_dns_filter::{
    Action, CLIENT_TAGS, ClientContext, ClientTags, CompileError, FilterSnapshot, ListInput,
    RuleSyntax,
};
fn compile(rules: &str, syntax: RuleSyntax) -> Result<FilterSnapshot, CompileError> {
    FilterSnapshot::compile(
        &[ListInput {
            name: "tags".into(),
            syntax,
            action: Action::Block,
            rules: rules.into(),
        }],
        10000,
        16 * 1024 * 1024,
    )
}
fn context(names: &[&str]) -> rustwalld_dns_filter::FilterContext<'static> {
    ClientContext {
        ip: "192.0.2.1".parse().unwrap(),
        name: Some("Kids"),
    }
    .with_tags(ClientTags::compile(names.iter().copied()).unwrap())
}
#[test]
fn combinations_exclusions_allow_precedence_and_missing_context() {
    let f=compile("||test^$ctag=device_phone|~user_admin,client=Kids,dnstype=AAAA,denyallow=safe.test\n@@||allow.test^$ctag=device_phone\n||allow.test^\n/^192\\.0\\.2\\.10$/$ctag=user_child,dnstype=A",RuleSyntax::AdguardV6).unwrap();
    for (tags, expected) in [
        (vec!["device_phone"], Action::Block),
        (vec!["device_phone", "user_admin"], Action::Allow),
        (vec!["user_child"], Action::Allow),
        (vec![], Action::Allow),
    ] {
        let ctx = context(&tags);
        assert_eq!(f.evaluate_client("track.test", 28, ctx).action, expected);
        assert_eq!(
            f.evaluate_client("safe.test", 28, ctx).action,
            Action::Allow
        );
        assert_eq!(
            f.evaluate_client("track.test", 1, ctx).action,
            Action::Allow
        );
        assert_eq!(
            f.evaluate_client("allow.test", 28, ctx).action,
            if tags.contains(&"device_phone") {
                Action::Allow
            } else {
                Action::Block
            }
        );
    }
    assert_eq!(f.evaluate_type("track.test", 28).action, Action::Allow);
    assert_eq!(f.evaluate_type("allow.test", 28).action, Action::Block);
    assert!(f.has_client_rules());
    assert!(f.has_tag_rules());
    assert_eq!(
        f.evaluate_value_client("192.0.2.10", 1, context(&["user_child"]))
            .action,
        Action::Block
    );
    assert_eq!(
        f.evaluate_value_client("192.0.2.10", 1, context(&[]))
            .action,
        Action::Allow
    );
    let negative = compile("||test^$ctag=~user_admin", RuleSyntax::AdguardV6).unwrap();
    assert!(negative.has_tag_rules());
    assert!(negative.has_client_rules());
    assert_eq!(
        negative.evaluate_type("track.test", 1).action,
        Action::Allow
    );
    assert_eq!(
        negative
            .evaluate_client("track.test", 1, context(&[]))
            .action,
        Action::Block
    );
    assert_eq!(
        negative
            .evaluate_client("track.test", 1, context(&["user_admin"]))
            .action,
        Action::Allow
    );
}
#[test]
fn masks_match_an_independent_set_model_and_cache_classes_ignore_unused_tags() {
    let f=compile("||a.test^$ctag=device_phone|user_child|~user_admin\n||b.test^$ctag=~os_linux\n||c.test^$client=192.0.2.0/24,ctag=device_pc",RuleSyntax::AdguardV6).unwrap();
    let names = [
        "device_phone",
        "user_child",
        "user_admin",
        "os_linux",
        "device_pc",
        "device_camera",
    ];
    let mut seen = std::collections::HashMap::new();
    for mask in 0..64 {
        let tags: Vec<_> = names
            .iter()
            .enumerate()
            .filter(|(i, _)| mask & (1 << i) != 0)
            .map(|(_, name)| *name)
            .collect();
        let ctx = context(&tags);
        let results =
            ["a.test", "b.test", "c.test"].map(|name| f.evaluate_client(name, 1, ctx).action);
        assert_eq!(
            results[0] == Action::Block,
            !tags.contains(&"user_admin")
                && (tags.contains(&"device_phone") || tags.contains(&"user_child"))
        );
        assert_eq!(results[1] == Action::Block, !tags.contains(&"os_linux"));
        assert_eq!(results[2] == Action::Block, tags.contains(&"device_pc"));
        let class = f.context_partition(ctx);
        if let Some(prior) = seen.insert(class, results) {
            assert_eq!(prior, results);
        }
    }
    assert_eq!(
        f.context_partition(context(&[])),
        f.context_partition(context(&["device_camera"]))
    );
    let ordinary = compile("ordinary.test", RuleSyntax::AdguardV5).unwrap();
    assert_eq!(
        ordinary.context_partition(context(&[])),
        ordinary.context_partition(context(&CLIENT_TAGS))
    );
}
#[test]
fn frozen_versions_invalid_tokens_and_budgets_fail_explicitly() {
    for version in [
        RuleSyntax::Adguard,
        RuleSyntax::AdguardV2,
        RuleSyntax::AdguardV3,
        RuleSyntax::AdguardV4,
        RuleSyntax::AdguardV5,
    ] {
        assert_eq!(
            compile("||test^$ctag=user_child", version).unwrap().stats[0].invalid,
            1,
            "{version:?}"
        );
    }
    for value in [
        "",
        "~",
        "device_phone|",
        "DEVICE_PHONE",
        "custom_tag",
        "'device_phone'",
        "device-phone",
        "device_phone,ctag=user_child",
        "device_phone,important",
        "device_phone,badfilter",
    ] {
        assert_eq!(
            compile(&format!("||test^$ctag={value}"), RuleSyntax::AdguardV6)
                .unwrap()
                .stats[0]
                .invalid,
            1,
            "{value}"
        );
    }
    assert!(ClientTags::compile(["device_phone", "device_phone"]).is_err());
    assert!(ClientTags::compile(["unknown"]).is_err());
    assert_eq!(
        compile(
            &format!("||test^$ctag={}", vec!["device_phone"; 65].join("|")),
            RuleSyntax::AdguardV6
        )
        .unwrap()
        .stats[0]
            .invalid,
        1
    );
    let oversized = (0..513)
        .map(|i| format!("||{i}.test^$ctag=device_phone"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(matches!(
        compile(&oversized, RuleSyntax::AdguardV6),
        Err(CompileError::Limit)
    ));
}
#[test]
fn scope_identity_serialization_and_declared_tag_budget() {
    let f=compile("||test^$ctag=device_phone|user_child|device_phone\n||test^$ctag=user_child|device_phone\n||test^$ctag=~device_phone",RuleSyntax::AdguardV6).unwrap();
    assert_eq!(f.rules().len(), 2);
    let json = serde_json::to_value(f.rules()).unwrap();
    assert_eq!(
        json[0]["ctag"]["include"],
        serde_json::json!(["device_phone", "user_child"])
    );
    let all = CLIENT_TAGS.join("|");
    let rules = (0..391)
        .map(|i| format!("||{i}.test^$ctag={all}"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(matches!(
        compile(&rules, RuleSyntax::AdguardV6),
        Err(CompileError::Limit)
    ));
}
#[cfg(feature = "parallel")]
#[test]
fn parallel_matches_serial_with_combined_scopes() {
    let rules = "||test^$ctag=device_phone|~user_admin,client=Kids,dnstype=AAAA\n/^192\\.0\\.2\\.10$/$ctag=user_child";
    let lists = [ListInput {
        name: "tags".into(),
        action: Action::Block,
        syntax: RuleSyntax::AdguardV6,
        rules: rules.into(),
    }];
    let serial = compile(rules, RuleSyntax::AdguardV6).unwrap();
    let parallel = rustwalld_dns_filter::ParallelCompiler::new(2)
        .unwrap()
        .compile(&lists, 10000, 16 * 1024 * 1024)
        .unwrap();
    assert_eq!(
        serde_json::to_value(serial.rules()).unwrap(),
        serde_json::to_value(parallel.rules()).unwrap()
    );
    assert_eq!(
        serial.evaluate_client("test", 28, context(&["device_phone"])),
        parallel.evaluate_client("test", 28, context(&["device_phone"]))
    );
}
