#![allow(clippy::unwrap_used)]
use rustwalld_dns_filter::{Action, CompileError, FilterSnapshot, ListInput, RuleSyntax};
fn list(rules: &str, syntax: RuleSyntax) -> ListInput {
    ListInput {
        name: "source".into(),
        action: Action::Block,
        syntax,
        rules: rules.into(),
    }
}
fn compile(rules: &str) -> FilterSnapshot {
    FilterSnapshot::compile(
        &[list(rules, RuleSyntax::AdguardV4)],
        20000,
        4 * 1024 * 1024,
    )
    .unwrap()
}
#[test]
fn types_narrow_exact_suffix_regex_and_allow_rules() {
    let filters = compile(
        "||test^$dnstype=aaaa\n|mail.test|$dnstype=MX\n/^txt.*test$/$dnstype=TXT\n@@||test^$dnstype=A",
    );
    assert_eq!(filters.stats[0].invalid, 0);
    for (name, kind, action) in [
        ("ads.test", 1, Action::Allow),
        ("ads.test", 28, Action::Block),
        ("mail.test", 15, Action::Block),
        ("x.mail.test", 15, Action::Allow),
        ("txt.test", 16, Action::Block),
        ("txt.test", 5, Action::Allow),
    ] {
        assert_eq!(
            filters.evaluate_type(name, kind).action,
            action,
            "{name}/{kind}"
        );
    }
    assert_eq!(filters.evaluate("ads.test").action, Action::Allow);
    assert!(filters.has_type_rules());
}
#[test]
fn exclusions_precede_inclusions_and_scope_order_is_canonical() {
    let filters = compile(
        "||test^$dnstype=~CNAME|A|AAAA,denyallow=Safe.test\n||test^$denyallow=safe.test,dnstype=AAAA|a|~cname\n|safe.test|$dnstype=AAAA",
    );
    assert_eq!(filters.stats[0].duplicates, 1);
    assert_eq!(filters.evaluate_type("ads.test", 5).action, Action::Allow);
    assert_eq!(filters.evaluate_type("ads.test", 1).action, Action::Block);
    assert_eq!(filters.evaluate_type("safe.test", 1).action, Action::Allow);
    assert_eq!(filters.evaluate_type("safe.test", 28).action, Action::Block);
    assert_eq!(
        compile("*$dnstype=A|~A").evaluate("any.test").action,
        Action::Allow
    );
    assert_eq!(
        compile("*$dnstype=~AAAA")
            .evaluate_type("any.test", 65280)
            .action,
        Action::Block
    );
}
#[test]
fn invalid_modifiers_never_publish_partial_scopes_and_old_versions_are_frozen() {
    let rules = [
        "||test^$dnstype=",
        "||test^$dnstype=A|",
        "||test^$dnstype=TYPE65280",
        "||test^$dnstype=ANAME",
        "||test^$dnstype=NONE",
        "||test^$dnstype=A,dnstype=AAAA",
        "||test^$dnstype=A,badfilter",
        "||test^$denyallow=safe.test,denyallow=other.test",
        "test$dnstype=A",
        "||test^$dnstype=A$badfilter",
    ];
    assert_eq!(compile(&rules.join("\n")).stats[0].invalid, rules.len());
    for syntax in [
        RuleSyntax::Native,
        RuleSyntax::Adguard,
        RuleSyntax::AdguardV2,
        RuleSyntax::AdguardV3,
    ] {
        let filters =
            FilterSnapshot::compile(&[list("||test^$dnstype=AAAA", syntax)], 100, 10000).unwrap();
        assert_eq!(filters.stats[0].invalid, 1);
    }
    let old = FilterSnapshot::compile(
        &[list("||test^$denyallow=safe.test", RuleSyntax::AdguardV3)],
        100,
        10000,
    )
    .unwrap();
    let json = serde_json::to_value(old.rules()).unwrap();
    assert_eq!(json[0]["denyallow"], serde_json::json!(["safe.test"]));
    assert!(json[0].get("scope").is_none());
    assert!(json[0].get("dnstype").is_none());
}
#[test]
fn v4_values_do_not_activate_legacy_ip_rules_or_prune_needed_descendants() {
    let filters=FilterSnapshot::compile(&[list("1\n/192\\.0\\.2\\.2/",RuleSyntax::Native),ListInput{name:"new".into(),..list("||192.0.2.1^$dnstype=A\n/^2001:db8::1$/$dnstype=AAAA\n||192.0.2.3^$dnstype=A,denyallow=safe.test",RuleSyntax::AdguardV4)}],100,10000).unwrap();
    assert_eq!(filters.evaluate_value("192.0.2.1", 1).action, Action::Block);
    assert_eq!(
        filters.evaluate_value("192.0.2.1", 28).action,
        Action::Allow
    );
    assert_eq!(filters.evaluate_value("192.0.2.2", 1).action, Action::Allow);
    assert_eq!(
        filters.evaluate_value("2001:db8::1", 28).action,
        Action::Block
    );
    assert_eq!(filters.evaluate_value("192.0.2.3", 1).action, Action::Allow);
    assert_eq!(filters.evaluate_type("192.0.2.3", 1).action, Action::Allow); // Native suffix stays eligible; V4 denyallow skips IP.
}
#[test]
fn type_and_value_budgets_are_independent_and_complete() {
    assert_eq!(
        compile(&format!("||test^$dnstype={}", vec!["A"; 65].join("|"))).stats[0].invalid,
        1
    );
    let rules = (0..513)
        .map(|n| format!("||n{n}.test^$dnstype=AAAA\n"))
        .collect::<String>();
    assert!(matches!(
        FilterSnapshot::compile(
            &[list(&rules, RuleSyntax::AdguardV4)],
            20000,
            4 * 1024 * 1024
        ),
        Err(CompileError::Limit)
    ));
    let many_types = "A|AAAA|CNAME|HTTPS|SVCB|MX|TXT|NS|SOA|PTR|DS|DNSKEY|RRSIG|NSEC|NSEC3|CAA|SRV";
    let rules = (0..512)
        .map(|n| format!("||n{n}.test^$dnstype={many_types}\n"))
        .collect::<String>();
    assert!(matches!(
        FilterSnapshot::compile(
            &[list(&rules, RuleSyntax::AdguardV4)],
            20000,
            4 * 1024 * 1024
        ),
        Err(CompileError::Limit)
    ));
    let rules = (0..4097)
        .map(|n| format!("||192.0.{}.{}^\n", n / 256, n % 256))
        .collect::<String>();
    assert!(matches!(
        FilterSnapshot::compile(
            &[list(&rules, RuleSyntax::AdguardV4)],
            20000,
            4 * 1024 * 1024
        ),
        Err(CompileError::Limit)
    ));
}
#[cfg(feature = "parallel")]
#[test]
fn parallel_v4_ids_metadata_and_typed_decisions_are_identical() {
    let rules = (0..40000)
        .map(|n| format!("||n{n}.test^\n"))
        .collect::<String>()
        + "||test^$dnstype=AAAA,denyallow=safe.test\n/^192\\.0\\.2\\.1$/$dnstype=A\n||cancel.test^\n||cancel.test^$badfilter";
    let inputs = [list(&rules, RuleSyntax::AdguardV4)];
    let serial = FilterSnapshot::compile(&inputs, 50000, 4 * 1024 * 1024).unwrap();
    for workers in [1, 2, 4] {
        let parallel = rustwalld_dns_filter::ParallelCompiler::new(workers)
            .unwrap()
            .compile(&inputs, 50000, 4 * 1024 * 1024)
            .unwrap();
        assert_eq!(
            serde_json::to_value(serial.rules()).unwrap(),
            serde_json::to_value(parallel.rules()).unwrap()
        );
        for kind in [1, 28, 5, 65, 65280] {
            for name in ["n42.test", "safe.test", "other.test"] {
                assert_eq!(
                    serial.evaluate_type(name, kind),
                    parallel.evaluate_type(name, kind)
                );
            }
            assert_eq!(
                serial.evaluate_value("192.0.2.1", kind),
                parallel.evaluate_value("192.0.2.1", kind)
            );
        }
    }
}
