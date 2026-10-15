#![allow(clippy::unwrap_used)]
use rustwalld_dns_filter::{Action, CompileError, FilterSnapshot, ListInput, RuleSyntax};
fn compile(rules: &str) -> FilterSnapshot {
    FilterSnapshot::compile(
        &[ListInput {
            name: "publisher".into(),
            action: Action::Block,
            syntax: RuleSyntax::AdguardV3,
            rules: rules.into(),
        }],
        20000,
        4 * 1024 * 1024,
    )
    .unwrap()
}
#[test]
fn exclusions_skip_only_their_rule_and_preserve_specificity() {
    let snapshot = compile(
        "||test^$denyallow=safe.test\n||safe.test^\n||other.test^$denyallow=x.other.test\n|x.other.test|\n||other.test^$denyallow=y.other.test\n@@||safe.test^$denyallow=ads.safe.test",
    );
    assert_eq!(snapshot.stats[0].invalid, 0);
    assert_eq!(snapshot.stats[0].redundant, 0);
    for (name, action) in [
        ("safe.test", Action::Allow),
        ("x.safe.test", Action::Allow),
        ("ads.safe.test", Action::Block),
        ("x.ads.safe.test", Action::Block),
        ("y.other.test", Action::Block),
        ("x.other.test", Action::Block),
        ("outside.com", Action::Allow),
    ] {
        assert_eq!(snapshot.evaluate(name).action, action, "{name}");
    }
    assert_eq!(
        snapshot
            .rule(snapshot.evaluate("x.other.test").rule.unwrap())
            .unwrap()
            .domain
            .as_ref(),
        "x.other.test"
    );
    assert_eq!(
        snapshot
            .rule(snapshot.evaluate("y.other.test").rule.unwrap())
            .unwrap()
            .domain
            .as_ref(),
        "other.test"
    );
}
#[test]
fn earlier_block_candidates_never_skip_a_later_allow_at_the_same_name() {
    let snapshot = compile(
        "||test^$denyallow=safe.test\n||test^$denyallow=other.test\n@@||test^$denyallow=ads.test",
    );
    assert_eq!(snapshot.evaluate("tracking.test").action, Action::Allow);
    assert_eq!(snapshot.evaluate("ads.test").action, Action::Block);
    assert_eq!(snapshot.evaluate("safe.test").action, Action::Allow);
    let snapshot = compile("||test^$denyallow=safe.test\n||test^");
    assert_eq!(snapshot.evaluate("tracking.test").rule, Some(0));
    assert_eq!(snapshot.evaluate("safe.test").rule, Some(1));
}
#[test]
fn exact_regex_exceptions_and_escaped_labels() {
    let snapshot = compile(
        r"|exact.test|$denyallow=unrelated.test
/^.*\.test$/$denyallow=safe.test
/^safe\.test$/
@@/^.*\.test$/$denyallow=exact.test|safe.test",
    );
    assert_eq!(snapshot.stats[0].invalid, 0);
    assert_eq!(snapshot.evaluate("exact.test").action, Action::Block);
    assert_eq!(snapshot.evaluate("safe.test").action, Action::Block);
    assert_eq!(snapshot.evaluate("x.safe.test").action, Action::Allow);
    assert_eq!(snapshot.evaluate("ordinary.test").action, Action::Allow);
    let boundaries = compile("||test^$denyallow=safe.test");
    for name in ["safe.test", "x.safe.test"] {
        assert_eq!(boundaries.evaluate(name).action, Action::Allow);
    }
    for name in ["notsafe.test", r"x\.safe.test", r"safe\.test.test"] {
        assert_eq!(boundaries.evaluate(name).action, Action::Block, "{name}");
    }
    assert_eq!(boundaries.evaluate(r"x\\.safe.test").action, Action::Allow);
}
#[test]
fn exclusion_identity_deduplication_redundancy_and_frozen_versions() {
    let snapshot = compile(
        "||test^$denyallow=B.test.|a.test|a.test\n||test^$denyallow=a.test|b.test\n||test^$denyallow=c.test\n||child.test^\n||test^$badfilter",
    );
    assert_eq!(snapshot.stats[0].duplicates, 1);
    assert_eq!(snapshot.rules().len(), 3);
    assert_eq!(snapshot.cancellation_targets(), 1);
    assert_eq!(snapshot.stats[0].disabled, 0);
    assert_eq!(
        snapshot.rules()[0]
            .denyallow()
            .as_ref()
            .unwrap()
            .domains()
            .iter()
            .map(|v| v.as_ref())
            .collect::<Vec<_>>(),
        ["a.test", "b.test"]
    );
    let covered = compile(
        "||test^\n||child.test^$denyallow=safe.child.test\n|exact.test|$denyallow=other.test",
    );
    assert_eq!(covered.stats[0].redundant, 2);
    assert_eq!(covered.effective_rules(), 1);
    for syntax in [
        RuleSyntax::Native,
        RuleSyntax::Adguard,
        RuleSyntax::AdguardV2,
    ] {
        let old = FilterSnapshot::compile(
            &[ListInput {
                name: "old".into(),
                action: Action::Block,
                syntax,
                rules: "||test^$denyallow=safe.test".into(),
            }],
            10,
            1000,
        )
        .unwrap();
        assert_eq!(old.stats[0].invalid, 1);
        assert_eq!(old.evaluate("ads.test").action, Action::Allow);
    }
}
#[test]
fn malformed_or_combined_modifiers_are_never_partially_applied() {
    let invalid = [
        "||test^$denyallow=",
        "||test^$denyallow=a.test|",
        "||test^$denyallow=*.test",
        "||test^$denyallow=~safe.test",
        "||test^$denyallow=a.test,dnstype=A",
        "||test^$denyallow=a.test,badfilter",
        "||test^$denyallow=a.test$badfilter",
        "||test^$badfilter,denyallow=a.test",
        "test$denyallow=a.test",
        "0.0.0.0 test$denyallow=a.test",
        r"||test^\$denyallow=a.test",
    ];
    let snapshot = compile(&invalid.join("\n"));
    assert_eq!(snapshot.stats[0].invalid, invalid.len());
    assert_eq!(snapshot.effective_rules(), 0);
    assert_eq!(
        compile("*$denyallow=com|net\n||tracking.com^")
            .evaluate("tracking.com")
            .action,
        Action::Block
    );
    assert_eq!(
        compile("*$denyallow=com|net").evaluate("safe.com").action,
        Action::Allow
    );
}
#[test]
fn scoped_limits_are_independent_of_duplicates_and_unscoped_rules() {
    let rules = (0..512)
        .map(|i| format!("||n{i}.test^$denyallow=safe.test\n"))
        .collect::<String>();
    let snapshot = compile(&(rules.clone() + "||n0.test^$denyallow=safe.test\nplain.test\n"));
    assert_eq!(snapshot.rules().len(), 513);
    assert_eq!(snapshot.stats[0].duplicates, 1);
    assert!(matches!(
        FilterSnapshot::compile(
            &[ListInput {
                name: "over".into(),
                action: Action::Block,
                syntax: RuleSyntax::AdguardV3,
                rules: rules + "||overflow.test^$denyallow=safe.test"
            }],
            20000,
            4 * 1024 * 1024
        ),
        Err(CompileError::Limit)
    ));
    let domains = (0..64)
        .map(|i| format!("safe{i}.test"))
        .collect::<Vec<_>>()
        .join("|");
    let rules = (0..129)
        .map(|i| format!("||n{i}.test^$denyallow={domains}\n"))
        .collect::<String>();
    assert!(matches!(
        FilterSnapshot::compile(
            &[ListInput {
                name: "total".into(),
                action: Action::Block,
                syntax: RuleSyntax::AdguardV3,
                rules
            }],
            20000,
            4 * 1024 * 1024
        ),
        Err(CompileError::Limit)
    ));
    assert_eq!(
        compile(&format!("||test^$denyallow={domains}|last.test")).stats[0].invalid,
        1
    );
}
#[cfg(feature = "parallel")]
#[test]
fn parallel_compilation_preserves_scoped_identity_and_decisions() {
    use rustwalld_dns_filter::ParallelCompiler;
    let rules = (0..40000)
        .map(|i| format!("||n{i}.test^\n"))
        .collect::<String>()
        + "||test^$denyallow=safe.test\n||safe.test^$denyallow=other.test\n/^.*test$/$denyallow=safe.test\n||cancel.test^\n||cancel.test^$badfilter\n";
    let lists = [ListInput {
        name: "publisher".into(),
        action: Action::Block,
        syntax: RuleSyntax::AdguardV3,
        rules,
    }];
    let serial = FilterSnapshot::compile(&lists, 50000, 4 * 1024 * 1024).unwrap();
    for workers in [1, 2, 4] {
        let parallel = ParallelCompiler::new(workers)
            .unwrap()
            .compile(&lists, 50000, 4 * 1024 * 1024)
            .unwrap();
        assert_eq!(
            serde_json::to_value(serial.rules()).unwrap(),
            serde_json::to_value(parallel.rules()).unwrap()
        );
        assert_eq!(serial.payload_bytes(), parallel.payload_bytes());
        assert_eq!(serial.effective_rules(), parallel.effective_rules());
        for query in [
            "safe.test",
            "other.test",
            "cancel.test",
            "n123.test",
            r"x\.safe.test",
        ] {
            assert_eq!(serial.evaluate(query), parallel.evaluate(query));
        }
    }
}

#[test]
fn deep_names_and_escape_runs_agree_with_label_boundary_exclusions() {
    let snapshot = compile("/.*/$denyallow=safe.test");
    let deep = "a.".repeat(120) + "safe.test";
    assert_eq!(deep.len(), 249);
    assert_eq!(snapshot.evaluate(&deep).action, Action::Allow);
    for count in 0..16 {
        let name = format!("x{}.safe.test", "\\".repeat(count));
        assert_eq!(
            snapshot.evaluate(&name).action,
            if count % 2 == 0 {
                Action::Allow
            } else {
                Action::Block
            },
            "{name}"
        );
    }
    for name in [
        r"safe\.test",
        r"x.safe\.test",
        r"x.safetest.test",
        "unsafe.test",
        "safe.test.test",
    ] {
        assert_eq!(snapshot.evaluate(name).action, Action::Block, "{name}");
    }
}
