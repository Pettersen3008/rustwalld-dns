#![allow(clippy::unwrap_used)]
use rustwalld_dns_filter::{Action, FilterSnapshot, ListInput, RuleSyntax};

fn list(name: &str, action: Action, syntax: RuleSyntax, rules: &str) -> ListInput {
    ListInput {
        name: name.into(),
        action,
        syntax,
        rules: rules.into(),
    }
}
fn compile(lists: &[ListInput]) -> FilterSnapshot {
    FilterSnapshot::compile(lists, 100_000, 10_000_000).unwrap()
}
#[test]
fn cancellation_precedes_deduplication_and_is_order_independent() {
    let original = list(
        "publisher",
        Action::Block,
        RuleSyntax::AdguardV2,
        "||ads.test^\n||ADS.test^\n||ads.test^\n||other.test^\n@@||safe.test^\n||safe.test^",
    );
    let directives = list(
        "operator",
        Action::Block,
        RuleSyntax::AdguardV2,
        "||ads.test^$badfilter\n@@||safe.test^$badfilter\n||absent.test^$badfilter",
    );
    for lists in [
        [original.clone(), directives.clone()],
        [directives.clone(), original.clone()],
    ] {
        let snapshot = compile(&lists);
        // The uppercase text variant survives although its matcher is identical.
        assert_eq!(snapshot.evaluate("ads.test").action, Action::Block);
        let id = snapshot.evaluate("ads.test").rule.unwrap();
        let sources = &snapshot.rule(id).unwrap().sources;
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].line, 2);
        assert_eq!(sources[0].list.as_ref(), "publisher");
        assert_eq!(snapshot.evaluate("safe.test").action, Action::Block);
        assert_eq!(snapshot.cancellation_targets(), 3);
        let report = &snapshot.cancellations()[0];
        assert_eq!(report.pattern.as_ref(), "||ads.test^");
        assert_eq!(report.directives, 1);
        assert_eq!(report.disabled, 2);
        assert_eq!(snapshot.cancellations()[2].disabled, 0);
        assert!(snapshot.stats.iter().all(|stats| stats.invalid == 0));
        assert_eq!(
            snapshot.stats.iter().map(|stats| stats.raw).sum::<usize>(),
            9
        );
    }
}
#[test]
fn effective_action_and_policy_syntax_are_part_of_identity() {
    let snapshot = compile(&[
        list("native", Action::Block, RuleSyntax::Native, "||same.test^"),
        list("legacy", Action::Block, RuleSyntax::Adguard, "||same.test^"),
        list(
            "v2",
            Action::Block,
            RuleSyntax::AdguardV2,
            "||same.test^\n@@||same.test^\n@@||same.test^$badfilter\n||same.test^$badfilter",
        ),
        list(
            "allow-list",
            Action::Allow,
            RuleSyntax::AdguardV2,
            "||same.test^",
        ),
    ]);
    assert_eq!(snapshot.evaluate("same.test").action, Action::Block);
    assert_eq!(snapshot.rule(0).unwrap().sources.len(), 2);
    assert_eq!(snapshot.cancellations()[0].disabled, 2);
    assert_eq!(snapshot.cancellations()[1].disabled, 1);
    assert_eq!(snapshot.stats[3].disabled, 1);
}
#[test]
fn regex_dollars_masks_comments_and_legacy_semantics() {
    let snapshot = compile(&[
        list(
            "v2",
            Action::Block,
            RuleSyntax::AdguardV2,
            "! header\n# comment\n/^ads\\.test$/\n/^ads\\.test$/$badfilter\n/^literal\\$badfilter$/\n||track*.test^\n||track*.test^$badfilter\n||inline.test^ # unsupported\n||inline.test^$badfilter # unsupported",
        ),
        list(
            "legacy",
            Action::Block,
            RuleSyntax::Adguard,
            "||old.test^ # still stripped\n||old.test^$badfilter",
        ),
    ]);
    assert_eq!(snapshot.evaluate("ads.test").action, Action::Allow);
    assert_eq!(snapshot.evaluate("track7.test").action, Action::Allow);
    assert_eq!(snapshot.evaluate("old.test").action, Action::Block);
    assert_eq!(snapshot.stats[0].invalid, 2);
    assert_eq!(snapshot.stats[0].badfilters, 2);
    assert_eq!(snapshot.stats[0].disabled, 2);
    assert_eq!(snapshot.stats[1].invalid, 1);
    assert_eq!(snapshot.stats[0].raw, 7);
    assert_eq!(snapshot.cancellations()[0].directive_sources[0].line, 4);
}
#[test]
fn unsupported_directives_cannot_hide_invalid_rules_or_hosts() {
    let rules = "0.0.0.0 hosts.test\n0.0.0.0 hosts.test$badfilter\nbare.test\nbare.test$badfilter\n||ads.test^$important\n||ads.test^$important,badfilter\n||ads.test^$important$badfilter\n||ads.test^$~badfilter\n||ads.test^$badfilter=1\n||ads.test^$badfilter,badfilter\n||ads.test^$BADFILTER\n||ads.test^$badfilter$badfilter\n||ads\\$badfilter";
    let snapshot = compile(&[list("v2", Action::Block, RuleSyntax::AdguardV2, rules)]);
    assert_eq!(snapshot.stats[0].invalid, 11);
    assert_eq!(snapshot.cancellation_targets(), 0);
    assert_eq!(snapshot.evaluate("hosts.test").action, Action::Block);
    assert_eq!(snapshot.evaluate("bare.test").action, Action::Block);
    assert_eq!(snapshot.evaluate("x.bare.test").action, Action::Allow);
}
#[test]
fn raw_byte_declaration_and_report_budgets_include_disabled_rules() {
    let input = list(
        "v2",
        Action::Block,
        RuleSyntax::AdguardV2,
        "||ads.test^\n||ads.test^$badfilter",
    );
    assert!(FilterSnapshot::compile(std::slice::from_ref(&input), 1, usize::MAX).is_err());
    assert!(
        FilterSnapshot::compile(std::slice::from_ref(&input), 2, input.rules.len() - 1).is_err()
    );
    assert_eq!(compile(&[input]).effective_rules(), 0);
    let mut rules = String::new();
    for i in 0..205 {
        for _ in 0..7 {
            rules.push_str(&format!("||ads{i}.test^$badfilter\n||ads{i}.test^\n"));
        }
    }
    let snapshot = compile(&[list("many", Action::Block, RuleSyntax::AdguardV2, &rules)]);
    assert_eq!(snapshot.effective_rules(), 0);
    assert_eq!(snapshot.cancellation_targets(), 205);
    assert_eq!(snapshot.cancellations().len(), 200);
    for report in snapshot.cancellations() {
        assert_eq!(report.directives, 7);
        assert_eq!(report.disabled, 7);
        assert_eq!(report.directive_sources.len(), 5);
        assert_eq!(report.disabled_sources.len(), 5);
    }
    let at_limit = list(
        "bounded",
        Action::Block,
        RuleSyntax::AdguardV2,
        &"||ads.test^$badfilter\n".repeat(65_536),
    );
    let snapshot = compile(std::slice::from_ref(&at_limit));
    assert_eq!(snapshot.cancellations()[0].directives, 65_536);
    assert_eq!(snapshot.stats[0].badfilters, 65_536);
    let mut over_limit = at_limit;
    over_limit.rules.push_str("||ads.test^$badfilter\n");
    assert!(FilterSnapshot::compile(&[over_limit], 100_000, usize::MAX).is_err());
}

#[test]
fn cancelled_regexes_do_not_exhaust_the_active_regex_budget() {
    let mut rules = String::new();
    for i in 0..600 {
        rules.push_str(&format!("/^ads{i}\\.test$/\n/^ads{i}\\.test$/$badfilter\n"));
    }
    rules.push_str("/^active\\.test$/\n/white space/\n/white space/$badfilter\n");
    let snapshot = compile(&[list("regex", Action::Block, RuleSyntax::AdguardV2, &rules)]);
    assert_eq!(snapshot.stats[0].invalid, 0);
    assert_eq!(snapshot.cancellation_targets(), 601);
    assert_eq!(snapshot.effective_rules(), 1);
    assert_eq!(snapshot.evaluate("ads599.test").action, Action::Allow);
    assert_eq!(snapshot.evaluate("active.test").action, Action::Block);
}
#[test]
fn unmatched_cancellation_preserves_an_allow_rule_and_zero_stats_are_legacy_compatible() {
    let old = compile(&[list(
        "legacy",
        Action::Block,
        RuleSyntax::Adguard,
        "||ads.test^ # inline comment\n@@||ads.test^",
    )]);
    let stats = serde_json::to_value(&old.stats).unwrap();
    assert!(stats[0].get("badfilters").is_none());
    assert!(stats[0].get("disabled").is_none());
    assert_eq!(old.rules()[0].id, 0);
    assert_eq!(old.rules()[1].id, 1);
    let v2 = compile(&[list(
        "v2",
        Action::Block,
        RuleSyntax::AdguardV2,
        "@@||ads.test^\n||ads.test^$badfilter",
    )]);
    assert_eq!(v2.evaluate("ads.test").action, Action::Allow);
    assert_eq!(v2.rules()[0].action, Action::Allow);
    assert_eq!(v2.cancellations()[0].disabled, 0);
    assert_eq!(v2.stats[0].unique, 1);
}
