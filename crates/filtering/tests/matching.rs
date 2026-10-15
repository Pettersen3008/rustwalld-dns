//! Matching, provenance and normalization contracts through the public API.
use rustwalld_dns_filter::*;

mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn normalization_and_invalid() {
        assert_eq!(normalize("EXAMPLE.com.").unwrap(), "example.com");
        assert_eq!(normalize("bücher.de").unwrap(), "xn--bcher-kva.de");
        for input in [
            "",
            "a..com",
            "http://example.com",
            "a.com$badfilter",
            "-bad.com",
        ] {
            assert!(normalize(input).is_err(), "{input}");
        }
    }
    #[test]
    fn precedence_label_boundaries_sources_and_subsumption() {
        let lists=vec![ListInput { syntax: Default::default(), name:"deny".into(),action:Action::Block,rules:"example.com\nEXAMPLE.com.\nsub.example.com\n=exact.test\n0.0.0.0 hosts.test other.test\n||ads.test^\ninvalid$modifier".into() },ListInput { syntax: Default::default(), name:"allow".into(),action:Action::Allow,rules:"=safe.example.com".into() }];
        let filters = FilterSnapshot::compile(&lists, 100, 10000).unwrap();
        assert_eq!(filters.evaluate("x.example.com").action, Action::Block);
        assert_eq!(filters.evaluate("notexample.com").action, Action::Allow);
        assert_eq!(filters.evaluate("safe.example.com").action, Action::Allow);
        assert_eq!(filters.evaluate("x.safe.example.com").action, Action::Block);
        assert_eq!(filters.evaluate("x.exact.test").action, Action::Allow);
        assert_eq!(filters.stats[0].duplicates, 1);
        assert_eq!(filters.stats[0].invalid, 1);
        assert_eq!(filters.stats[0].redundant, 1);
        let rule = filters
            .rule(filters.evaluate("example.com").rule.unwrap())
            .unwrap();
        assert_eq!(rule.sources.len(), 2);
    }
    #[test]
    fn limits() {
        let list = ListInput {
            syntax: Default::default(),
            name: "test".into(),
            action: Action::Block,
            rules: "a.test\nb.test".into(),
        };
        assert!(FilterSnapshot::compile(std::slice::from_ref(&list), 1, 100).is_err());
        assert!(FilterSnapshot::compile(&[list], 10, 1).is_err());
    }

    #[test]
    fn provenance_survives_inputs_and_independent_snapshots() {
        let snapshot = {
            let lists = [
                ListInput {
                    syntax: Default::default(),
                    name: "first".into(),
                    action: Action::Block,
                    rules: "EXAMPLE.test.\n=example.test\nsub.example.test\nexample.test".into(),
                },
                ListInput {
                    syntax: Default::default(),
                    name: "second".into(),
                    action: Action::Allow,
                    rules: "@@=safe.example.test\n@@example.test\n@@EXAMPLE.test.".into(),
                },
            ];
            FilterSnapshot::compile(&lists, 100, 10_000).unwrap()
        };
        let replacement = FilterSnapshot::compile(
            &[ListInput {
                syntax: Default::default(),
                name: "replacement".into(),
                action: Action::Block,
                rules: "other.test".into(),
            }],
            100,
            10_000,
        )
        .unwrap();
        assert_eq!(snapshot.rules().len(), 5);
        assert_eq!(snapshot.effective_rules(), 2);
        assert_eq!(snapshot.stats[0].duplicates, 1);
        assert_eq!(snapshot.stats[0].redundant, 2);
        assert_eq!(snapshot.stats[1].duplicates, 1);
        assert_eq!(snapshot.stats[1].redundant, 1);
        let decision = snapshot.evaluate("x.example.test");
        assert_eq!(decision.action, Action::Allow);
        let rule = snapshot.rule(decision.rule.unwrap()).unwrap();
        assert_eq!(rule.domain.as_ref(), "example.test");
        assert_eq!(rule.matcher, Matcher::Suffix);
        assert_eq!(
            rule.sources
                .iter()
                .map(|source| (source.list.as_ref(), source.line))
                .collect::<Vec<_>>(),
            [("second", 2), ("second", 3)]
        );
        assert_eq!(replacement.evaluate("x.example.test"), Decision::ALLOW);
        assert_eq!(replacement.evaluate("other.test").action, Action::Block);
        assert!(snapshot.payload_bytes() > replacement.payload_bytes());
        assert_eq!(
            FilterSnapshot::compile(&[], 100, 100)
                .unwrap()
                .payload_bytes(),
            0
        );
    }

    #[test]
    fn compiled_actions_match_reference_across_overlaps() {
        let domains = ["test", "a.test", "b.test", "x.a.test"];
        let queries = [
            "test",
            "a.test",
            "b.test",
            "x.a.test",
            "y.x.a.test",
            "other.test",
            "notatest",
        ];
        // Exhaust all pairs, including equal names, different actions/matchers
        // and suffix subsumption. Duplicate lines exercise shared provenance.
        for first in 0..16 {
            for second in 0..16 {
                let inputs = [first, second].map(|index| {
                    let action = if index & 1 == 0 {
                        Action::Block
                    } else {
                        Action::Allow
                    };
                    let matcher = if index & 2 == 0 {
                        Matcher::Exact
                    } else {
                        Matcher::Suffix
                    };
                    (action, matcher, domains[index / 4])
                });
                let lists = inputs
                    .iter()
                    .enumerate()
                    .map(|(i, (action, matcher, domain))| {
                        let prefix = if *matcher == Matcher::Exact { "=" } else { "" };
                        ListInput {
                            syntax: Default::default(),
                            name: format!("list{i}"),
                            action: *action,
                            rules: format!("{prefix}{domain}\n{prefix}{domain}"),
                        }
                    })
                    .collect::<Vec<_>>();
                let snapshot = FilterSnapshot::compile(&lists, 100, 10_000).unwrap();
                for query in queries {
                    let matches = |action| {
                        inputs.iter().any(|(a, matcher, domain)| {
                            *a == action
                                && (query == *domain
                                    || (*matcher == Matcher::Suffix
                                        && query
                                            .strip_suffix(domain)
                                            .is_some_and(|prefix| prefix.ends_with('.'))))
                        })
                    };
                    let expected = if matches(Action::Allow) {
                        Action::Allow
                    } else if matches(Action::Block) {
                        Action::Block
                    } else {
                        Action::Allow
                    };
                    let decision = snapshot.evaluate(query);
                    assert_eq!(decision.action, expected, "{inputs:?}: {query}");
                    if let Some(id) = decision.rule {
                        let rule = snapshot.rule(id).unwrap();
                        assert_eq!(rule.action, expected);
                        assert_eq!(rule.sources.len(), if first == second { 4 } else { 2 });
                    }
                }
            }
        }
    }
}

mod differential {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// Reference semantics: rules subsumed by a same-action suffix rule (above
    /// them, or at the same name for exact rules) are dropped; then any allow
    /// beats any block, and within an action an exact match beats a suffix
    /// match and nearer suffixes beat farther ones.
    fn reference(
        rules: &[(Action, Matcher, &str)],
        query: &str,
    ) -> Option<(Action, Matcher, String)> {
        let below = |name: &str, ancestor: &str| {
            name.strip_suffix(ancestor)
                .is_some_and(|prefix| prefix.ends_with('.'))
        };
        let effective: Vec<_> = rules
            .iter()
            .filter(|(action, matcher, domain)| {
                !rules.iter().any(|(a, m, d)| {
                    a == action
                        && *m == Matcher::Suffix
                        && (below(domain, d) || (*matcher == Matcher::Exact && domain == d))
                })
            })
            .collect();
        for action in [Action::Allow, Action::Block] {
            if let Some((_, _, domain)) = effective
                .iter()
                .find(|(a, m, d)| *a == action && *m == Matcher::Exact && query == *d)
            {
                return Some((action, Matcher::Exact, (*domain).to_owned()));
            }
            if let Some((_, _, domain)) = effective
                .iter()
                .filter(|(a, m, d)| {
                    *a == action && *m == Matcher::Suffix && (query == *d || below(query, d))
                })
                .max_by_key(|(_, _, d)| d.len())
            {
                return Some((action, Matcher::Suffix, (*domain).to_owned()));
            }
        }
        None
    }

    #[test]
    fn single_walk_matches_reference_on_random_overlapping_rule_sets() {
        let names = [
            "test",
            "a.test",
            "b.a.test",
            "c.b.a.test",
            "x.test",
            "other",
        ];
        let queries = [
            "test",
            "a.test",
            "b.a.test",
            "c.b.a.test",
            "d.c.b.a.test",
            "x.test",
            "y.x.test",
            "other",
            "z.other",
            "unrelated.example",
        ];
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = |bound: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            usize::try_from(seed % bound as u64).unwrap()
        };
        for _ in 0..4000 {
            let count = 1 + next(6);
            let rules: Vec<_> = (0..count)
                .map(|_| {
                    let action = if next(2) == 0 {
                        Action::Allow
                    } else {
                        Action::Block
                    };
                    let matcher = if next(2) == 0 {
                        Matcher::Exact
                    } else {
                        Matcher::Suffix
                    };
                    (action, matcher, names[next(names.len())])
                })
                .collect();
            let lists: Vec<_> = rules
                .iter()
                .enumerate()
                .map(|(index, (action, matcher, domain))| ListInput {
                    syntax: Default::default(),
                    name: format!("list{index}"),
                    action: *action,
                    rules: format!(
                        "{}{domain}",
                        if *matcher == Matcher::Exact { "=" } else { "" }
                    ),
                })
                .collect();
            let snapshot = FilterSnapshot::compile(&lists, 100, 10_000).unwrap();
            for query in queries {
                let decision = snapshot.evaluate(query);
                match reference(&rules, query) {
                    None => assert_eq!(decision, Decision::ALLOW, "{rules:?} {query}"),
                    Some((action, matcher, domain)) => {
                        assert_eq!(decision.action, action, "{rules:?} {query}");
                        assert_eq!(decision.matcher, Some(matcher), "{rules:?} {query}");
                        let rule = snapshot.rule(decision.rule.unwrap()).unwrap();
                        assert_eq!(
                            (rule.action, rule.matcher, rule.domain.as_ref()),
                            (action, matcher, domain.as_str()),
                            "{rules:?} {query}"
                        );
                        assert!(!rule.redundant);
                    }
                }
            }
        }
    }
}

mod escaped_labels {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn escaped_dots_are_not_dns_label_boundaries() {
        let snapshot = FilterSnapshot::compile(
            &[ListInput {
                syntax: Default::default(),
                name: "test".into(),
                action: Action::Block,
                rules: "example.com".into(),
            }],
            10,
            1000,
        )
        .unwrap();
        assert_eq!(
            snapshot.evaluate(r"evil\.example.com").action,
            Action::Allow
        );
        assert_eq!(
            snapshot.evaluate(r"evil\.label.example.com").action,
            Action::Block
        );
        assert_eq!(
            snapshot.evaluate(r"evil\\.example.com").action,
            Action::Block
        );
    }
}
