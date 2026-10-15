#![no_main]
use libfuzzer_sys::fuzz_target;
use rustwalld_dns_filter::{Action, FilterSnapshot, ListInput, ParallelCompiler, RuleSyntax, Matcher};
use std::sync::OnceLock;
// Test-only owned pool, reused across fuzz inputs; no global Rayon pool.
static COMPILER: OnceLock<ParallelCompiler> = OnceLock::new();
fuzz_target!(|input: &str| {
    const MAX_BYTES: usize = 512 * 1024;
    if input.len() > MAX_BYTES {
        return;
    }
    let compiler = COMPILER.get_or_init(|| ParallelCompiler::new(2).unwrap());
    // Odd lines feed an allowlist so allow and block rules share index entries.
    let (mut block, mut allow) = (String::new(), String::new());
    for (index, line) in input.lines().enumerate() {
        let list = if index % 2 == 0 { &mut block } else { &mut allow };
        list.push_str(line);
        list.push('\n');
    }
    let lists = [
        ListInput { syntax: match input.as_bytes().first().copied().unwrap_or(0) & 28 { 0 => RuleSyntax::Native, 4 => RuleSyntax::Adguard, 8 => RuleSyntax::AdguardV2, 12 => RuleSyntax::AdguardV3, 16 => RuleSyntax::AdguardV4, 20 => RuleSyntax::AdguardV5, _=>RuleSyntax::AdguardV6 },
            name: "fuzz".into(),
            action: Action::Block,
            rules: block,
        },
        ListInput { syntax: match input.as_bytes().first().copied().unwrap_or(0) & 28 { 0 => RuleSyntax::Native, 4 => RuleSyntax::Adguard, 8 => RuleSyntax::AdguardV2, 12 => RuleSyntax::AdguardV3, 16 => RuleSyntax::AdguardV4, 20 => RuleSyntax::AdguardV5, _=>RuleSyntax::AdguardV6 },
            name: "allow".into(),
            action: Action::Allow,
            rules: allow,
        },
    ];
    let limit = [0, 1, 256, 40000][usize::from(input.as_bytes().first().copied().unwrap_or(0) & 3)];
    match (
        FilterSnapshot::compile(&lists, limit, MAX_BYTES),
        compiler.compile(&lists, limit, MAX_BYTES),
    ) {
        (Ok(serial), Ok(parallel)) => {
            assert_eq!(
                serde_json::to_vec(serial.rules()).unwrap(),
                serde_json::to_vec(parallel.rules()).unwrap()
            );
            assert_eq!(
                serde_json::to_vec(&serial.stats).unwrap(),
                serde_json::to_vec(&parallel.stats).unwrap()
            );
            assert_eq!(serial.cancellation_targets(), parallel.cancellation_targets());
            assert_eq!(serde_json::to_vec(serial.cancellations()).unwrap(), serde_json::to_vec(parallel.cancellations()).unwrap());
            assert!(serial.cancellations().len() <= 200);
            assert!(serial.cancellations().iter().all(|report| report.directive_sources.len() <= 5 && report.disabled_sources.len() <= 5));
            assert_eq!(serial.payload_bytes(), parallel.payload_bytes());
            assert_eq!(serial.effective_rules(), parallel.effective_rules());
            assert_eq!(serial.has_tag_rules(),parallel.has_tag_rules());
            assert_eq!(serial.has_client_rules(),parallel.has_client_rules());
            assert!(!serial.has_tag_rules() || serial.has_client_rules());
            for rule in serial.rules() {
                for kind in [1, 5, 28, 65] {
                    assert_eq!(serial.evaluate_type(&rule.domain, kind), parallel.evaluate_type(&rule.domain, kind));
                    assert_eq!(serial.evaluate_value(&rule.domain, kind), parallel.evaluate_value(&rule.domain, kind));
                }
                for client in [rustwalld_dns_filter::ClientContext{ip:"192.0.2.1".parse().unwrap(),name:Some("Kids")},rustwalld_dns_filter::ClientContext{ip:"2001:db8::1".parse().unwrap(),name:None}] {
                    assert_eq!(serial.client_partition(client),parallel.client_partition(client));
                    for tags in [rustwalld_dns_filter::ClientTags::default(),rustwalld_dns_filter::ClientTags::compile(["device_phone","user_child"]).unwrap()] {
                        let ctx=client.with_tags(tags);
                        assert_eq!(serial.context_partition(ctx),parallel.context_partition(ctx));
                        assert_eq!(serial.evaluate_client(&rule.domain,1,ctx),parallel.evaluate_client(&rule.domain,1,ctx));
                        assert_eq!(serial.evaluate_value_client(&rule.domain,1,ctx),parallel.evaluate_value_client(&rule.domain,1,ctx));
                    }
                    assert_eq!(serial.evaluate_client(&rule.domain,1,client),parallel.evaluate_client(&rule.domain,1,client));
                    assert_eq!(serial.evaluate_value_client(&rule.domain,1,client),parallel.evaluate_value_client(&rule.domain,1,client));
                }
                let decision = serial.evaluate(&rule.domain);
                assert_eq!(decision, parallel.evaluate(&rule.domain));
                // Allow precedence: a name covered by an allow rule never blocks.
                if rule.action == Action::Allow && rule.matcher != Matcher::Regex && rule.scope.is_none() {
                    assert_eq!(decision.action, Action::Allow);
                }
                if let Some(id) = decision.rule {
                    let decided = serial.rule(id).unwrap();
                    assert_eq!(decided.action, decision.action);
                    assert!(!decided.redundant);
                }
                assert_eq!(
                    serial.evaluate(&format!("child.{}", rule.domain)),
                    parallel.evaluate(&format!("child.{}", rule.domain))
                );
            }
        }
        (Err(serial), Err(parallel)) => assert_eq!(serial.to_string(), parallel.to_string()),
        _ => panic!("sequential/parallel compilation diverged"),
    }
});
