//! Control-plane diagnostics only; no unchecked snapshot leaves this module.
use crate::{Assertion, PolicyConfigSet, PolicyError, PolicySnapshot};
use filtering::{Decision, Matcher, Source};
use ipnet::IpNet;
use serde::Serialize;

const MAX_REPORTED_SOURCES: usize = 16;

#[derive(Debug, Serialize)]
pub struct CheckReport {
    pub basis: &'static str,
    pub valid: bool,
    pub assertions: usize,
    pub failed: usize,
    pub policies: usize,
    pub results: Vec<AssertionResult>,
    pub list_stats: Vec<PolicyListStats>,
}

#[derive(Debug, Serialize)]
pub struct PolicyListStats {
    pub policy: String,
    pub lists: Vec<filtering::ListStats>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::{Binding, PolicyConfig, Rewrite};
    use filtering::{Action, ListInput};

    #[test]
    fn complete_reports_agree_with_strict_compilation_and_effective_policies() {
        let mut config = PolicyConfigSet {
            allowed_clients: vec![
                "127.0.0.0/8".parse().unwrap(),
                "2001:db8::/32".parse().unwrap(),
            ],
            ..Default::default()
        };
        config.policies[0].lists = vec![
            ListInput {
                name: "deny".into(),
                action: Action::Block,
                rules: "=adverts.test\ntracking.test\n=bücher.test\nnas.test".into(),
            },
            ListInput {
                name: "allow".into(),
                action: Action::Allow,
                rules: "=work.tracking.test".into(),
            },
        ];
        config.policies[0].rewrites.push(Rewrite {
            domain: "nas.test".into(),
            addresses: vec!["192.0.2.10".parse().unwrap()],
            ttl: 60,
        });
        config.policies.push(PolicyConfig {
            name: "device".into(),
            upstream: "default".into(),
            lists: vec![],
            rewrites: vec![],
            temporary_exceptions: vec![],
        });
        config.bindings = vec![
            Binding {
                name: "Loopback".into(),
                network: "127.0.0.0/8".parse().unwrap(),
                policy: "default".into(),
                metadata: None,
            },
            Binding {
                name: "Laptop".into(),
                network: "127.0.0.2/32".parse().unwrap(),
                policy: "device".into(),
                metadata: None,
            },
            Binding {
                name: "IPv6".into(),
                network: "2001:db8::/32".parse().unwrap(),
                policy: "default".into(),
                metadata: None,
            },
        ];
        config.assertions = [
            ("127.0.0.1", "adverts.test", Action::Allow),
            ("127.0.0.1", "x.tracking.test", Action::Allow),
            ("127.0.0.1", "work.tracking.test", Action::Allow),
            ("127.0.0.1", "nas.test", Action::Allow),
            ("192.0.2.1", "allowed.test", Action::Allow),
            ("127.0.0.1", "invalid..test", Action::Allow),
            ("::ffff:127.0.0.2", "adverts.test", Action::Allow),
            ("2001:db8::1", "x.tracking.test", Action::Block),
            ("127.0.0.1", "BÜCHER.TEST.", Action::Block),
            ("127.0.0.1", "allowed.test", Action::Allow),
        ]
        .into_iter()
        .map(|(client, domain, expected)| Assertion {
            client: client.parse().unwrap(),
            domain: domain.into(),
            expected,
        })
        .collect();
        let report = PolicySnapshot::check(config.clone()).unwrap();
        assert!(!report.valid);
        assert_eq!(report.failed, 4);
        assert_eq!(report.assertions, 10);
        assert_eq!(report.policies, 2);
        let trace = |index: usize| report.results[index].trace.as_ref().unwrap();
        assert_eq!(trace(0).rule.as_ref().unwrap().matcher, Matcher::Exact);
        assert_eq!(trace(1).rule.as_ref().unwrap().matcher, Matcher::Suffix);
        assert_eq!(trace(1).rule.as_ref().unwrap().sources[0].line, 2);
        assert_eq!(
            trace(2).rule.as_ref().unwrap().sources[0].list.as_ref(),
            "allow"
        );
        assert!(trace(3).rewrite);
        assert!(trace(3).rule.is_none());
        assert!(!report.results[4].permitted);
        assert!(matches!(
            report.results[4].failure,
            Some(AssertionFailure::ClientNotPermitted)
        ));
        assert!(matches!(
            report.results[5].failure,
            Some(AssertionFailure::InvalidDomain)
        ));
        assert!(report.results[5].trace.is_none());
        assert_eq!(trace(6).policy, "device");
        assert_eq!(trace(6).client_name.as_deref(), Some("Laptop"));
        assert_eq!(trace(6).network.unwrap().to_string(), "127.0.0.2/32");
        assert_eq!(trace(7).client_name.as_deref(), Some("IPv6"));
        assert_eq!(trace(8).domain, "xn--bcher-kva.test");
        assert!(trace(9).rule.is_none());
        assert!(PolicySnapshot::compile(config.clone(), 1).is_err());
        for result in report.results {
            let mut single = config.clone();
            single.assertions = vec![result.assertion];
            assert_eq!(
                PolicySnapshot::compile(single, 2).is_ok(),
                result.failure.is_none()
            );
        }
    }

    #[test]
    fn provenance_is_capped_and_structural_or_case_limits_reject_checking() {
        let mut config = PolicyConfigSet::default();
        config.policies[0].lists.push(ListInput {
            name: "duplicates".into(),
            action: Action::Block,
            rules: "ads.test\n".repeat(100),
        });
        config.assertions = vec![
            Assertion {
                client: "127.0.0.1".parse().unwrap(),
                domain: "ads.test".into(),
                expected: Action::Block
            };
            2
        ];
        let report = PolicySnapshot::check(config.clone()).unwrap();
        assert!(report.valid);
        for result in report.results {
            let rule = result.trace.unwrap().rule.unwrap();
            assert_eq!(rule.sources.len(), MAX_REPORTED_SOURCES);
            assert_eq!(rule.total_sources, 100);
            assert_eq!(rule.sources[15].line, 16);
        }
        config.assertions = vec![config.assertions[0].clone(); 10_001];
        assert!(PolicySnapshot::check(config.clone()).is_err());
        config.assertions.clear();
        config.policies[0].upstream = "missing".into();
        assert!(PolicySnapshot::check(config).is_err());
        let report = PolicySnapshot::check(PolicyConfigSet::default()).unwrap();
        assert!(report.valid);
        assert_eq!(report.assertions, 0);
        assert_eq!(report.failed, 0);
    }
}

#[derive(Debug, Serialize)]
pub struct AssertionResult {
    pub assertion: Assertion,
    pub permitted: bool,
    pub trace: Option<AssertionTrace>,
    pub failure: Option<AssertionFailure>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AssertionFailure {
    ClientNotPermitted,
    InvalidDomain,
    UnexpectedDecision,
}

#[derive(Debug, Serialize)]
pub struct AssertionTrace {
    pub domain: String,
    pub client_name: Option<String>,
    pub network: Option<IpNet>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding_metadata: Option<crate::BindingMetadata>,
    pub policy: String,
    pub decision: Decision,
    pub rewrite: bool,
    pub upstream: String,
    pub rule: Option<MatchedRule>,
}

#[derive(Debug, Serialize)]
pub struct MatchedRule {
    pub domain: String,
    pub matcher: Matcher,
    pub sources: Vec<Source>,
    pub total_sources: usize,
}

impl PolicySnapshot {
    /// Compile and check all assertions without returning a publishable snapshot.
    /// No listeners, database, executor or upstream exchange are created here.
    pub fn check(config: PolicyConfigSet) -> Result<CheckReport, PolicyError> {
        let snapshot = Self::build(config, 1)?;
        let results: Vec<_> = snapshot
            .config
            .assertions
            .iter()
            .map(|assertion| snapshot.check_assertion(assertion))
            .collect();
        let failed = results
            .iter()
            .filter(|result| result.failure.is_some())
            .count();
        Ok(CheckReport {
            basis: "permanent_policy",
            valid: failed == 0,
            assertions: results.len(),
            failed,
            policies: snapshot.policies.len(),
            results,
            list_stats: snapshot
                .policies
                .iter()
                .map(|policy| PolicyListStats {
                    policy: policy.name.clone(),
                    lists: policy.filters.stats.clone(),
                })
                .collect(),
        })
    }

    fn check_assertion(&self, assertion: &Assertion) -> AssertionResult {
        let permitted = self.permits(assertion.client);
        let Ok(domain) = filtering::normalize(&assertion.domain) else {
            return AssertionResult {
                assertion: assertion.clone(),
                permitted,
                trace: None,
                failure: Some(AssertionFailure::InvalidDomain),
            };
        };
        let explanation = self.explain_normalized(assertion.client, &domain);
        let failure = if !permitted {
            Some(AssertionFailure::ClientNotPermitted)
        } else if explanation.decision.action != assertion.expected {
            Some(AssertionFailure::UnexpectedDecision)
        } else {
            None
        };
        AssertionResult {
            assertion: assertion.clone(),
            permitted,
            trace: Some(AssertionTrace {
                domain,
                client_name: explanation.client_name.map(str::to_owned),
                network: explanation.network,
                binding_metadata: explanation.binding_metadata.cloned(),
                policy: explanation.policy.to_owned(),
                decision: explanation.decision,
                rewrite: explanation.rewrite,
                upstream: explanation.upstream.to_owned(),
                rule: explanation.rule.map(|rule| MatchedRule {
                    domain: rule.domain.to_string(),
                    matcher: rule.matcher,
                    sources: rule
                        .sources
                        .iter()
                        .take(MAX_REPORTED_SOURCES)
                        .cloned()
                        .collect(),
                    total_sources: rule.sources.len(),
                }),
            }),
            failure,
        }
    }
}
