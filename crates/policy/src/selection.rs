//! Pure client selection and control-plane explanations.
use crate::{Explanation, PolicyError, PolicySnapshot, Selection};
use rustwalld_dns_filter::Decision;
use std::{net::IpAddr, time::Instant};
impl PolicySnapshot {
    pub fn permits(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.config
            .allowed_clients
            .iter()
            .any(|network| network.contains(&ip))
    }
    pub fn select(&self, ip: IpAddr) -> Selection<'_> {
        let ip = ip.to_canonical();
        let binding = match ip {
            IpAddr::V4(ip) => self.ipv4.iter().find_map(|(prefix, map)| {
                let mask = if *prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                map.get(&(u32::from(ip) & mask))
            }),
            IpAddr::V6(ip) => self.ipv6.iter().find_map(|(prefix, map)| {
                let mask = if *prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                map.get(&(u128::from(ip) & mask))
            }),
        };
        Selection {
            policy: &self.policies[binding.map_or(self.default, |b| b.policy)],
            client_name: binding.map(|b| b.name.as_str()),
            network: binding.map(|b| b.network),
        }
    }
    pub fn explain(&self, client: IpAddr, domain: &str) -> Result<Explanation<'_>, PolicyError> {
        let domain = rustwalld_dns_filter::normalize(domain)?;
        let mut explanation = self.explain_normalized(client, &domain);
        if !explanation.rewrite
            && let Some(found) = self
                .select(client)
                .policy
                .temporary_allow(&domain, Instant::now())
        {
            explanation.decision = Decision::ALLOW;
            explanation.rule = None;
            explanation.temporary_exception = Some(found.exception);
        }
        Ok(explanation)
    }
    pub(crate) fn explain_normalized(&self, client: IpAddr, domain: &str) -> Explanation<'_> {
        let selected = self.select(client);
        let policy = selected.policy;
        let rewrite = policy.has_rewrite(domain);
        let decision = if rewrite {
            Decision::ALLOW
        } else {
            policy.filters.evaluate(domain)
        };
        Explanation {
            generation: self.generation,
            client,
            permitted: self.permits(client),
            client_name: selected.client_name,
            network: selected.network,
            binding_metadata: selected.network.and_then(|network| {
                self.metadata
                    .get(&network)
                    .and_then(|index| self.config.bindings[*index].metadata.as_ref())
            }),
            policy: &policy.name,
            decision,
            rule: decision.rule.and_then(|id| policy.filters.rule(id)),
            rewrite,
            upstream: &self.config.upstreams[policy.upstream].name,
            temporary_exception: None,
        }
    }
    pub fn test_assertions(&self) -> Result<(), PolicyError> {
        for assertion in &self.config.assertions {
            if !self.permits(assertion.client) {
                return Err(PolicyError::Assertion(format!(
                    "{} is outside allowed client networks",
                    assertion.client
                )));
            }
            let domain = rustwalld_dns_filter::normalize(&assertion.domain)?;
            let explanation = self.explain_normalized(assertion.client, &domain);
            if explanation.decision.action != assertion.expected {
                return Err(PolicyError::Assertion(format!(
                    "{} + {}: expected {:?}, got {:?}; policy {}, rule {}",
                    assertion.client,
                    domain,
                    assertion.expected,
                    explanation.decision.action,
                    explanation.policy,
                    describe_rule(&explanation)
                )));
            }
        }
        Ok(())
    }
}
/// Bounded rule summary: a heavily duplicated rule can carry millions of sources.
fn describe_rule(explanation: &Explanation<'_>) -> String {
    const SHOWN: usize = 3;
    let Some(rule) = explanation.rule else {
        return if explanation.rewrite {
            "none (local rewrite)".into()
        } else {
            "none (default allow)".into()
        };
    };
    let mut text = format!(
        "{:?} {:?} {:?} from ",
        rule.action, rule.matcher, rule.domain
    );
    for (index, source) in rule.sources.iter().take(SHOWN).enumerate() {
        if index > 0 {
            text.push_str(", ");
        }
        text.push_str(&format!("{}:{}", source.list, source.line));
    }
    if rule.sources.len() > SHOWN {
        text.push_str(&format!(" (+{} more)", rule.sources.len() - SHOWN));
    }
    text
}
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::{Assertion, Binding, PolicyConfig, PolicyConfigSet};
    use rustwalld_dns_filter::{Action, ListInput};
    #[test]
    fn longest_prefix_ipv4_ipv6_and_assertions() {
        let mut config = PolicyConfigSet {
            allowed_clients: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
            ..Default::default()
        };
        config.policies.push(PolicyConfig {
            name: "iot".into(),
            upstream: "default".into(),
            lists: vec![ListInput {
                name: "deny".into(),
                action: Action::Block,
                rules: "ads.test".into(),
            }],
            rewrites: vec![],
            temporary_exceptions: vec![],
        });
        config.bindings = vec![
            Binding {
                network: "10.0.0.0/8".parse().unwrap(),
                policy: "iot".into(),
                name: "iot-net".into(),
                metadata: None,
            },
            Binding {
                network: "10.1.0.1/32".parse().unwrap(),
                policy: "default".into(),
                name: "exception".into(),
                metadata: None,
            },
            Binding {
                network: "2001:db8::/32".parse().unwrap(),
                policy: "iot".into(),
                name: "v6".into(),
                metadata: None,
            },
        ];
        config.assertions.push(Assertion {
            client: "10.0.1.1".parse().unwrap(),
            domain: "ads.test".into(),
            expected: Action::Block,
        });
        let snapshot = PolicySnapshot::compile(config.clone(), 1).unwrap();
        assert_eq!(
            snapshot.select("10.1.0.1".parse().unwrap()).policy.name,
            "default"
        );
        assert_eq!(
            snapshot.select("10.2.0.1".parse().unwrap()).policy.name,
            "iot"
        );
        assert_eq!(
            snapshot.select("2001:db8::1".parse().unwrap()).policy.name,
            "iot"
        );
        assert_eq!(
            snapshot
                .select("::ffff:10.1.0.1".parse().unwrap())
                .policy
                .name,
            "default"
        );
        assert_eq!(
            snapshot
                .select("::ffff:10.2.0.1".parse().unwrap())
                .policy
                .name,
            "iot"
        );
        config.assertions[0].expected = Action::Allow;
        assert!(PolicySnapshot::compile(config, 2).is_err());
    }
    #[test]
    fn explanations_report_admission_and_assertion_failures_are_bounded() {
        let mut config = PolicyConfigSet::default();
        config.policies[0].lists = vec![ListInput {
            name: "deny".into(),
            action: Action::Block,
            rules: "ads.test\n".repeat(1000),
        }];
        let snapshot = PolicySnapshot::compile(config.clone(), 1).unwrap();
        let admitted = snapshot
            .explain("::ffff:127.0.0.1".parse().unwrap(), "x.ads.test")
            .unwrap();
        assert!(admitted.permitted);
        let dropped = snapshot
            .explain("192.0.2.1".parse().unwrap(), "safe.test")
            .unwrap();
        // DNS drops this client; the ALLOW below is only a hypothetical trace.
        assert!(!dropped.permitted);
        assert_eq!(dropped.decision.action, Action::Allow);
        assert_eq!(
            serde_json::to_value(&dropped).unwrap()["permitted"],
            serde_json::Value::Bool(false)
        );
        config.assertions.push(Assertion {
            client: "127.0.0.1".parse().unwrap(),
            domain: "x.ads.test".into(),
            expected: Action::Allow,
        });
        let message = PolicySnapshot::compile(config, 2).unwrap_err().to_string();
        assert_eq!(
            message,
            "required policy assertion failed: 127.0.0.1 + x.ads.test: expected Allow, \
             got Block; policy default, rule Block Suffix \"ads.test\" from deny:1, deny:2, \
             deny:3 (+997 more)"
        );
    }
}
