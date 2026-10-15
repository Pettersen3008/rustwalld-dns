//! Pure client selection and control-plane explanations.
use crate::{Explanation, PolicyError, PolicySnapshot, Selection};
use hickory_proto::rr::RecordType;
use rustwalld_dns_filter::Decision;
use std::{net::IpAddr, time::Instant};
impl PolicySnapshot {
    /// Actual source address and explicit binding name from this generation.
    pub fn client_context(&self, client: IpAddr) -> rustwalld_dns_filter::ClientContext<'_> {
        rustwalld_dns_filter::ClientContext {
            ip: client.to_canonical(),
            name: self.select(client).client_name,
        }
    }
    /// Explicit identity and filtering tags from this pinned generation.
    pub fn filter_context(&self, client: IpAddr) -> rustwalld_dns_filter::FilterContext<'_> {
        let selected = self.select(client);
        rustwalld_dns_filter::ClientContext {
            ip: client.to_canonical(),
            name: selected.client_name,
        }
        .with_tags(selected.filter_tags)
    }
    /// Whether `ip` is inside `allowed_clients`; DNS drops other clients.
    pub fn permits(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.config
            .allowed_clients
            .iter()
            .any(|network| network.contains(&ip))
    }
    /// The policy for `ip`: the longest matching binding, or the default policy.
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
            filter_tags: binding.map_or(rustwalld_dns_filter::ClientTags::default(), |b| {
                b.filter_tags
            }),
        }
    }
    /// How the current generation would answer `domain` for `client`, including
    /// temporary exceptions. Check `permitted`: DNS drops clients outside
    /// `allowed_clients`.
    ///
    /// # Errors
    ///
    /// [`PolicyError::Filter`] when `domain` is not a valid name.
    pub fn explain(&self, client: IpAddr, domain: &str) -> Result<Explanation<'_>, PolicyError> {
        self.explain_at(client, domain, std::time::SystemTime::now())
    }
    /// Explain current policy using an explicit trusted wall-clock instant.
    pub fn explain_at(
        &self,
        client: IpAddr,
        domain: &str,
        now: std::time::SystemTime,
    ) -> Result<Explanation<'_>, PolicyError> {
        self.explain_query_at(client, domain, RecordType::A, now)
    }
    /// Explain the actual question type, including local/provider alias routing.
    ///
    /// # Errors
    /// Returns [`PolicyError`] when the domain cannot be normalized.
    pub fn explain_query(
        &self,
        client: IpAddr,
        domain: &str,
        kind: RecordType,
    ) -> Result<Explanation<'_>, PolicyError> {
        self.explain_query_at(client, domain, kind, std::time::SystemTime::now())
    }
    /// Explain a typed question at an explicit trusted wall-clock instant.
    ///
    /// # Errors
    /// Returns [`PolicyError`] when the domain cannot be normalized.
    pub fn explain_query_at(
        &self,
        client: IpAddr,
        domain: &str,
        kind: RecordType,
        now: std::time::SystemTime,
    ) -> Result<Explanation<'_>, PolicyError> {
        let domain = rustwalld_dns_filter::normalize(domain)?;
        let mut explanation = self.explain_normalized_query(client, &domain, kind);
        let policy = self.select(client).policy;
        if let Some(evaluation) = policy.service_schedule_at(now) {
            let filters = policy.filters_for_services(evaluation.state.blocking());
            if !explanation.rewrite {
                explanation.decision =
                    filters.evaluate_client(&domain, u16::from(kind), self.filter_context(client));
                explanation.rule = explanation.decision.rule.and_then(|id| filters.rule(id));
                explanation.safe_search =
                    if explanation.decision.action == rustwalld_dns_filter::Action::Allow {
                        policy.safe_search_match(&domain)
                    } else {
                        None
                    };
                let question = hickory_proto::rr::Name::from_ascii(format!("{domain}."))
                    .map_err(|_| crate::PolicyError::Invalid("invalid explanation name".into()))?;
                let target = policy
                    .safe_search_answer(&domain, kind)
                    .and_then(|(_, target)| target)
                    .filter(|_| explanation.decision.action == rustwalld_dns_filter::Action::Allow)
                    .unwrap_or(&question);
                explanation.upstream =
                    &self.config.upstreams[policy.upstream_for_query(target, kind)].name;
            }
            explanation.service_schedule = self
                .config
                .policies
                .get(policy.id())
                .and_then(|value| value.blocked_services.as_ref())
                .and_then(|value| value.schedule.as_ref())
                .map(|schedule| crate::ScheduleExplanation {
                    time_zone: &schedule.time_zone,
                    state: evaluation.state,
                    ttl_cap: evaluation.ttl_cap,
                });
        }
        if !explanation.rewrite
            && let Some(found) =
                self.select(client)
                    .policy
                    .temporary_allow_for(&domain, client, Instant::now())
        {
            explanation.decision = Decision::ALLOW;
            explanation.rule = None;
            explanation.temporary_exception = Some(found.exception);
            let policy = self.select(client).policy;
            explanation.safe_search = policy.safe_search_match(&domain);
            if let Some((_, Some(target))) = policy.safe_search_answer(&domain, kind) {
                explanation.upstream =
                    &self.config.upstreams[policy.upstream_for_query(target, kind)].name;
            }
        }
        Ok(explanation)
    }
    /// Inspect a response subject with its actual RR type alongside the original question.
    /// Original-question allows, local rewrites and live exceptions retain their exemptions.
    /// # Errors
    /// Returns a policy error for invalid question names or response values/types.
    pub fn explain_answer_query(
        &self,
        client: IpAddr,
        question: &str,
        qtype: RecordType,
        value: &str,
        rrtype: u16,
    ) -> Result<Explanation<'_>, PolicyError> {
        let now = std::time::SystemTime::now();
        let mut explanation = self.explain_query_at(client, question, qtype, now)?;
        let value = match rrtype {
            5 => {
                let name = hickory_proto::rr::Name::from_ascii(value)
                    .map_err(|_| PolicyError::Invalid("invalid canonical response name".into()))?;
                let mut name = name.to_ascii();
                name.make_ascii_lowercase();
                if name.ends_with('.') {
                    name.pop();
                }
                name
            }
            1 | 28 | 65 => {
                let address = value
                    .parse::<std::net::IpAddr>()
                    .map_err(|_| PolicyError::Invalid("invalid response address".into()))?;
                if rrtype == 1 && !address.to_canonical().is_ipv4() {
                    return Err(PolicyError::Invalid(
                        "response address/type mismatch".into(),
                    ));
                }
                address.to_canonical().to_string()
            }
            _ => {
                return Err(PolicyError::Invalid(
                    "unsupported response subject type".into(),
                ));
            }
        };
        if explanation.decision != Decision::ALLOW
            || explanation.rewrite
            || explanation.temporary_exception.is_some()
        {
            return Ok(explanation);
        }
        let policy = self.select(client).policy;
        let filters = policy.filters_for_services(
            policy
                .service_schedule_at(now)
                .is_none_or(|state| state.state.blocking()),
        );
        explanation.decision = if rrtype == 5 {
            filters.evaluate_client(
                &value,
                if filters.typed_responses() {
                    5
                } else {
                    u16::from(qtype)
                },
                self.filter_context(client),
            )
        } else {
            filters.evaluate_value_client(&value, rrtype, self.filter_context(client))
        };
        explanation.rule = explanation.decision.rule.and_then(|id| filters.rule(id));
        Ok(explanation)
    }
    pub(crate) fn explain_normalized_query(
        &self,
        client: IpAddr,
        domain: &str,
        kind: RecordType,
    ) -> Explanation<'_> {
        let selected = self.select(client);
        let policy = selected.policy;
        let rewrite = policy.has_rewrite_for(domain, kind);
        let decision = if rewrite {
            Decision::ALLOW
        } else {
            policy
                .filters
                .evaluate_client(domain, u16::from(kind), self.filter_context(client))
        };
        Explanation {
            filter_tags: selected.filter_tags.names().collect(),
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
            service_schedule: None,
            safe_search: if !rewrite && decision.action == rustwalld_dns_filter::Action::Allow {
                policy.safe_search_match(domain)
            } else {
                None
            },
            upstream: &self.config.upstreams[policy
                .rewrite_forward(domain, kind)
                .map(|(name, _)| policy.upstream_for_query(name, kind))
                .or_else(|| {
                    (decision.action == rustwalld_dns_filter::Action::Allow)
                        .then(|| policy.safe_search_answer(domain, kind))
                        .flatten()
                        .and_then(|(_, target)| {
                            target.map(|name| policy.upstream_for_query(name, kind))
                        })
                })
                .or_else(|| {
                    hickory_proto::rr::Name::from_ascii(format!("{domain}."))
                        .ok()
                        .map(|name| policy.upstream_for_query(&name, kind))
                })
                .unwrap_or(policy.upstream)]
            .name,
            temporary_exception: None,
        }
    }
    /// Check every required assertion against this snapshot.
    ///
    /// # Errors
    ///
    /// [`PolicyError::Assertion`] for the first failing assertion.
    pub fn test_assertions(&self) -> Result<(), PolicyError> {
        for assertion in &self.config.assertions {
            if !self.permits(assertion.client) {
                return Err(PolicyError::Assertion(format!(
                    "{} is outside allowed client networks",
                    assertion.client
                )));
            }
            let domain = rustwalld_dns_filter::normalize(&assertion.domain)?;
            let explanation = self.explain_normalized_query(
                assertion.client,
                &domain,
                RecordType::from(assertion.qtype),
            );
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
    if let Some(domains) = rule.denyallow() {
        text.push_str("; excluded from this rule: ");
        text.push_str(
            &domains
                .domains()
                .iter()
                .map(|name| name.as_ref())
                .collect::<Vec<_>>()
                .join(", "),
        );
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
            dns_records: vec![],
            routes: vec![],
            ds_routing: Default::default(),
            block_mode: Default::default(),
            safe_search: None,
            blocked_services: None,
            name: "iot".into(),
            upstream: "default".into(),
            lists: vec![ListInput {
                syntax: Default::default(),
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
                filter_tags: Vec::new(),
                metadata: None,
            },
            Binding {
                network: "10.1.0.1/32".parse().unwrap(),
                policy: "default".into(),
                name: "exception".into(),
                filter_tags: Vec::new(),
                metadata: None,
            },
            Binding {
                network: "2001:db8::/32".parse().unwrap(),
                policy: "iot".into(),
                name: "v6".into(),
                filter_tags: Vec::new(),
                metadata: None,
            },
        ];
        config.assertions.push(Assertion {
            qtype: 1,
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
            syntax: Default::default(),
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
            qtype: 1,
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
