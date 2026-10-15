//! Bounded filtering of the alias chain reachable from the original question.
use hickory_proto::{
    op::Message,
    rr::{DNSClass, Name, RData},
};
use rustwalld_dns_filter::{Action, Decision, FilterSnapshot};

pub(crate) enum Inspection {
    Clean,
    Blocked {
        decision: Decision,
        domain: String,
        kind: u16,
    },
    Invalid,
}

/// Only answer-section IN CNAMEs whose owner is reachable are relevant. Unrelated
/// records cannot manufacture a policy decision. Names retain Hickory's escaped
/// label boundaries; normalization/parsing of filter input never runs here.
pub(crate) fn inspect_client(
    request: &Message,
    response: &Message,
    filters: &FilterSnapshot,
    exempt: bool,
    client: Option<rustwalld_dns_filter::FilterContext<'_>>,
) -> Inspection {
    let Some(question) = request.queries.first() else {
        return Inspection::Invalid;
    };
    let mut current = question.name();
    let mut visited: [Option<&Name>; 17] = [None; 17];
    visited[0] = Some(current);
    let mut checks = 0usize;
    let values_active = !exempt
        && client.map_or_else(
            || filters.has_value_rules(),
            |client| filters.has_value_rules_for_client(client),
        );
    for depth in 0..=16 {
        let mut target = None;
        for record in &response.answers {
            if record.dns_class != DNSClass::IN || &record.name != current {
                continue;
            }
            if let RData::CNAME(alias) = &record.data {
                if target.is_some_and(|name| name != &alias.0) {
                    return Inspection::Invalid;
                }
                target = Some(&alias.0);
            }
        }
        let Some(next) = target else {
            if values_active
                && let Some(result) =
                    inspect_values(response, current, filters, &mut checks, client)
            {
                return result;
            }
            return Inspection::Clean;
        };
        if depth == 16 || visited[..=depth].contains(&Some(next)) {
            return Inspection::Invalid;
        }
        if values_active
            && let Some(result) = inspect_values(response, current, filters, &mut checks, client)
        {
            return result;
        }
        if !exempt {
            let mut domain = next.to_ascii();
            domain.make_ascii_lowercase();
            if domain.ends_with('.') {
                domain.pop();
            }
            let kind = if filters.typed_responses() {
                5
            } else {
                u16::from(question.query_type())
            };
            let decision = client.map_or_else(
                || filters.evaluate_type(&domain, kind),
                |client| filters.evaluate_client(&domain, kind, client),
            );
            if decision.action == Action::Block {
                return Inspection::Blocked {
                    decision,
                    domain,
                    kind: 5,
                };
            }
        }
        current = next;
        visited[depth + 1] = Some(current);
    }
    Inspection::Invalid
}

fn inspect_values(
    response: &Message,
    owner: &Name,
    filters: &FilterSnapshot,
    checks: &mut usize,
    client: Option<rustwalld_dns_filter::FilterContext<'_>>,
) -> Option<Inspection> {
    use hickory_proto::rr::rdata::svcb::SvcParamValue;
    let mut inspect = |value: String, kind: u16| {
        if *checks == 256 {
            return Some(Inspection::Invalid);
        }
        *checks += 1;
        let decision = client.map_or_else(
            || filters.evaluate_value(&value, kind),
            |client| filters.evaluate_value_client(&value, kind, client),
        );
        (decision.action == Action::Block).then_some(Inspection::Blocked {
            decision,
            domain: value,
            kind,
        })
    };
    for record in &response.answers {
        if record.dns_class != DNSClass::IN || &record.name != owner {
            continue;
        }
        match &record.data {
            RData::A(address) => {
                if let Some(result) = inspect(address.0.to_string(), 1) {
                    return Some(result);
                }
            }
            RData::AAAA(address) => {
                if let Some(result) = inspect(
                    std::net::IpAddr::V6(address.0).to_canonical().to_string(),
                    28,
                ) {
                    return Some(result);
                }
            }
            RData::HTTPS(data) => {
                for (_, value) in &data.svc_params {
                    match value {
                        SvcParamValue::Ipv4Hint(addresses) => {
                            for address in &addresses.0 {
                                if let Some(result) = inspect(address.to_string(), 65) {
                                    return Some(result);
                                }
                            }
                        }
                        SvcParamValue::Ipv6Hint(addresses) => {
                            for address in &addresses.0 {
                                if let Some(result) = inspect(
                                    std::net::IpAddr::V6(address.0).to_canonical().to_string(),
                                    65,
                                ) {
                                    return Some(result);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
fn inspect(
    request: &Message,
    response: &Message,
    filters: &FilterSnapshot,
    exempt: bool,
) -> Inspection {
    inspect_client(request, response, filters, exempt, None)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use hickory_proto::{
        op::{Query, ResponseCode},
        rr::{Record, RecordType, rdata::CNAME},
    };
    use rustwalld_dns_filter::ListInput;
    fn fixtures() -> (Message, Message, FilterSnapshot) {
        let mut query = Message::new(
            1,
            hickory_proto::op::MessageType::Query,
            hickory_proto::op::OpCode::Query,
        );
        query.add_query(Query::query(
            Name::from_ascii("alias.test.").unwrap(),
            RecordType::A,
        ));
        let response = crate::reply(&query, ResponseCode::NoError);
        let filters = FilterSnapshot::compile(
            &[ListInput {
                syntax: Default::default(),
                name: "deny".into(),
                action: Action::Block,
                rules: "blocked.test\n@@=safe.blocked.test".into(),
            }],
            100,
            10000,
        )
        .unwrap();
        (query, response, filters)
    }
    fn alias(response: &mut Message, owner: &str, target: &str) {
        response.add_answer(Record::from_rdata(
            Name::from_ascii(owner).unwrap(),
            60,
            RData::CNAME(CNAME(Name::from_ascii(target).unwrap())),
        ));
    }
    #[test]
    fn reachable_chain_allow_precedence_and_unrelated_records() {
        let (query, mut response, filters) = fixtures();
        alias(&mut response, "unrelated.test.", "blocked.test.");
        assert!(matches!(
            inspect(&query, &response, &filters, false),
            Inspection::Clean
        ));
        alias(&mut response, "ALIAS.test.", "middle.test.");
        alias(&mut response, "middle.test.", "safe.blocked.test.");
        assert!(matches!(
            inspect(&query, &response, &filters, false),
            Inspection::Clean
        ));
        alias(&mut response, "safe.blocked.test.", "x.blocked.test.");
        let Inspection::Blocked {
            decision, domain, ..
        } = inspect(&query, &response, &filters, false)
        else {
            panic!("missing reachable block")
        };
        assert_eq!(domain, "x.blocked.test");
        assert_eq!(
            filters.rule(decision.rule.unwrap()).unwrap().sources[0]
                .list
                .as_ref(),
            "deny"
        );
        assert!(matches!(
            inspect(&query, &response, &filters, true),
            Inspection::Clean
        ));
    }
    #[test]
    fn loops_conflicts_and_chain_bound_fail_even_when_exempt() {
        let (query, mut response, filters) = fixtures();
        alias(&mut response, "alias.test.", "middle.test.");
        alias(&mut response, "middle.test.", "alias.test.");
        assert!(matches!(
            inspect(&query, &response, &filters, true),
            Inspection::Invalid
        ));
        response.answers.clear();
        alias(&mut response, "alias.test.", "one.test.");
        alias(&mut response, "alias.test.", "two.test.");
        assert!(matches!(
            inspect(&query, &response, &filters, true),
            Inspection::Invalid
        ));
        response.answers.clear();
        alias(&mut response, "alias.test.", "n0.test.");
        for n in 0..15 {
            alias(
                &mut response,
                &format!("n{n}.test."),
                &format!("n{}.test.", n + 1),
            );
        }
        assert!(matches!(
            inspect(&query, &response, &filters, true),
            Inspection::Clean
        ));
        alias(&mut response, "n15.test.", "n16.test.");
        assert!(matches!(
            inspect(&query, &response, &filters, true),
            Inspection::Invalid
        ));
    }
}

#[cfg(test)]
mod typed_tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use hickory_proto::{
        op::Query,
        rr::{
            Record, RecordType,
            rdata::{
                A, AAAA, CNAME, HTTPS, SVCB,
                svcb::{IpHint, SvcParamKey, SvcParamValue},
            },
        },
    };
    use rustwalld_dns_filter::{ListInput, RuleSyntax};
    fn filters(rules: &str) -> FilterSnapshot {
        FilterSnapshot::compile(
            &[ListInput {
                name: "v4".into(),
                action: Action::Block,
                syntax: RuleSyntax::AdguardV4,
                rules: rules.into(),
            }],
            1000,
            100000,
        )
        .unwrap()
    }
    fn messages() -> (Message, Message) {
        let mut request = Message::query();
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(
            Name::from_ascii("alias.test.").unwrap(),
            RecordType::A,
        ));
        let response = crate::reply(&request, hickory_proto::op::ResponseCode::NoError);
        (request, response)
    }
    fn record(response: &mut Message, owner: &str, data: RData) {
        response.add_answer(Record::from_rdata(
            Name::from_ascii(owner).unwrap(),
            60,
            data,
        ));
    }
    #[test]
    fn source_negative_cname_example_does_not_filter_the_final_a_owner() {
        let (request, mut response) = messages();
        record(
            &mut response,
            "alias.test.",
            RData::CNAME(CNAME(Name::from_ascii("canon.test.").unwrap())),
        );
        record(
            &mut response,
            "canon.test.",
            RData::A(A("192.0.2.1".parse().unwrap())),
        );
        assert!(matches!(
            inspect(
                &request,
                &response,
                &filters("||canon.test^$dnstype=~CNAME"),
                false
            ),
            Inspection::Clean
        ));
        let Inspection::Blocked { domain, kind, .. } = inspect(
            &request,
            &response,
            &filters("||canon.test^$dnstype=CNAME"),
            false,
        ) else {
            panic!("missing typed alias block")
        };
        assert_eq!(domain, "canon.test");
        assert_eq!(kind, 5);
    }
    #[test]
    fn ip_and_https_hint_types_are_actual_record_types_and_reachable_only() {
        let (request, mut response) = messages();
        record(
            &mut response,
            "unrelated.test.",
            RData::A(A("192.0.2.1".parse().unwrap())),
        );
        let policy = filters("/^192\\.0\\.2\\.1$/$dnstype=A\n/^2001:db8::1$/$dnstype=AAAA");
        assert!(matches!(
            inspect(&request, &response, &policy, false),
            Inspection::Clean
        ));
        record(
            &mut response,
            "alias.test.",
            RData::AAAA(AAAA("2001:db8::1".parse().unwrap())),
        );
        let Inspection::Blocked { domain, kind, .. } = inspect(&request, &response, &policy, false)
        else {
            panic!("missing AAAA value block")
        };
        assert_eq!(domain, "2001:db8::1");
        assert_eq!(kind, 28);
        assert!(matches!(
            inspect(&request, &response, &policy, true),
            Inspection::Clean
        ));
        response.answers.clear();
        let service = SVCB::new(
            1,
            Name::root(),
            vec![(
                SvcParamKey::Ipv4Hint,
                SvcParamValue::Ipv4Hint(IpHint(vec![A("192.0.2.1".parse().unwrap())])),
            )],
        );
        record(
            &mut response,
            "alias.test.",
            RData::HTTPS(HTTPS(service.clone())),
        );
        assert!(matches!(
            inspect(&request, &response, &policy, false),
            Inspection::Clean
        ));
        assert!(matches!(
            inspect(
                &request,
                &response,
                &filters("/^192\\.0\\.2\\.1$/$dnstype=HTTPS"),
                false
            ),
            Inspection::Blocked { kind: 65, .. }
        ));
        response.answers.clear();
        record(&mut response, "alias.test.", RData::SVCB(service));
        assert!(matches!(
            inspect(&request, &response, &filters("/^192\\.0\\.2\\.1$/"), false),
            Inspection::Clean
        ));
    }
    #[test]
    fn mapped_aaaa_addresses_keep_record_type_and_work_bounds_fail_closed() {
        let (request, mut response) = messages();
        record(
            &mut response,
            "alias.test.",
            RData::AAAA(AAAA("::ffff:192.0.2.1".parse().unwrap())),
        );
        assert!(matches!(
            inspect(
                &request,
                &response,
                &filters("/^192\\.0\\.2\\.1$/$dnstype=AAAA"),
                false
            ),
            Inspection::Blocked { kind: 28, .. }
        ));
        response.answers.clear();
        for _ in 0..257 {
            record(
                &mut response,
                "alias.test.",
                RData::A(A("192.0.2.2".parse().unwrap())),
            );
        }
        assert!(matches!(
            inspect(&request, &response, &filters("/^192\\.0\\.2\\.1$/"), false),
            Inspection::Invalid
        ));
        assert!(matches!(
            inspect(&request, &response, &filters("/^192\\.0\\.2\\.1$/"), true),
            Inspection::Clean
        ));
    }
    #[test]
    fn value_bounds_apply_only_when_a_client_rule_can_apply() {
        let (request, mut response) = messages();
        for _ in 0..257 {
            record(
                &mut response,
                "alias.test.",
                RData::A(A("192.0.2.2".parse().unwrap())),
            );
        }
        let policy = FilterSnapshot::compile(
            &[ListInput {
                name: "v5".into(),
                syntax: RuleSyntax::AdguardV5,
                action: Action::Block,
                rules: "/^192\\.0\\.2\\.1$/$client=Kids".into(),
            }],
            10,
            10000,
        )
        .unwrap();
        for (name, invalid) in [("Kids", true), ("Adults", false)] {
            let result = inspect_client(
                &request,
                &response,
                &policy,
                false,
                Some(
                    rustwalld_dns_filter::ClientContext {
                        ip: "192.0.2.1".parse().unwrap(),
                        name: Some(name),
                    }
                    .into(),
                ),
            );
            assert_eq!(matches!(result, Inspection::Invalid), invalid);
        }

        let tagged = FilterSnapshot::compile(
            &[ListInput {
                name: "tagged".into(),
                syntax: RuleSyntax::AdguardV6,
                action: Action::Block,
                rules: "/^192\\.0\\.2\\.1$/$ctag=user_child".into(),
            }],
            10,
            10000,
        )
        .unwrap();
        for (tags, invalid) in [(vec!["user_child"], true), (vec![], false)] {
            let ctx = rustwalld_dns_filter::ClientContext {
                ip: "192.0.2.1".parse().unwrap(),
                name: Some("Kids"),
            }
            .with_tags(rustwalld_dns_filter::ClientTags::compile(tags).unwrap());
            assert_eq!(
                matches!(
                    inspect_client(&request, &response, &tagged, false, Some(ctx)),
                    Inspection::Invalid
                ),
                invalid
            );
        }
    }
}
