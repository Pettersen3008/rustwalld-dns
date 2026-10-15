#![allow(clippy::unwrap_used)]
use super::*;
use crate::{Action, reply};
use hickory_proto::op::{Edns, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::rr::{
    RData, Record,
    rdata::{A, CNAME},
};
use rustwalld_dns_policy::{
    BlockedServices, SafeSearchConfig, ScheduleDay, ScheduleMode, ScheduleWindow,
    ServiceScheduleState as State, WeeklySchedule, YouTubeMode,
};
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
fn at(text: &str) -> SystemTime {
    // Policy tests verify named-zone conversion; these UTC fixtures use simple
    // known timestamps, avoiding an additional core date dependency.
    let seconds = match text {
        "before" => 1791795599,
        "inside" => 1791795600,
        "end" => 1791799200,
        _ => 1791795660,
    };
    UNIX_EPOCH + Duration::from_secs(seconds)
}
fn config() -> PolicySnapshot {
    let mut config = rustwalld_dns_policy::PolicyConfigSet::default();
    config.upstreams[0].addresses = vec!["127.0.0.1:9".parse().unwrap()];
    config.policies[0].blocked_services = Some(BlockedServices {
        catalog_version: 1,
        ids: vec!["youtube".into()],
        schedule: Some(WeeklySchedule {
            time_zone: "UTC".into(),
            mode: ScheduleMode::Block,
            windows: vec![ScheduleWindow {
                days: vec![ScheduleDay::Mon],
                start: "09:00".into(),
                end: "10:00".into(),
            }],
        }),
    });
    config.policies[0].lists = vec![rustwalld_dns_filter::ListInput {
        name: "ordinary".into(),
        action: Action::Block,
        rules: "=manual.test".into(),
        syntax: Default::default(),
    }];
    PolicySnapshot::compile(config, 1).unwrap()
}
fn wire(domain: &str) -> Vec<u8> {
    let mut msg = Message::query();
    msg.metadata.id = 77;
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(
        Name::from_ascii(domain).unwrap(),
        RecordType::A,
    ));
    msg.set_edns(Edns::new().set_dnssec_ok(true).clone());
    msg.to_vec().unwrap()
}
fn parsed(output: Prepared) -> Message {
    let Prepared::Reply(bytes) = output else {
        panic!("expected local reply")
    };
    Message::from_vec(&bytes).unwrap()
}
fn pending(engine: &Engine, domain: &str, now: SystemTime) -> Box<Pending> {
    let Prepared::Forward(query) = engine.prepare_at(
        &wire(domain),
        "127.0.0.1".parse().unwrap(),
        Transport::Udp,
        Some(now),
    ) else {
        panic!("expected pending query")
    };
    query.0
}
fn answer(request: &Message, target: Option<&str>) -> Message {
    let mut response = reply(request, ResponseCode::NoError);
    let question = &request.queries[0];
    let owner = if let Some(target) = target {
        let name = Name::from_ascii(target).unwrap();
        response.add_answer(Record::from_rdata(
            question.name().clone(),
            600,
            RData::CNAME(CNAME(name.clone())),
        ));
        name
    } else {
        question.name().clone()
    };
    response.add_answer(Record::from_rdata(
        owner,
        600,
        RData::A(A("192.0.2.10".parse().unwrap())),
    ));
    response
}
#[tokio::test]
async fn warm_raw_and_decision_caches_partition_states_and_clamp_private_ttls() {
    let (telemetry, mut events) = Telemetry::channel(32);
    let (engine, _) = Engine::controlled(config(), EngineConfig::default(), telemetry);
    let before = at("before") + Duration::from_millis(500);
    let query = pending(&engine, "www.youtube.com.", before);
    let key = query.key.clone();
    let response = answer(&query.request, None);
    assert!(
        engine
            .resolver
            .cache
            .insert(key.clone(), response.clone(), Instant::now())
    );
    let output = Message::from_vec(
        &engine
            .complete_at(query, response, QuerySource::Upstream, Some(before))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(output.answers[0].ttl, 0);
    assert_eq!(
        events.recv().await.unwrap().service_schedule,
        Some(State::Inactive)
    );
    let cached = parsed(engine.prepare_at(
        &wire("www.youtube.com."),
        "127.0.0.1".parse().unwrap(),
        Transport::Udp,
        Some(at("before")),
    ));
    assert_eq!(cached.answers[0].ttl, 1);
    assert!(events.recv().await.unwrap().decision_cached);
    let denied = parsed(engine.prepare_at(
        &wire("www.youtube.com."),
        "127.0.0.1".parse().unwrap(),
        Transport::Udp,
        Some(at("inside")),
    ));
    assert_eq!(denied.metadata.response_code, ResponseCode::NXDomain);
    let event = events.recv().await.unwrap();
    assert_eq!(event.service_schedule, Some(State::Active));
    assert!(event.decision.rule.is_some());
    assert!(!event.decision_cached);
    let allowed = parsed(engine.prepare_at(
        &wire("www.youtube.com."),
        "127.0.0.1".parse().unwrap(),
        Transport::Udp,
        Some(at("end")),
    ));
    assert_eq!(allowed.answers[0].ttl, 60);
    assert_eq!(allowed.metadata.id, 77);
    assert!(allowed.edns.as_ref().unwrap().flags().dnssec_ok);
    assert_eq!(
        events.recv().await.unwrap().service_schedule,
        Some(State::Inactive)
    );
    assert_eq!(
        engine
            .resolver
            .cache
            .get(&key, Instant::now())
            .unwrap()
            .answers[0]
            .ttl,
        600
    );
    assert_eq!(engine.telemetry.metrics.blocked.load(Ordering::Relaxed), 1);
}
#[tokio::test]
async fn inflight_root_cname_and_safesearch_are_rechecked_at_the_final_minute() {
    let mut snapshot = config().config().clone();
    snapshot.policies[0].safe_search = Some(SafeSearchConfig {
        youtube: YouTubeMode::Strict,
        ..Default::default()
    });
    let (telemetry, mut events) = Telemetry::channel(16);
    let (engine, _) = Engine::controlled(
        PolicySnapshot::compile(snapshot, 1).unwrap(),
        EngineConfig::default(),
        telemetry,
    );
    let query = pending(&engine, "www.youtube.com.", at("before"));
    let response = answer(query.lookup_request.as_ref().unwrap(), None);
    let output = Message::from_vec(
        &engine
            .complete_at(query, response, QuerySource::Coalesced, Some(at("inside")))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(output.metadata.response_code, ResponseCode::NXDomain);
    let event = events.recv().await.unwrap();
    assert_eq!(event.service_schedule, Some(State::Active));
    assert!(event.matched_domain.is_none());
    let query = pending(&engine, "alias.test.", at("before"));
    let response = answer(&query.request, Some("www.youtube.com."));
    let output = Message::from_vec(
        &engine
            .complete_at(query, response, QuerySource::Coalesced, Some(at("inside")))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(output.metadata.response_code, ResponseCode::NXDomain);
    let event = events.recv().await.unwrap();
    assert_eq!(event.matched_domain.as_deref(), Some("www.youtube.com"));
    assert_eq!(event.service_schedule, Some(State::Active));
    assert_eq!(engine.telemetry.metrics.blocked.load(Ordering::Relaxed), 2);
    assert_eq!(engine.telemetry.metrics.rewrites.load(Ordering::Relaxed), 0);
}
#[tokio::test]
async fn a_synthesized_block_crossing_to_off_retries_and_invalid_clock_fails_closed() {
    let snapshot = config();
    let policy = &snapshot.policies()[0];
    let request = Message::from_vec(&wire("www.youtube.com.")).unwrap();
    let decision = policy.filters().evaluate("www.youtube.com");
    let (telemetry, mut events) = Telemetry::channel(8);
    let (engine, _) = Engine::controlled(config(), EngineConfig::default(), telemetry);
    let mut outcome = Outcome {
        start: Instant::now(),
        client: "127.0.0.1".parse().unwrap(),
        transport: Transport::Udp,
        request: &request,
        policy,
        client_name: None,
        filter_tags: rustwalld_dns_filter::ClientTags::default(),
        generation: 1,
        domain: "www.youtube.com".into(),
        qtype: 1,
        decision,
        decision_cached: false,
        excepted: false,
        exception: None,
        schedule: policy.service_schedule_at(at("inside")),
        response: crate::response::blocked(&request, policy.block_mode()),
        source: QuerySource::Blocked,
    };
    let output =
        Message::from_vec(&engine.finish_at(&mut outcome, Some(at("end"))).unwrap()).unwrap();
    assert_eq!(output.metadata.response_code, ResponseCode::ServFail);
    let event = events.recv().await.unwrap();
    assert_eq!(event.service_schedule, Some(State::Inactive));
    assert_eq!(event.decision.action, Action::Allow);
    assert_eq!(engine.telemetry.metrics.blocked.load(Ordering::Relaxed), 0);
    assert_eq!(engine.telemetry.metrics.failures.load(Ordering::Relaxed), 1);
    let denied = parsed(engine.prepare_at(
        &wire("www.youtube.com."),
        "127.0.0.1".parse().unwrap(),
        Transport::Udp,
        Some(UNIX_EPOCH),
    ));
    assert_eq!(denied.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(
        events.recv().await.unwrap().service_schedule,
        Some(State::InvalidClock)
    );
    let manual = parsed(engine.prepare_at(
        &wire("manual.test."),
        "127.0.0.1".parse().unwrap(),
        Transport::Udp,
        Some(at("end")),
    ));
    assert_eq!(manual.metadata.response_code, ResponseCode::NXDomain);
    let event = events.recv().await.unwrap();
    assert_eq!(event.service_schedule, Some(State::Inactive));
    assert!(event.decision.rule.is_some());
}

#[tokio::test]
async fn shadow_selects_its_own_weekly_state_without_fetching_candidate_answers() {
    let base = config().config().clone();
    let mut active = base.clone();
    active.policies[0].blocked_services = None;
    let (telemetry, mut events) = Telemetry::channel(8);
    let (engine, control) = Engine::controlled(
        PolicySnapshot::compile(active, 1).unwrap(),
        EngineConfig::default(),
        telemetry,
    );
    control
        .prepare(
            PolicySnapshot::compile(base, 2).unwrap(),
            crate::PublicationTarget::Shadow,
            control.version(),
        )
        .unwrap()
        .commit();
    let query = pending(&engine, "www.youtube.com.", at("inside"));
    let response = answer(&query.request, None);
    let output = Message::from_vec(
        &engine
            .complete_at(query, response, QuerySource::Upstream, Some(at("inside")))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(output.metadata.response_code, ResponseCode::NoError);
    let event = events.recv().await.unwrap();
    assert!(event.service_schedule.is_none());
    let shadow = event.shadow.unwrap();
    assert_eq!(shadow.service_schedule, Some(State::Active));
    assert!(shadow.differs);
    let query = pending(&engine, "www.youtube.com.", at("end"));
    let response = answer(&query.request, None);
    engine
        .complete_at(query, response, QuerySource::Upstream, Some(at("end")))
        .unwrap();
    let shadow = events.recv().await.unwrap().shadow.unwrap();
    assert_eq!(shadow.service_schedule, Some(State::Inactive));
    assert!(!shadow.differs);
}

#[tokio::test]
async fn native_allows_local_records_and_scoped_live_pauses_survive_schedule_cutover() {
    let mut configured = config().config().clone();
    configured.allowed_clients = vec!["127.0.0.0/24".parse().unwrap()];
    configured.policies[0]
        .lists
        .push(rustwalld_dns_filter::ListInput {
            name: "allow".into(),
            action: Action::Allow,
            rules: "=allow.youtube.com".into(),
            syntax: Default::default(),
        });
    configured.policies[0]
        .rewrites
        .push(rustwalld_dns_policy::Rewrite {
            domain: "local.youtube.com".into(),
            addresses: vec!["192.0.2.20".parse().unwrap()],
            ttl: 600,
        });
    configured.policies[0]
        .temporary_exceptions
        .push(rustwalld_dns_policy::TemporaryException {
            name: "scoped repair".into(),
            domain: "paused.youtube.com".into(),
            expires_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 300,
            clients: vec!["127.0.0.1/32".parse().unwrap()],
            include_subdomains: false,
        });
    let (telemetry, mut events) = Telemetry::channel(8);
    let (engine, _) = Engine::controlled(
        PolicySnapshot::compile(configured, 1).unwrap(),
        EngineConfig::default(),
        telemetry,
    );
    for domain in ["allow.youtube.com.", "paused.youtube.com."] {
        let query = pending(&engine, domain, at("before"));
        let response = answer(&query.request, Some("www.youtube.com."));
        let output = Message::from_vec(
            &engine
                .complete_at(query, response, QuerySource::Coalesced, Some(at("inside")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(output.metadata.response_code, ResponseCode::NoError);
        assert_eq!(output.answers.len(), 2);
        assert!(output.answers.iter().all(|record| record.ttl <= 60));
        let event = events.recv().await.unwrap();
        assert_eq!(event.service_schedule, Some(State::Active));
        assert_eq!(
            event.temporary_exception.is_some(),
            domain.starts_with("paused")
        );
    }
    let local = parsed(engine.prepare_at(
        &wire("local.youtube.com."),
        "127.0.0.1".parse().unwrap(),
        Transport::Udp,
        Some(at("inside")),
    ));
    assert_eq!(local.metadata.response_code, ResponseCode::NoError);
    assert_eq!(local.answers[0].ttl, 60);
    assert_eq!(
        local.answers[0].data,
        RData::A(A("192.0.2.20".parse().unwrap()))
    );
    assert_eq!(events.recv().await.unwrap().source, QuerySource::Rewrite);
    let denied = parsed(engine.prepare_at(
        &wire("paused.youtube.com."),
        "127.0.0.2".parse().unwrap(),
        Transport::Udp,
        Some(at("inside")),
    ));
    assert_eq!(denied.metadata.response_code, ResponseCode::NXDomain);
    assert!(events.recv().await.unwrap().temporary_exception.is_none());
    assert_eq!(engine.telemetry.metrics.blocked.load(Ordering::Relaxed), 1);
    assert_eq!(
        engine
            .telemetry
            .metrics
            .temporary_allows
            .load(Ordering::Relaxed),
        1
    );
}

#[tokio::test]
async fn typed_rules_survive_schedule_cutover_and_pending_exception_expiry() {
    use rustwalld_dns_filter::{ListInput, RuleSyntax};
    for syntax in [
        RuleSyntax::AdguardV4,
        RuleSyntax::AdguardV5,
        RuleSyntax::AdguardV6,
    ] {
        let mut configured = config().config().clone();
        if syntax == RuleSyntax::AdguardV6 {
            configured.bindings.push(rustwalld_dns_policy::Binding {
                name: "Tagged".into(),
                network: "127.0.0.1/32".parse().unwrap(),
                policy: "default".into(),
                filter_tags: vec!["user_child".into()],
                metadata: None,
            });
        }
        configured.policies[0].lists = vec![ListInput {
            name: "typed".into(),
            action: Action::Block,
            syntax,
            rules: if syntax == RuleSyntax::AdguardV6 {
                "||typed.test^$dnstype=AAAA,ctag=user_child\n/^192\\.0\\.2\\.10$/$dnstype=AAAA,ctag=user_child\n@@||allowed.test^$dnstype=A,ctag=user_child".into()
            } else if syntax == RuleSyntax::AdguardV5 {
                "||typed.test^$dnstype=AAAA,client=127.0.0.1\n/^192\\.0\\.2\\.10$/$dnstype=AAAA,client=127.0.0.1\n@@||allowed.test^$dnstype=A,client=127.0.0.1".into()
            } else {
                "||typed.test^$dnstype=AAAA\n/^192\\.0\\.2\\.10$/$dnstype=AAAA\n@@||allowed.test^$dnstype=A".into()
            },
        }];
        let expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 300;
        configured.policies[0].temporary_exceptions.push(
            rustwalld_dns_policy::TemporaryException {
                name: "expiry".into(),
                domain: "typed.test".into(),
                expires_at: expiry,
                clients: vec![],
                include_subdomains: false,
            },
        );
        let (telemetry, mut events) = Telemetry::channel(16);
        let (engine, _) = Engine::controlled(
            PolicySnapshot::compile(configured, 1).unwrap(),
            EngineConfig::default(),
            telemetry,
        );
        // A typed address rule must remain inapplicable to actual A records when
        // the service-filter snapshot is selected again at a weekly boundary.
        let query = pending(&engine, "ordinary.test.", at("before"));
        let response = answer(&query.request, None);
        let output = Message::from_vec(
            &engine
                .complete_at(query, response, QuerySource::Upstream, Some(at("inside")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(output.metadata.response_code, ResponseCode::NoError);
        assert_eq!(
            events.recv().await.unwrap().service_schedule,
            Some(State::Active)
        );
        // An explicit question allow also exempts aliases and addresses.
        let query = pending(&engine, "allowed.test.", at("inside"));
        let response = answer(&query.request, Some("typed.test."));
        assert_eq!(
            Message::from_vec(
                &engine
                    .complete_at(query, response, QuerySource::Upstream, Some(at("inside")))
                    .unwrap()
            )
            .unwrap()
            .metadata
            .response_code,
            ResponseCode::NoError
        );
        events.recv().await.unwrap();
        let mut queries = Vec::new();
        for kind in [RecordType::A, RecordType::AAAA] {
            let mut msg = Message::from_vec(&wire("typed.test.")).unwrap();
            msg.queries[0].set_query_type(kind);
            let Prepared::Forward(query) = engine.prepare_at(
                &msg.to_vec().unwrap(),
                "127.0.0.1".parse().unwrap(),
                Transport::Udp,
                Some(UNIX_EPOCH + Duration::from_secs(expiry - 1)),
            ) else {
                panic!("expected live exemption")
            };
            queries.push((kind, query));
        }
        let active = engine.active();
        let found = active
            .select("127.0.0.1".parse().unwrap())
            .policy
            .temporary_allow_for("typed.test", "127.0.0.1".parse().unwrap(), Instant::now())
            .unwrap();
        assert!(
            found
                .remaining_ttl(Instant::now() + Duration::from_secs(301))
                .is_none()
        );
        for (kind, query) in queries {
            let response = answer(&query.0.request, None);
            let output = Message::from_vec(
                &engine
                    .complete_at(
                        query.0,
                        response,
                        QuerySource::Upstream,
                        Some(UNIX_EPOCH + Duration::from_secs(expiry + 1)),
                    )
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                output.metadata.response_code,
                if kind == RecordType::AAAA {
                    ResponseCode::NXDomain
                } else {
                    ResponseCode::NoError
                }
            );
            let event = events.recv().await.unwrap();
            assert!(event.temporary_exception.is_none());
            assert_eq!(event.qtype, u16::from(kind));
        }
    }
}
