#![no_main]
use libfuzzer_sys::fuzz_target;
use rustwalld_dns_policy::{
    BlockedServices, PolicyConfigSet, PolicySnapshot, ScheduleDay, ScheduleMode, ScheduleWindow,
    ServiceScheduleState, WeeklySchedule,
};
use std::time::{Duration, UNIX_EPOCH};
fuzz_target!(|input: &[u8]| {
    if input.len() > 8192 {
        return;
    }
    let Some((&flags, body)) = input.split_first() else {
        return;
    };
    let schedule = if body.starts_with(b"{") {
        let Ok(value) = serde_json::from_slice::<WeeklySchedule>(body) else {
            return;
        };
        value
    } else {
        WeeklySchedule {
            time_zone: if flags & 1 != 0 { "Europe/Oslo" } else { "UTC" }.into(),
            mode: if flags & 2 != 0 {
                ScheduleMode::Allow
            } else {
                ScheduleMode::Block
            },
            windows: vec![ScheduleWindow {
                days: vec![ScheduleDay::Mon, ScheduleDay::Sun],
                start: "22:00".into(),
                end: "07:00".into(),
            }],
        }
    };
    let mut config = PolicyConfigSet::default();
    config.upstreams[0].addresses = vec!["127.0.0.1:9".parse().unwrap()];
    config.policies[0].blocked_services = Some(BlockedServices {
        catalog_version: 1,
        ids: vec!["youtube".into()],
        schedule: Some(schedule),
    });
    let Ok(snapshot) = PolicySnapshot::compile(config, 1) else {
        return;
    };
    let mut sample = [0u8; 8];
    for (slot, byte) in sample.iter_mut().zip(body) {
        *slot = *byte;
    }
    let seconds = u64::from_le_bytes(sample);
    for value in [seconds, 946684800, 1791795600, 1792890000, 4102444800] {
        let Some(now) = UNIX_EPOCH.checked_add(Duration::from_secs(value)) else {
            continue;
        };
        let evaluation = snapshot.policies()[0].service_schedule_at(now).unwrap();
        assert!(evaluation.ttl_cap <= 60);
        if !(946684800..4102444800).contains(&value) {
            assert_eq!(evaluation.state, ServiceScheduleState::InvalidClock);
            assert_eq!(evaluation.ttl_cap, 0);
        }
        let trace = snapshot
            .explain_at("127.0.0.1".parse().unwrap(), "www.youtube.com", now)
            .unwrap();
        assert_eq!(trace.service_schedule.unwrap().state, evaluation.state);
        let inputs = snapshot.config().policies[0]
            .filter_inputs_for_services(evaluation.state.blocking())
            .unwrap();
        let filters = rustwalld_dns_filter::FilterSnapshot::compile(&inputs, 1000, 10000).unwrap();
        assert_eq!(
            trace.decision.action,
            filters.evaluate("www.youtube.com").action
        );
    }
});
