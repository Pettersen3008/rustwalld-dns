use super::*;
#[tokio::test]
async fn scheduled_current_and_recorded_variants_keep_their_own_sources() {
    use rustwalld_dns_policy::{
        BlockedServices, ScheduleDay, ScheduleMode, ScheduleWindow, WeeklySchedule,
    };
    let harness = Harness::start().await;
    let mut config: PolicyConfigSet = harness.get("/api/v1/config").await.json().await.unwrap();
    config.upstreams[0].addresses = vec!["127.0.0.1:9".parse().unwrap()];
    config.policies[0].lists = vec![ListInput {
        name: "manual".into(),
        action: Action::Block,
        rules: "youtube.com".into(),
        syntax: Default::default(),
    }];
    config.policies[0].blocked_services = Some(BlockedServices {
        catalog_version: 1,
        ids: vec!["youtube".into()],
        schedule: Some(WeeklySchedule {
            time_zone: "UTC".into(),
            mode: ScheduleMode::Block,
            windows: vec![ScheduleWindow {
                days: vec![
                    ScheduleDay::Mon,
                    ScheduleDay::Tue,
                    ScheduleDay::Wed,
                    ScheduleDay::Thu,
                    ScheduleDay::Fri,
                    ScheduleDay::Sat,
                    ScheduleDay::Sun,
                ],
                start: "00:00".into(),
                end: "24:00".into(),
            }],
        }),
    });
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        200
    );
    assert_eq!(
        harness
            .dns("active-schedule.youtube.com")
            .await
            .response_code,
        ResponseCode::NXDomain
    );
    let harness_ref = &harness;
    let capture = |domain: &'static str| async move {
        timeout(Duration::from_secs(2), async {
            loop {
                let events: Vec<Value> = harness_ref
                    .get("/api/v1/queries?limit=20")
                    .await
                    .json()
                    .await
                    .unwrap();
                if let Some(event) = events.into_iter().find(|event| event["domain"] == domain) {
                    break event;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap()
    };
    let active = capture("active-schedule.youtube.com").await;
    assert_eq!(active["service_schedule"], "active");
    config.policies[0]
        .blocked_services
        .as_mut()
        .unwrap()
        .schedule
        .as_mut()
        .unwrap()
        .windows
        .clear();
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        200
    );
    assert_eq!(
        harness
            .dns("inactive-schedule.youtube.com")
            .await
            .response_code,
        ResponseCode::NXDomain
    );
    let inactive = capture("inactive-schedule.youtube.com").await;
    assert_eq!(inactive["service_schedule"], "inactive");
    let path = format!(
        "/api/v1/queries/{}/explain",
        inactive["id"].as_u64().unwrap()
    );
    let recorded: Value = harness.get(&path).await.json().await.unwrap();
    assert_eq!(recorded["service_schedule"]["state"], "inactive");
    assert_eq!(recorded["rule"]["sources"].as_array().unwrap().len(), 1);
    assert_eq!(recorded["rule"]["sources"][0]["list"], "manual");
    let path = format!("/api/v1/queries/{}/explain", active["id"].as_u64().unwrap());
    let original: Value = harness.get(&path).await.json().await.unwrap();
    assert_eq!(original["service_schedule"]["state"], "active");
    assert_eq!(original["rule"]["sources"].as_array().unwrap().len(), 2);
    let policies: Value = harness.get("/api/v1/policies").await.json().await.unwrap();
    assert_eq!(policies[0]["service_schedule"]["state"], "inactive");
    // A missing state must not be guessed from persistence time/current windows.
    let db = rusqlite::Connection::open(&harness.path).unwrap();
    db.execute(
        "UPDATE queries SET service_schedule=NULL WHERE id=?1",
        [i64::try_from(active["id"].as_u64().unwrap()).unwrap()],
    )
    .unwrap();
    let path = format!("/api/v1/queries/{}/explain", active["id"].as_u64().unwrap());
    assert_eq!(harness.get(&path).await.status(), 503);
    drop(db);
    harness.shutdown().await;
}
