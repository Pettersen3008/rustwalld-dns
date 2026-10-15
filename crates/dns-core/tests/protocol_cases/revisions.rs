#![allow(clippy::unwrap_used)]
use super::*;

#[tokio::test]
async fn reload_under_traffic_generation_invalidation_and_shadow() {
    use rustwalld_dns_filter::{Action, ListInput};
    let mock = Mock::start(false, false).await;
    let (engine, mut receiver) = engine_for(&mock, 1000, 32);
    let client = "127.0.0.1".parse().unwrap();
    let bytes = query(RecordType::A).to_vec().unwrap();
    assert_eq!(
        Message::from_vec(&engine.answer(&bytes, client, Transport::Udp).await.unwrap())
            .unwrap()
            .answers
            .len(),
        1
    );
    let mut candidate = engine.active.load().config().clone();
    candidate.policies[0].lists.push(ListInput {
        syntax: Default::default(),
        name: "deny".into(),
        action: Action::Block,
        rules: "example".into(),
    });
    engine.shadow.store(Some(Arc::new(
        PolicySnapshot::compile(candidate.clone(), 2).unwrap(),
    )));
    assert_eq!(
        Message::from_vec(&engine.answer(&bytes, client, Transport::Udp).await.unwrap())
            .unwrap()
            .answers
            .len(),
        1
    );
    let mut difference = false;
    while let Ok(event) = receiver.try_recv() {
        difference |= event.shadow.is_some_and(|s| s.differs);
    }
    assert!(difference);
    let tasks = {
        let engine = engine.clone();
        let bytes = bytes.clone();
        tokio::spawn(async move {
            for _ in 0..200 {
                let response = Message::from_vec(
                    &engine.answer(&bytes, client, Transport::Udp).await.unwrap(),
                )
                .unwrap();
                assert!(matches!(
                    response.metadata.response_code,
                    ResponseCode::NoError | ResponseCode::NXDomain
                ));
                tokio::task::yield_now().await;
            }
        })
    };
    engine
        .active
        .store(Arc::new(PolicySnapshot::compile(candidate, 3).unwrap()));
    tasks.await.unwrap();
    for _ in 0..10 {
        assert_eq!(
            Message::from_vec(&engine.answer(&bytes, client, Transport::Udp).await.unwrap())
                .unwrap()
                .metadata
                .response_code,
            ResponseCode::NXDomain
        );
    }
    assert_eq!(mock.hits.load(Ordering::Relaxed), 1);
    // Rollback compiles the old content into a fresh generation. Decisions are
    // per generation, so the block lifts immediately; the upstream profile is
    // unchanged (only its timeout differs), so the still-valid cached answer is
    // reused instead of querying upstream again.
    let mut old = PolicyConfigSet::default();
    old.upstreams[0].addresses = vec![mock.addr];
    engine
        .active
        .store(Arc::new(PolicySnapshot::compile(old, 4).unwrap()));
    assert_eq!(
        Message::from_vec(&engine.answer(&bytes, client, Transport::Udp).await.unwrap())
            .unwrap()
            .answers
            .len(),
        1
    );
    assert_eq!(mock.hits.load(Ordering::Relaxed), 1);
}
