#![allow(clippy::unwrap_used)]
mod support {
    pub mod diagnostics;
    pub mod tls;
}
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{Name, RecordType},
};
use rustwalld_dns_resolver::{FailureKind, Forwarder, UpstreamTransport};
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use support::{
    diagnostics::{failure, reconciled},
    tls::Mock,
};
fn query() -> Message {
    let mut q = Message::new(12, MessageType::Query, OpCode::Query);
    q.add_query(Query::query(
        Name::from_ascii("allowed.test.").unwrap(),
        RecordType::A,
    ));
    q
}
fn forward(mock: &Mock) -> Forwarder {
    Forwarder::with_transport(
        vec![mock.address],
        Duration::from_millis(200),
        &mock.transport,
    )
    .unwrap()
}
#[tokio::test]
async fn trusted_reuse_reconnect_and_invalid_dns() {
    let mock = Mock::start(0).await;
    let f = forward(&mock);
    for _ in 0..10 {
        assert_eq!(f.resolve(&query()).await.unwrap().answers.len(), 1);
    }
    assert_eq!(mock.accepted.load(Ordering::SeqCst), 1);
    mock.mode.store(1, Ordering::SeqCst);
    f.resolve(&query()).await.unwrap();
    f.resolve(&query()).await.unwrap();
    assert_eq!(mock.accepted.load(Ordering::SeqCst), 2);
    for mode in [3, 4, 5, 7, 9] {
        let bad = Mock::start(mode).await;
        let f = forward(&bad);
        assert!(f.resolve(&query()).await.is_err());
        failure(
            &f.health()[0],
            if mode == 9 {
                FailureKind::Connection
            } else {
                FailureKind::DnsResponse
            },
            1,
        );
        assert_eq!(bad.queries.load(Ordering::SeqCst), 1);
    }
}
#[tokio::test]
async fn certificate_identity_trust_and_validity_are_required() {
    let mock = Mock::start(0).await;
    let mut wrong = mock.transport.clone();
    if let UpstreamTransport::Tls { server_name, .. } = &mut wrong {
        *server_name = "wrong.test".into();
    }
    let f =
        Forwarder::with_transport(vec![mock.address], Duration::from_millis(200), &wrong).unwrap();
    assert!(f.resolve(&query()).await.is_err());
    failure(&f.health()[0], FailureKind::TlsAuthentication, 1);
    let mut untrusted = mock.transport.clone();
    if let UpstreamTransport::Tls { ca_pem, .. } = &mut untrusted {
        *ca_pem = None;
    }
    let f = Forwarder::with_transport(vec![mock.address], Duration::from_millis(200), &untrusted)
        .unwrap();
    assert!(f.resolve(&query()).await.is_err());
    failure(&f.health()[0], FailureKind::TlsAuthentication, 1);
    let expired = Mock::with_expiry(0, true).await;
    let f = forward(&expired);
    assert!(f.resolve(&query()).await.is_err());
    failure(&f.health()[0], FailureKind::TlsAuthentication, 1);
    assert_eq!(mock.queries.load(Ordering::SeqCst), 0);
    assert_eq!(expired.queries.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn timeout_cancel_and_pool_admission_do_not_poison_reuse() {
    let mock = Mock::start(2).await;
    let mut config = mock.transport.clone();
    if let UpstreamTransport::Tls {
        max_connections, ..
    } = &mut config
    {
        *max_connections = 1;
    }
    let f = Arc::new(
        Forwarder::with_transport(vec![mock.address], Duration::from_millis(100), &config).unwrap(),
    );
    let first = {
        let f = f.clone();
        tokio::spawn(async move { f.resolve(&query()).await })
    };
    mock.wait_queries(1).await;
    let mut waiters = vec![];
    for _ in 0..8 {
        let f = f.clone();
        waiters.push(tokio::spawn(async move { f.resolve(&query()).await }));
    }
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(mock.accepted.load(Ordering::SeqCst), 1);
    first.abort();
    let _ = first.await;
    // Cancellation retires the shared connection from admission. Existing
    // pending requests retain it until their deadlines, then a new socket opens.
    for waiter in waiters {
        assert!(waiter.await.unwrap().is_err());
    }
    mock.mode.store(0, Ordering::SeqCst);
    assert!(f.resolve(&query()).await.is_ok());
    assert_eq!(f.health()[0].successes.load(Ordering::SeqCst), 1);
    failure(&f.health()[0], FailureKind::Cancelled, 1);
    failure(&f.health()[0], FailureKind::Deadline, 8);
    let stall = Mock::start(6).await;
    let f = forward(&stall);
    assert!(f.resolve(&query()).await.is_err());
    failure(&f.health()[0], FailureKind::Deadline, 1);
    assert_eq!(stall.queries.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn fallback_is_sequential_and_never_plaintext() {
    let bad = Mock::start(6).await;
    let good = Mock::start(0).await;
    let mut transport = good.transport.clone();
    // Both endpoints intentionally have the same identity but separate test roots.
    if let UpstreamTransport::Tls { ca_pem, .. } = &mut transport
        && let UpstreamTransport::Tls {
            ca_pem: Some(pem), ..
        } = &bad.transport
    {
        ca_pem.as_mut().unwrap().push_str(pem);
    }
    let f = Arc::new(
        Forwarder::with_transport(
            vec![bad.address, good.address],
            Duration::from_millis(100),
            &transport,
        )
        .unwrap(),
    );
    let task = {
        let f = f.clone();
        tokio::spawn(async move { f.resolve(&query()).await })
    };
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(good.accepted.load(Ordering::SeqCst), 0);
    assert!(task.await.unwrap().is_ok());
    assert_eq!(bad.accepted.load(Ordering::SeqCst), 1);
    assert_eq!(good.accepted.load(Ordering::SeqCst), 1);
    assert_eq!(f.health()[0].successes.load(Ordering::SeqCst), 0);
    failure(&f.health()[0], FailureKind::Deadline, 1);
    reconciled(&f.health()[1]);
}
#[test]
fn invalid_tls_configuration_rejected_before_connect() {
    let address = "127.0.0.1:853".parse().unwrap();
    for (name, ca, max) in [
        ("127.0.0.1", None, 2),
        ("resolver.test.", None, 2),
        ("resolver.test", Some("not pem"), 2),
        ("resolver.test", None, 0),
        ("resolver.test", None, 9),
    ] {
        assert!(
            Forwarder::with_transport(
                vec![address],
                Duration::from_secs(1),
                &UpstreamTransport::Tls {
                    server_name: name.into(),
                    ca_pem: ca.map(str::to_string),
                    max_connections: max
                }
            )
            .is_err()
        );
    }
}

#[tokio::test]
async fn concurrent_successful_queries_stay_within_connection_bound() {
    let mock = Mock::start(8).await;
    let f = Arc::new(
        Forwarder::with_transport(vec![mock.address], Duration::from_secs(2), &mock.transport)
            .unwrap(),
    );
    let mut tasks = vec![];
    for _ in 0..32 {
        let f = f.clone();
        tasks.push(tokio::spawn(async move { f.resolve(&query()).await }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap().unwrap().answers.len(), 1);
    }
    assert_eq!(mock.queries.load(Ordering::SeqCst), 32);
    assert_eq!(mock.accepted.load(Ordering::SeqCst), 2);
    reconciled(&f.health()[0]);
    assert_eq!(f.health()[0].successes.load(Ordering::SeqCst), 32);
}

#[tokio::test]
async fn failed_tls_authentication_cannot_send_plaintext_dns() {
    let bad = Mock::start(0).await;
    let good = Mock::start(0).await;
    let spy = tokio::net::UdpSocket::bind(bad.address).await.unwrap();
    let f = Forwarder::with_transport(
        vec![bad.address, good.address],
        Duration::from_millis(200),
        &good.transport,
    )
    .unwrap();
    assert!(f.resolve(&query()).await.is_ok());
    failure(&f.health()[0], FailureKind::TlsAuthentication, 1);
    reconciled(&f.health()[1]);
    assert_eq!(bad.queries.load(Ordering::SeqCst), 0);
    assert_eq!(good.queries.load(Ordering::SeqCst), 1);
    let mut bytes = [0; 4096];
    assert!(
        tokio::time::timeout(Duration::from_millis(30), spy.recv(&mut bytes))
            .await
            .is_err()
    );
}
#[test]
fn tls_trust_input_bounds_and_invalid_der_are_rejected() {
    let cert = rcgen::generate_simple_self_signed(vec!["resolver.test".into()])
        .unwrap()
        .cert
        .pem();
    for pem in [
        "x".repeat(65537),
        cert.repeat(33),
        "-----BEGIN CERTIFICATE-----\nYWJjZA==\n-----END CERTIFICATE-----".into(),
    ] {
        let transport = UpstreamTransport::Tls {
            server_name: "resolver.test".into(),
            ca_pem: Some(pem),
            max_connections: 1,
        };
        assert!(
            Forwarder::with_transport(
                vec!["127.0.0.1:853".parse().unwrap()],
                Duration::from_secs(1),
                &transport
            )
            .is_err()
        );
    }
}

#[tokio::test]
async fn failed_endpoint_cools_down_single_probe_cancels_and_recovers() {
    let bad = Mock::start(3).await;
    let good = Mock::start(0).await;
    let mut transport = good.transport.clone();
    if let UpstreamTransport::Tls {
        ca_pem: Some(pem), ..
    } = &mut transport
        && let UpstreamTransport::Tls {
            ca_pem: Some(other),
            ..
        } = &bad.transport
    {
        pem.push_str(other);
    }
    let f = Arc::new(
        Forwarder::with_transport(
            vec![bad.address, good.address],
            Duration::from_secs(2),
            &transport,
        )
        .unwrap(),
    );
    for _ in 0..3 {
        assert!(f.resolve(&query()).await.is_ok());
    }
    assert_eq!(f.health()[0].admission_status().state, "cooldown");
    for _ in 0..20 {
        assert!(f.resolve(&query()).await.is_ok());
    }
    assert_eq!(bad.queries.load(Ordering::SeqCst), 3);
    assert_eq!(f.health()[0].backoff_skips.load(Ordering::SeqCst), 20);
    // A compiled generation owns fresh endpoint admission, independent of old work.
    let fresh = Forwarder::with_transport(
        vec![bad.address, good.address],
        Duration::from_secs(2),
        &transport,
    )
    .unwrap();
    assert_eq!(fresh.health()[0].admission_status().state, "ready");
    assert!(fresh.resolve(&query()).await.is_ok());
    assert_eq!(bad.queries.load(Ordering::SeqCst), 4);
    bad.mode.store(2, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(260)).await;
    let probe = {
        let f = f.clone();
        tokio::spawn(async move { f.resolve(&query()).await })
    };
    bad.wait_queries(5).await;
    assert_eq!(f.health()[0].admission_status().state, "probing");
    let mut others = vec![];
    for _ in 0..20 {
        let f = f.clone();
        others.push(tokio::spawn(async move { f.resolve(&query()).await }));
    }
    for other in others {
        assert!(other.await.unwrap().is_ok());
    }
    assert_eq!(bad.queries.load(Ordering::SeqCst), 5);
    assert_eq!(f.health()[0].recovery_probes.load(Ordering::SeqCst), 1);
    probe.abort();
    let _ = probe.await;
    failure(&f.health()[0], FailureKind::Cancelled, 1);
    bad.mode.store(0, Ordering::SeqCst);
    assert!(f.resolve(&query()).await.is_ok());
    assert_eq!(f.health()[0].admission_status().state, "ready");
    assert_eq!(f.health()[0].recovery_probes.load(Ordering::SeqCst), 2);
    let fallback_attempts = f.health()[1].attempts.load(Ordering::SeqCst);
    assert!(f.resolve(&query()).await.is_ok());
    assert_eq!(
        f.health()[1].attempts.load(Ordering::SeqCst),
        fallback_attempts
    );
    reconciled(&f.health()[0]);
    reconciled(&f.health()[1]);
}

fn named_query(name: &str) -> Message {
    let mut q = query();
    q.queries[0].set_name(Name::from_ascii(name).unwrap());
    q
}
fn single(mock: &Mock) -> Arc<Forwarder> {
    let mut transport = mock.transport.clone();
    if let UpstreamTransport::Tls {
        max_connections, ..
    } = &mut transport
    {
        *max_connections = 1;
    }
    Arc::new(
        Forwarder::with_transport(vec![mock.address], Duration::from_secs(2), &transport).unwrap(),
    )
}
async fn pending_named(
    f: &Arc<Forwarder>,
    name: &'static str,
) -> tokio::task::JoinHandle<Result<Message, rustwalld_dns_resolver::ResolveError>> {
    let f = f.clone();
    tokio::spawn(async move { f.resolve(&named_query(name)).await })
}
#[tokio::test]
async fn pipelined_replies_can_arrive_out_of_order() {
    let mock = Mock::start(11).await;
    let f = single(&mock);
    f.resolve(&query()).await.unwrap();
    mock.pin_release.send_replace(false);
    let slow = pending_named(&f, "slow-first.test.").await;
    mock.wait_queries(2).await;
    let fast = pending_named(&f, "fast-second.test.").await;
    let fast = fast.await.unwrap().unwrap();
    assert_eq!(fast.queries, named_query("fast-second.test.").queries);
    assert!(!slow.is_finished());
    assert_eq!(mock.accepted.load(Ordering::SeqCst), 1);
    mock.pin_release.send_replace(true);
    let slow = slow.await.unwrap().unwrap();
    assert_eq!(slow.queries, named_query("slow-first.test.").queries);
    drop(f);
    mock.wait_closed().await;
}
#[tokio::test]
async fn cancellation_discards_late_reply_without_failing_an_existing_waiter() {
    let mock = Mock::start(11).await;
    let f = single(&mock);
    f.resolve(&query()).await.unwrap();
    mock.pin_release.send_replace(false);
    let live = pending_named(&f, "slow-live.test.").await;
    mock.wait_queries(2).await;
    let cancelled = pending_named(&f, "cancelled.test.").await;
    mock.wait_queries(3).await;
    cancelled.abort();
    let _ = cancelled.await;
    tokio::time::timeout(Duration::from_secs(1), async {
        while mock.replies.load(Ordering::SeqCst) < 2 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    assert!(!live.is_finished());
    mock.pin_release.send_replace(true);
    assert_eq!(
        live.await.unwrap().unwrap().queries,
        named_query("slow-live.test.").queries
    );
    f.resolve(&query()).await.unwrap();
    assert_eq!(mock.accepted.load(Ordering::SeqCst), 2);
    failure(&f.health()[0], FailureKind::Cancelled, 1);
    drop(f);
    mock.wait_closed().await;
}
#[tokio::test]
async fn loss_unknown_id_and_malformed_frame_fail_all_pending_queries() {
    for mode in [12, 13, 14] {
        let mock = Mock::start(10).await;
        let f = single(&mock);
        f.resolve(&query()).await.unwrap();
        mock.mode.store(mode, Ordering::SeqCst);
        mock.pin_release.send_replace(false);
        let a = pending_named(&f, "first.test.").await;
        let b = pending_named(&f, "second.test.").await;
        let c = pending_named(&f, "third.test.").await;
        mock.wait_queries(4).await;
        assert_eq!(mock.accepted.load(Ordering::SeqCst), 1);
        mock.pin_release.send_replace(true);
        for task in [a, b, c] {
            assert!(task.await.unwrap().is_err());
        }
        let kind = if mode == 12 {
            FailureKind::Connection
        } else {
            FailureKind::DnsResponse
        };
        failure(&f.health()[0], kind, 3);
        mock.mode.store(10, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(260)).await;
        assert!(f.resolve(&query()).await.is_ok());
        drop(f);
        mock.wait_closed().await;
    }
}
#[tokio::test]
async fn pending_capacity_is_bounded_and_released_after_cancellation() {
    let mock = Mock::start(11).await;
    let f = single(&mock);
    f.resolve(&query()).await.unwrap();
    mock.pin_release.send_replace(false);
    let mut tasks = vec![];
    for _ in 0..32 {
        tasks.push(pending_named(&f, "slow-capacity.test.").await);
    }
    mock.wait_queries(9).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(mock.queries.load(Ordering::SeqCst), 9);
    assert_eq!(mock.peak.load(Ordering::SeqCst), 8);
    assert_eq!(mock.active.load(Ordering::SeqCst), 1);
    for task in &tasks {
        task.abort();
    }
    for task in tasks {
        let _ = task.await;
    }
    mock.wait_closed().await;
    mock.pin_release.send_replace(true);
    f.resolve(&query()).await.unwrap();
    drop(f);
    mock.wait_closed().await;
}
#[test]
fn dot_decoder_rejects_trailing_data_and_invalid_envelopes() {
    let mut reply = query().into_response();
    let bytes = reply.to_vec().unwrap();
    assert!(rustwalld_dns_resolver::decode_dot_frame(&bytes).is_ok());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(rustwalld_dns_resolver::decode_dot_frame(&trailing).is_err());
    reply.metadata.truncation = true;
    assert!(rustwalld_dns_resolver::decode_dot_frame(&reply.to_vec().unwrap()).is_err());
    assert!(rustwalld_dns_resolver::decode_dot_frame(&query().to_vec().unwrap()).is_err());
    assert!(rustwalld_dns_resolver::decode_dot_frame(&[0; 11]).is_err());
}
