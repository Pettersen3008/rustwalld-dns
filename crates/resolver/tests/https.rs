#![allow(clippy::unwrap_used)]
mod support {
    pub mod diagnostics;
    pub mod https;
}
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{Name, RecordType},
};
use http::{HeaderMap, StatusCode, header};
use rustwalld_dns_resolver::{
    FailureKind, Forwarder, UpstreamTransport,
    https::decode_response,
    response_cache::{CacheKey, ResponseCache},
};
use std::{
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};
use support::{
    diagnostics::{failure, reconciled},
    https::Mock,
};
fn query() -> Message {
    let mut q = Message::new(0, MessageType::Query, OpCode::Query);
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
async fn trusted_warm_reuse_age_and_retirement() {
    let mock = Mock::start(0).await;
    let f = forward(&mock);
    for _ in 0..10 {
        assert_eq!(f.resolve(&query()).await.unwrap().answers[0].ttl, 60);
    }
    assert_eq!(mock.accepted.load(Ordering::SeqCst), 1);
    mock.mode.store(5, Ordering::SeqCst);
    assert_eq!(f.resolve(&query()).await.unwrap().answers[0].ttl, 50);
    drop(f);
    mock.wait_closed().await;
}
#[tokio::test]
async fn http_envelopes_and_malformed_dns_are_rejected() {
    for (mode, kind) in [
        (1, FailureKind::HttpStatus),
        (2, FailureKind::HttpStatus),
        (3, FailureKind::HttpEnvelope),
        (4, FailureKind::HttpEnvelope),
        (6, FailureKind::HttpEnvelope),
        (7, FailureKind::HttpEnvelope),
        (8, FailureKind::HttpProtocol),
        (11, FailureKind::DnsResponse),
        (12, FailureKind::DnsResponse),
        (13, FailureKind::DnsResponse),
        (14, FailureKind::DnsResponse),
        (19, FailureKind::HttpEnvelope),
        (22, FailureKind::HttpProtocol),
    ] {
        let mock = Mock::start(mode).await;
        let f = forward(&mock);
        assert!(f.resolve(&query()).await.is_err(), "mode {mode}");
        failure(&f.health[0], kind, 1);
        assert_eq!(mock.queries.load(Ordering::SeqCst), 1, "mode {mode}");
    }
}
#[tokio::test]
async fn negative_http_age_is_subtracted_from_soa_minimum_before_caching() {
    for mode in [20, 21] {
        let mock = Mock::start(mode).await;
        let response = forward(&mock).resolve(&query()).await.unwrap();
        assert_eq!(response.authorities[0].ttl, 20);
        let now = Instant::now();
        let cache = ResponseCache::new(8);
        let key = CacheKey::new(&query(), 0, 1).unwrap();
        assert!(cache.insert(key.clone(), response, now));
        assert!(cache.get(&key, now + Duration::from_secs(19)).is_some());
        assert!(cache.get(&key, now + Duration::from_secs(20)).is_none());
    }
}
#[tokio::test]
async fn certificates_alpn_and_handshake_deadline_are_required() {
    let mock = Mock::start(0).await;
    for untrusted in [false, true] {
        let mut config = mock.transport.clone();
        if let UpstreamTransport::Https {
            server_name,
            ca_pem,
            ..
        } = &mut config
        {
            if untrusted {
                *ca_pem = None;
            } else {
                *server_name = "wrong.test".into();
            }
        }
        let f = Forwarder::with_transport(vec![mock.address], Duration::from_millis(200), &config)
            .unwrap();
        assert!(f.resolve(&query()).await.is_err());
        failure(&f.health[0], FailureKind::TlsAuthentication, 1);
    }
    assert_eq!(mock.queries.load(Ordering::SeqCst), 0);
    let expired = Mock::with_expiry(0, true).await;
    let f = forward(&expired);
    assert!(f.resolve(&query()).await.is_err());
    failure(&f.health[0], FailureKind::TlsAuthentication, 1);
    for mode in [15, 16] {
        let mock = Mock::start(mode).await;
        let f = forward(&mock);
        assert!(f.resolve(&query()).await.is_err());
        failure(
            &f.health[0],
            if mode == 15 {
                FailureKind::TlsProtocol
            } else {
                FailureKind::Deadline
            },
            1,
        );
        assert_eq!(mock.queries.load(Ordering::SeqCst), 0);
    }
}
#[tokio::test]
async fn concurrent_queries_obey_pool_limit_and_cancelled_sockets_are_disposed() {
    let mock = Mock::start(17).await;
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
        assert!(task.await.unwrap().is_ok());
    }
    assert_eq!(mock.accepted.load(Ordering::SeqCst), 2);
    reconciled(&f.health[0]);
    assert_eq!(f.health[0].successes.load(Ordering::SeqCst), 32);
    drop(f);
    mock.wait_closed().await;
    for mode in [9, 10] {
        let mock = Mock::start(mode).await;
        let mut config = mock.transport.clone();
        if let UpstreamTransport::Https {
            max_connections, ..
        } = &mut config
        {
            *max_connections = 1;
        }
        let f = Arc::new(
            Forwarder::with_transport(vec![mock.address], Duration::from_millis(200), &config)
                .unwrap(),
        );
        let task = {
            let f = f.clone();
            tokio::spawn(async move { f.resolve(&query()).await })
        };
        mock.wait_queries(1).await;
        task.abort();
        let _ = task.await;
        mock.mode.store(0, Ordering::SeqCst);
        assert!(f.resolve(&query()).await.is_ok());
        failure(&f.health[0], FailureKind::Cancelled, 1);
        assert_eq!(f.health[0].successes.load(Ordering::SeqCst), 1);
        // Pool owns only the new valid socket; cancelled driver disposes old TLS.
        drop(f);
        mock.wait_closed().await;
        assert_eq!(mock.accepted.load(Ordering::SeqCst), 2);
    }
}
#[tokio::test]
async fn stalled_headers_and_body_expire_and_can_reconnect() {
    for mode in [9, 10] {
        let mock = Mock::start(mode).await;
        let f = forward(&mock);
        assert!(f.resolve(&query()).await.is_err());
        mock.mode.store(0, Ordering::SeqCst);
        assert!(f.resolve(&query()).await.is_ok());
        failure(&f.health[0], FailureKind::Deadline, 1);
        assert_eq!(f.health[0].successes.load(Ordering::SeqCst), 1);
        assert_eq!(mock.accepted.load(Ordering::SeqCst), 2);
    }
}
#[tokio::test]
async fn fallback_is_sequential_and_redirects_cannot_leak_plaintext_queries() {
    let bad = Mock::start(9).await;
    let good = Mock::start(0).await;
    let mut config = good.transport.clone();
    if let UpstreamTransport::Https {
        ca_pem: Some(pem), ..
    } = &mut config
        && let UpstreamTransport::Https {
            ca_pem: Some(other),
            ..
        } = &bad.transport
    {
        pem.push_str(other);
    }
    let f = Arc::new(
        Forwarder::with_transport(
            vec![bad.address, good.address],
            Duration::from_millis(100),
            &config,
        )
        .unwrap(),
    );
    let task = {
        let f = f.clone();
        tokio::spawn(async move { f.resolve(&query()).await })
    };
    bad.wait_queries(1).await;
    assert_eq!(good.accepted.load(Ordering::SeqCst), 0);
    assert!(task.await.unwrap().is_ok());
    failure(&f.health[0], FailureKind::Deadline, 1);
    reconciled(&f.health[1]);
    let redirect = Mock::start(2).await;
    let observer = tokio::net::UdpSocket::bind(redirect.address).await.unwrap();
    assert!(forward(&redirect).resolve(&query()).await.is_err());
    assert_eq!(redirect.accepted.load(Ordering::SeqCst), 1);
    let mut bytes = [0; 4096];
    assert!(
        tokio::time::timeout(Duration::from_millis(30), observer.recv(&mut bytes))
            .await
            .is_err()
    );
}
#[test]
fn endpoint_and_envelope_boundaries_fail_closed() {
    for path in [
        "http://host/path",
        "//host/path",
        "/dns-query#fragment",
        "/dns query",
        "",
    ] {
        let config = UpstreamTransport::Https {
            server_name: "resolver.test".into(),
            path: path.into(),
            ca_pem: None,
            max_connections: 2,
        };
        assert!(
            Forwarder::with_transport(
                vec!["127.0.0.1:443".parse().unwrap()],
                Duration::from_secs(1),
                &config
            )
            .is_err()
        );
    }
    let request = query();
    let response = request.clone().into_response().to_vec().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "application/dns-message".parse().unwrap(),
    );
    for age in ["-1", "+1", "1,2", ""] {
        headers.insert(header::AGE, age.parse().unwrap());
        assert!(decode_response(&request, StatusCode::OK, &headers, &response).is_err());
    }
    headers.remove(header::AGE);
    headers.append(
        header::CONTENT_TYPE,
        "application/dns-message".parse().unwrap(),
    );
    assert!(decode_response(&request, StatusCode::OK, &headers, &response).is_err());
    headers.remove(header::CONTENT_TYPE);
    headers.insert(
        header::CONTENT_TYPE,
        "Application/DNS-Message".parse().unwrap(),
    );
    assert!(decode_response(&request, StatusCode::OK, &headers, &response).is_ok());
    headers.insert(header::CONTENT_LENGTH, "99".parse().unwrap());
    assert!(decode_response(&request, StatusCode::OK, &headers, &response).is_err());
}

#[test]
fn trailing_dns_data_is_rejected_and_expired_http_data_is_not_cached() {
    let request = query();
    let mut response = request.clone().into_response();
    response.add_answer(hickory_proto::rr::Record::from_rdata(
        request.queries[0].name().clone(),
        60,
        hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A("192.0.2.1".parse().unwrap())),
    ));
    let mut bytes = response.to_vec().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "application/dns-message".parse().unwrap(),
    );
    bytes.push(0);
    assert!(decode_response(&request, StatusCode::OK, &headers, &bytes).is_err());
    bytes.pop();
    headers.insert(header::AGE, "999999999999999999999999999".parse().unwrap());
    let response = decode_response(&request, StatusCode::OK, &headers, &bytes).unwrap();
    assert_eq!(response.answers[0].ttl, 0);
    assert!(!ResponseCache::new(8).insert(
        CacheKey::new(&request, 0, 1).unwrap(),
        response,
        Instant::now()
    ));
}

#[tokio::test]
async fn remotely_closed_idle_connection_reconnects_to_same_endpoint() {
    let mock = Mock::start(0).await;
    let f = forward(&mock);
    assert!(f.resolve(&query()).await.is_ok());
    mock.disconnect.send_modify(|epoch| *epoch += 1);
    mock.wait_closed().await;
    assert!(f.resolve(&query()).await.is_ok());
    assert_eq!(mock.accepted.load(Ordering::SeqCst), 2);
    drop(f);
    mock.wait_closed().await;
}

#[tokio::test]
async fn malformed_http_on_reused_connection_is_not_retried() {
    let mock = Mock::start(0).await;
    let f = forward(&mock);
    assert!(f.resolve(&query()).await.is_ok());
    mock.mode.store(8, Ordering::SeqCst);
    assert!(f.resolve(&query()).await.is_err());
    assert_eq!(mock.queries.load(Ordering::SeqCst), 2);
    assert_eq!(mock.accepted.load(Ordering::SeqCst), 1);
    drop(f);
    mock.wait_closed().await;
}

#[tokio::test]
async fn failed_endpoint_cools_down_single_probe_cancels_and_recovers() {
    let bad = Mock::start(12).await;
    let good = Mock::start(0).await;
    let mut transport = good.transport.clone();
    if let UpstreamTransport::Https {
        ca_pem: Some(pem), ..
    } = &mut transport
        && let UpstreamTransport::Https {
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
    assert_eq!(f.health[0].admission_status().state, "cooldown");
    for _ in 0..20 {
        assert!(f.resolve(&query()).await.is_ok());
    }
    assert_eq!(bad.queries.load(Ordering::SeqCst), 3);
    assert_eq!(f.health[0].backoff_skips.load(Ordering::SeqCst), 20);
    // A compiled generation owns fresh endpoint admission, independent of old work.
    let fresh = Forwarder::with_transport(
        vec![bad.address, good.address],
        Duration::from_secs(2),
        &transport,
    )
    .unwrap();
    assert_eq!(fresh.health[0].admission_status().state, "ready");
    assert!(fresh.resolve(&query()).await.is_ok());
    assert_eq!(bad.queries.load(Ordering::SeqCst), 4);
    bad.mode.store(9, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(260)).await;
    let probe = {
        let f = f.clone();
        tokio::spawn(async move { f.resolve(&query()).await })
    };
    bad.wait_queries(5).await;
    assert_eq!(f.health[0].admission_status().state, "probing");
    let mut others = vec![];
    for _ in 0..20 {
        let f = f.clone();
        others.push(tokio::spawn(async move { f.resolve(&query()).await }));
    }
    for other in others {
        assert!(other.await.unwrap().is_ok());
    }
    assert_eq!(bad.queries.load(Ordering::SeqCst), 5);
    assert_eq!(f.health[0].recovery_probes.load(Ordering::SeqCst), 1);
    probe.abort();
    let _ = probe.await;
    failure(&f.health[0], FailureKind::Cancelled, 1);
    bad.mode.store(0, Ordering::SeqCst);
    assert!(f.resolve(&query()).await.is_ok());
    assert_eq!(f.health[0].admission_status().state, "ready");
    assert_eq!(f.health[0].recovery_probes.load(Ordering::SeqCst), 2);
    let fallback_attempts = f.health[1].attempts.load(Ordering::SeqCst);
    assert!(f.resolve(&query()).await.is_ok());
    assert_eq!(
        f.health[1].attempts.load(Ordering::SeqCst),
        fallback_attempts
    );
    reconciled(&f.health[0]);
    reconciled(&f.health[1]);
}
