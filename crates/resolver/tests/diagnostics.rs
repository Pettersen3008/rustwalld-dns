#![allow(clippy::unwrap_used)]
mod support {
    pub mod diagnostics;
}
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{Name, RecordType},
};
use rustwalld_dns_resolver::{FailureKind, Forwarder};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};
use support::diagnostics::{failure, reconciled};
use tokio::net::UdpSocket;

#[tokio::test]
async fn udp_failures_fallback_recovery_and_untrusted_packet_deadline() {
    let primary = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let secondary = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addresses = vec![
        primary.local_addr().unwrap(),
        secondary.local_addr().unwrap(),
    ];
    let mode = Arc::new(AtomicU8::new(1));
    let primary_task = {
        let mode = mode.clone();
        tokio::spawn(async move {
            let mut bytes = [0; 4096];
            loop {
                let (len, source) = primary.recv_from(&mut bytes).await.unwrap();
                let request = Message::from_vec(&bytes[..len]).unwrap();
                let mut response = request.into_response();
                match mode.load(Ordering::SeqCst) {
                    1 => response.metadata.response_code = ResponseCode::ServFail,
                    2 => response.metadata.response_code = ResponseCode::Refused,
                    3 => response.metadata.id = response.metadata.id.wrapping_add(1),
                    4 => {
                        primary.send_to(&[255; 12], source).await.unwrap();
                        continue;
                    }
                    _ => {}
                }
                primary
                    .send_to(&response.to_vec().unwrap(), source)
                    .await
                    .unwrap();
            }
        })
    };
    let secondary_task = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        loop {
            let (len, source) = secondary.recv_from(&mut bytes).await.unwrap();
            let response = Message::from_vec(&bytes[..len]).unwrap().into_response();
            secondary
                .send_to(&response.to_vec().unwrap(), source)
                .await
                .unwrap();
        }
    });
    let f = Forwarder::new(addresses, Duration::from_millis(50)).unwrap();
    let mut request = Message::query();
    request.add_query(Query::query(
        Name::from_ascii("allowed.test.").unwrap(),
        RecordType::A,
    ));
    for next in 1..=4 {
        mode.store(next, Ordering::SeqCst);
        assert_eq!(
            f.resolve(&request).await.unwrap().metadata.response_code,
            ResponseCode::NoError
        );
    }
    failure(&f.health()[0], FailureKind::Servfail, 1);
    failure(&f.health()[0], FailureKind::Refused, 1);
    failure(&f.health()[0], FailureKind::Deadline, 2);
    failure(&f.health()[0], FailureKind::DnsResponse, 0);
    assert_eq!(f.health()[1].successes.load(Ordering::SeqCst), 4);
    mode.store(0, Ordering::SeqCst);
    assert!(f.resolve(&request).await.is_ok());
    reconciled(&f.health()[0]);
    reconciled(&f.health()[1]);
    assert_eq!(f.health()[0].attempts.load(Ordering::SeqCst), 5);
    assert_eq!(f.health()[0].successes.load(Ordering::SeqCst), 1);
    assert_eq!(f.health()[1].attempts.load(Ordering::SeqCst), 4);
    primary_task.abort();
    secondary_task.abort();
    let _ = primary_task.await;
    let _ = secondary_task.await;
}

#[tokio::test]
async fn closed_tcp_endpoint_is_connection_failure() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let f = Forwarder::with_transport(
        vec![address],
        Duration::from_millis(200),
        &rustwalld_dns_resolver::UpstreamTransport::Tls {
            server_name: "resolver.test".into(),
            ca_pem: None,
            max_connections: 1,
        },
    )
    .unwrap();
    assert!(f.resolve(&Message::query()).await.is_err());
    failure(&f.health()[0], FailureKind::Connection, 1);
    for _ in 0..2 {
        assert!(f.resolve(&Message::query()).await.is_err());
    }
    for _ in 0..50 {
        assert!(f.resolve(&Message::query()).await.is_err());
    }
    failure(&f.health()[0], FailureKind::Connection, 3);
    assert_eq!(f.health()[0].backoff_skips.load(Ordering::SeqCst), 50);
    assert_eq!(f.health()[0].attempts.load(Ordering::SeqCst), 3);
    reconciled(&f.health()[0]);
}

#[test]
fn local_encoding_errors_and_tls_protocol_errors_are_not_text_matched() {
    assert_eq!(
        rustwalld_dns_resolver::ResolveError::Encoding.failure_kind(),
        FailureKind::LocalError
    );
    let textual = std::io::Error::other("invalid peer certificate: expired");
    assert_eq!(
        rustwalld_dns_resolver::ResolveError::Io(textual).failure_kind(),
        FailureKind::Connection
    );
    let typed = std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        tokio_rustls::rustls::Error::General("test protocol failure".into()),
    );
    assert_eq!(
        rustwalld_dns_resolver::ResolveError::Io(typed).failure_kind(),
        FailureKind::TlsProtocol
    );
}
