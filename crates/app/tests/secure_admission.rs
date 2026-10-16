//! Encrypted DNS ingress closes non-admitted peers before a slot or TLS handshake.
//! Uses two loopback source addresses (Linux routes all of 127.0.0.0/8 locally).
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use axum::serve::Listener;
use rustwalld_dns::tls::{SecureListener, from_pem};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpSocket, TcpStream},
    time::timeout,
};
use tokio_rustls::{
    TlsConnector,
    rustls::{ClientConfig, RootCertStore, pki_types::ServerName},
};

async fn connect_from(source: &str, server: SocketAddr) -> TcpStream {
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind(format!("{source}:0").parse().unwrap()).unwrap();
    socket.connect(server).await.unwrap()
}

#[tokio::test]
async fn unadmitted_peer_is_closed_before_slot_or_handshake() {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["dns.test".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let acceptor = from_pem(cert.pem().as_bytes(), key.serialize_pem().as_bytes(), false)
        .ok()
        .unwrap();
    let inner = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = inner.local_addr().unwrap();
    let mut listener = SecureListener::new(inner, acceptor, 1)
        .with_admission(Arc::new(|peer| peer == std::net::Ipv4Addr::LOCALHOST));
    let server = tokio::spawn(async move { listener.accept().await.1 });

    // A non-admitted peer that never sends a ClientHello would otherwise hold
    // the only slot for the five-second handshake deadline.
    let mut denied = connect_from("127.0.0.2", address).await;
    let mut byte = [0; 1];
    let read = timeout(Duration::from_secs(2), denied.read(&mut byte))
        .await
        .expect("non-admitted peer must be closed promptly");
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");

    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let connector = TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));
    let stream = connect_from("127.0.0.1", address).await;
    let client = tokio::spawn(async move {
        connector
            .connect(ServerName::try_from("dns.test").unwrap(), stream)
            .await
    });
    let peer = timeout(Duration::from_secs(2), server)
        .await
        .expect("admitted peer must complete its handshake in the free slot")
        .unwrap();
    assert_eq!(peer.ip(), std::net::Ipv4Addr::LOCALHOST);
    client.await.unwrap().unwrap();
    drop(denied);
}
