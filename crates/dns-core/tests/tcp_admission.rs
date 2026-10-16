//! Non-admitted TCP peers must not hold connection slots that admitted clients need.
//! Uses two loopback source addresses (Linux routes all of 127.0.0.0/8 locally).
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{Name, RecordType},
};
use rustwalld_dns_core::{
    Engine, EngineConfig, PolicyConfigSet, PolicySnapshot, Server, ServerConfig, Telemetry,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, TcpStream},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

// ANY is refused locally, so no upstream (and no public DNS) is involved.
fn refused_query() -> Vec<u8> {
    let mut request = Message::new(9, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(
        Name::from_ascii("admission.test.").unwrap(),
        RecordType::ANY,
    ));
    request.to_vec().unwrap()
}

async fn connect_from(source: &str, server: SocketAddr) -> TcpStream {
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind(format!("{source}:0").parse().unwrap()).unwrap();
    socket.connect(server).await.unwrap()
}

#[tokio::test]
async fn unadmitted_tcp_peer_is_closed_without_consuming_a_connection_slot() {
    let config = PolicyConfigSet {
        allowed_clients: vec!["127.0.0.1/32".parse().unwrap()],
        ..Default::default()
    };
    let (telemetry, _events) = Telemetry::channel(16);
    let engine = Arc::new(Engine::with_config(
        PolicySnapshot::compile(config, 1).unwrap(),
        EngineConfig::default(),
        telemetry,
    ));
    let server = Server::bind(
        ServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            max_tcp_connections: 1,
            tcp_idle_timeout: Duration::from_secs(30),
            ..Default::default()
        },
        engine.clone(),
    )
    .await
    .unwrap();
    let address = server.local_addr().unwrap();
    let cancel = CancellationToken::new();
    let task = tokio::spawn(server.run(cancel.clone()));

    // An idle connection from a source outside allowed_clients is closed at once.
    let mut denied = connect_from("127.0.0.2", address).await;
    let mut byte = [0; 1];
    let read = timeout(Duration::from_secs(2), denied.read(&mut byte))
        .await
        .expect("non-admitted TCP peer must be closed promptly");
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");

    // The single slot stays free for an admitted client while the peer lingers.
    let mut allowed = connect_from("127.0.0.1", address).await;
    let query = refused_query();
    let mut frame = u16::try_from(query.len()).unwrap().to_be_bytes().to_vec();
    frame.extend_from_slice(&query);
    allowed.write_all(&frame).await.unwrap();
    let len = timeout(Duration::from_secs(2), allowed.read_u16())
        .await
        .expect("admitted TCP client must be answered")
        .unwrap();
    let mut reply = vec![0; usize::from(len)];
    allowed.read_exact(&mut reply).await.unwrap();
    let reply = Message::from_vec(&reply).unwrap();
    assert_eq!(reply.metadata.id, 9);
    assert_eq!(reply.metadata.response_code, ResponseCode::Refused);
    assert_eq!(engine.telemetry().metrics.snapshot().tcp_overloads, 0);

    drop(denied);
    cancel.cancel();
    task.await.unwrap().unwrap();
}
