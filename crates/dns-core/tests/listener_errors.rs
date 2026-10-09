//! Listener failures must not end DNS service. This lowers the process
//! descriptor limit, so it lives in its own test binary with a single test.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{Name, RecordType},
};
use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
use rustwalld_dns_core::{
    Engine, EngineConfig, PolicyConfigSet, PolicySnapshot, Server, ServerConfig, Telemetry,
};
use std::{fs::File, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;

// ANY is refused locally, so no upstream (and no public DNS) is involved.
fn refused_query() -> Vec<u8> {
    let mut request = Message::new(7, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(
        Name::from_ascii("listener.test.").unwrap(),
        RecordType::ANY,
    ));
    request.to_vec().unwrap()
}

async fn udp_exchange(server: SocketAddr) -> Message {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(&refused_query(), server).await.unwrap();
    let mut buffer = vec![0; 4096];
    let len = timeout(Duration::from_secs(2), socket.recv(&mut buffer))
        .await
        .expect("UDP answer while TCP accept was failing")
        .unwrap();
    Message::from_vec(&buffer[..len]).unwrap()
}

#[tokio::test]
async fn descriptor_exhaustion_pauses_accept_without_ending_service() {
    let (telemetry, _events) = Telemetry::channel(16);
    let engine = Arc::new(Engine::with_config(
        PolicySnapshot::compile(PolicyConfigSet::default(), 1).unwrap(),
        EngineConfig::default(),
        telemetry,
    ));
    let server = Server::bind(
        ServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        },
        engine.clone(),
    )
    .await
    .unwrap();
    let address = server.local_addr().unwrap();
    let cancel = CancellationToken::new();
    let task = tokio::spawn(server.run(cancel.clone()));

    // Fill the descriptor table, leaving exactly one slot for a client socket.
    // The kernel completes the handshake, so the server's accept then fails
    // with EMFILE until descriptors are released.
    let original = getrlimit(Resource::Nofile);
    setrlimit(
        Resource::Nofile,
        Rlimit {
            current: Some(256),
            maximum: original.maximum,
        },
    )
    .unwrap();
    let mut filler = Vec::new();
    loop {
        match File::open("/dev/null") {
            Ok(file) => filler.push(file),
            Err(error) if error.raw_os_error() == Some(rustix::io::Errno::MFILE.raw_os_error()) => {
                break;
            }
            Err(error) => panic!("unexpected open failure: {error}"),
        }
    }
    filler.pop();
    let mut stream = TcpStream::connect(address).await.unwrap();
    sleep(Duration::from_millis(300)).await;
    let failures = engine
        .telemetry()
        .metrics
        .listener_errors
        .load(std::sync::atomic::Ordering::Relaxed);
    drop(filler);
    setrlimit(Resource::Nofile, original).unwrap();
    assert!(!task.is_finished(), "server stopped after an accept error");
    assert!(failures > 0, "accept never observed descriptor exhaustion");

    // UDP kept working, and the paused TCP listener accepts the waiting client.
    assert_eq!(
        udp_exchange(address).await.metadata.response_code,
        ResponseCode::Refused
    );
    let query = refused_query();
    stream
        .write_all(&u16::try_from(query.len()).unwrap().to_be_bytes())
        .await
        .unwrap();
    stream.write_all(&query).await.unwrap();
    let len = timeout(Duration::from_secs(2), stream.read_u16())
        .await
        .expect("TCP answer after descriptors were released")
        .unwrap();
    let mut bytes = vec![0; usize::from(len)];
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(
        Message::from_vec(&bytes).unwrap().metadata.response_code,
        ResponseCode::Refused
    );

    cancel.cancel();
    timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
