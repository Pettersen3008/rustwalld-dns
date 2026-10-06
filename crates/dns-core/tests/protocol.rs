#![allow(clippy::unwrap_used, clippy::expect_used)]
use hickory_proto::{
    op::{Message, OpCode, Query, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, AAAA, CNAME},
    },
};
use rustwalld_dns_core::telemetry::Telemetry;
use rustwalld_dns_core::{Server, ServerConfig, reply};
use rustwalld_dns_policy::{Binding, PolicyConfig, TemporaryException};
use rustwalld_dns_policy::{PolicyConfigSet, PolicySnapshot};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinHandle,
    time::timeout,
};
use tokio_util::sync::CancellationToken;

fn exception_expiry(seconds: u64) -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + seconds
}
async fn wait_exception_expiry(expiry: u64) {
    let remaining = (std::time::UNIX_EPOCH + Duration::from_secs(expiry))
        .duration_since(std::time::SystemTime::now())
        .unwrap_or_default();
    tokio::time::sleep(remaining + Duration::from_millis(20)).await;
}
fn temporary_config(mock: &Mock, expiry: u64) -> PolicyConfigSet {
    let mut config = PolicyConfigSet::default();
    config.upstreams[0].addresses = vec![mock.addr];
    config.upstreams[0].timeout_ms = 5000;
    config.policies[0].lists = vec![rustwalld_dns_filter::ListInput {
        name: "deny".into(),
        action: rustwalld_dns_filter::Action::Block,
        rules: "example".into(),
    }];
    config.policies[0].temporary_exceptions = vec![TemporaryException {
        name: "repair".into(),
        domain: "test.example".into(),
        expires_at: expiry,
    }];
    config
}

struct Mock {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
    cancel: CancellationToken,
    task: JoinHandle<()>,
}
impl Mock {
    async fn start(truncated: bool, spoof: bool) -> Self {
        Self::with_delay(truncated, spoof, Duration::ZERO).await
    }
    async fn with_delay(truncated: bool, spoof: bool, delay: Duration) -> Self {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let udp = UdpSocket::bind(addr).await.unwrap();
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let hits = Arc::new(AtomicUsize::new(0));
        let counts = hits.clone();
        let task = tokio::spawn(async move {
            let mut buffer = vec![0; 65535];
            loop {
                tokio::select! {
                    _ = stop.cancelled() => break,
                    packet = udp.recv_from(&mut buffer) => {
                        let (len, peer) = packet.unwrap(); let request = Message::from_vec(&buffer[..len]).unwrap();
                        counts.fetch_add(1, Ordering::Relaxed);
                    tokio::time::sleep(delay).await;
                        let mut response = answer(&request);
                        if spoof {
                            response.metadata.id = response.metadata.id.wrapping_add(1);
                            udp.send_to(&response.to_vec().unwrap(), peer).await.unwrap();
                            response.metadata.id = request.metadata.id;
                            response.queries[0].set_name(Name::from_ascii("wrong.example.").unwrap());
                            udp.send_to(&response.to_vec().unwrap(), peer).await.unwrap();
                            response = answer(&request);
                        }
                        response.metadata.truncation = truncated;
                        udp.send_to(&response.to_vec().unwrap(), peer).await.unwrap();
                    }
                    connection = tcp.accept() => {
                        let (mut stream, _) = connection.unwrap();
                        let len = stream.read_u16().await.unwrap() as usize;
                        let mut bytes = vec![0;len]; stream.read_exact(&mut bytes).await.unwrap();
                        let request = Message::from_vec(&bytes).unwrap();
                        let bytes = answer(&request).to_vec().unwrap();
                        stream.write_u16(bytes.len() as u16).await.unwrap(); stream.write_all(&bytes).await.unwrap();
                    }
                }
            }
        });
        Self {
            addr,
            hits,
            cancel,
            task,
        }
    }
}
impl Drop for Mock {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}
fn query(kind: RecordType) -> Message {
    let mut request = Message::new(42, hickory_proto::op::MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(
        Name::from_ascii("test.example.").unwrap(),
        kind,
    ));
    request
}
fn answer(request: &Message) -> Message {
    let mut out = reply(request, ResponseCode::NoError);
    let question = &request.queries[0];
    let data = match question.query_type() {
        RecordType::AAAA => RData::AAAA(AAAA("2001:db8::1".parse().unwrap())),
        RecordType::CNAME => RData::CNAME(CNAME(Name::from_ascii("target.example.").unwrap())),
        _ => RData::A(A("192.0.2.1".parse().unwrap())),
    };
    out.add_answer(Record::from_rdata(question.name().clone(), 60, data));
    out
}
async fn server(
    upstreams: Vec<SocketAddr>,
) -> (
    SocketAddr,
    CancellationToken,
    JoinHandle<std::io::Result<()>>,
) {
    let mut config = PolicyConfigSet::default();
    config.upstreams[0].addresses = upstreams;
    config.upstreams[0].timeout_ms = 100;
    let (telemetry, _receiver) = Telemetry::channel(1000);
    let engine = Arc::new(Engine::new(
        PolicySnapshot::compile(config, 1).unwrap(),
        4096,
        4096,
        256,
        telemetry,
    ));
    let server = Server::bind(
        ServerConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        },
        engine.handle(),
    )
    .await
    .unwrap();
    let addr = server.local_addr().unwrap();
    let cancel = CancellationToken::new();
    let task = tokio::spawn(server.run(cancel.clone()));
    (addr, cancel, task)
}
async fn udp_query(addr: SocketAddr, query: &Message) -> Message {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .send_to(&query.to_vec().unwrap(), addr)
        .await
        .unwrap();
    let mut bytes = vec![0; 65535];
    let (len, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    Message::from_vec(&bytes[..len]).unwrap()
}

fn engine_for(
    mock: &Mock,
    capacity: usize,
    inflight: usize,
) -> (
    Arc<Engine>,
    tokio::sync::mpsc::Receiver<rustwalld_dns_core::telemetry::QueryEvent>,
) {
    let mut config = PolicyConfigSet::default();
    config.upstreams[0].addresses = vec![mock.addr];
    config.upstreams[0].timeout_ms = 500;
    let (telemetry, receiver) = Telemetry::channel(capacity);
    (
        Arc::new(Engine::new(
            PolicySnapshot::compile(config, 1).unwrap(),
            1000,
            1000,
            inflight,
            telemetry,
        )),
        receiver,
    )
}

#[path = "../../resolver/tests/support/tls.rs"]
mod tls_fixture;

#[path = "../../resolver/tests/support/https.rs"]
mod https_fixture;

#[path = "protocol_cases/cache.rs"]
mod cache;

#[path = "protocol_cases/exceptions.rs"]
mod exceptions;

#[path = "protocol_cases/protocol.rs"]
mod protocol;

#[path = "protocol_cases/revisions.rs"]
mod revisions;

#[path = "support/engine.rs"]
mod engine_support;
use engine_support::TestEngine as Engine;
