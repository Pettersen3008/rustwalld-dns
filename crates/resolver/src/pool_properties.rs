//! Pool lifecycle model: cancelled calls may finish or cancel; survivors must
//! match their question. After each round all request capacity is restored;
//! after drop, every physical lease and every peer connection is released.
#![allow(clippy::unwrap_used)]
#[path = "../tests/support/https.rs"]
mod https_fixture;
#[path = "../tests/support/tls.rs"]
mod tls_fixture;
use crate::{Endpoint, Forwarder, UpstreamTransport};
use hickory_proto::{
    op::{Message, Query},
    rr::{Name, RData, RecordType, rdata::A},
};
use proptest::{prelude::*, test_runner::FileFailurePersistence};
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;

enum Fixture {
    Dot(tls_fixture::Mock),
    Doh(https_fixture::Mock),
}
impl Fixture {
    async fn start(https: bool) -> Self {
        if https {
            Self::Doh(https_fixture::Mock::with_streams(17, 100).await)
        } else {
            Self::Dot(tls_fixture::Mock::start(10).await)
        }
    }
    fn transport(&self, connections: usize) -> UpstreamTransport {
        let mut transport = match self {
            Self::Dot(f) => f.transport.clone(),
            Self::Doh(f) => f.transport.clone(),
        };
        match &mut transport {
            UpstreamTransport::Tls {
                max_connections, ..
            }
            | UpstreamTransport::Https {
                max_connections, ..
            } => *max_connections = connections,
            _ => unreachable!(),
        }
        transport
    }
    fn address(&self) -> std::net::SocketAddr {
        match self {
            Self::Dot(f) => f.address,
            Self::Doh(f) => f.address,
        }
    }
    async fn closed(&self) {
        match self {
            Self::Dot(f) => f.wait_closed().await,
            Self::Doh(f) => f.wait_closed().await,
        }
    }
}
// Kept only while checking a round; capacity handles do not retain a pool.
enum Pool {
    Dot(Arc<crate::tls::TlsPool>),
    Doh(Arc<crate::https::HttpsPool>),
}
impl Pool {
    fn from(forwarder: &Forwarder) -> Self {
        match &forwarder.endpoints[0] {
            Endpoint::Tls(pool) => Self::Dot(pool.clone()),
            Endpoint::Https(pool) => Self::Doh(pool.clone()),
            _ => unreachable!(),
        }
    }
    fn capacity(&self) -> (Arc<Semaphore>, Arc<Semaphore>) {
        match self {
            Self::Dot(p) => p.test_capacity(),
            Self::Doh(p) => p.test_capacity(),
        }
    }
    fn loads(&self) -> Vec<usize> {
        match self {
            Self::Dot(p) => p.test_loads(),
            Self::Doh(p) => p.test_loads(),
        }
    }
}
fn query(round: usize, index: u8) -> Message {
    let mut request = Message::query();
    request.add_query(Query::query(
        Name::from_ascii(format!("r{round}-q{index}.model.test.")).unwrap(),
        RecordType::A,
    ));
    request
}
async fn run_model(https: bool, connections: usize, rounds: Vec<(u8, u64, u8)>) {
    let fixture = Fixture::start(https).await;
    let forwarder = Arc::new(
        Forwarder::with_transport(
            vec![fixture.address()],
            Duration::from_secs(2),
            &fixture.transport(connections),
        )
        .unwrap(),
    );
    let pool = Pool::from(&forwarder);
    let (requests, physical) = pool.capacity();
    let request_limit = connections * 8;
    for (round, (clients, cancelled, delay)) in rounds.into_iter().enumerate() {
        let mut tasks = vec![];
        for index in 0..clients {
            let forwarder = forwarder.clone();
            tasks.push(tokio::spawn(async move {
                let request = query(round, index);
                let response = forwarder.resolve(&request).await.unwrap();
                assert_eq!(response.queries, request.queries);
                assert_eq!(response.answers.len(), 1);
                assert_eq!(
                    response.answers[0].data,
                    RData::A(A("192.0.2.1".parse().unwrap()))
                );
            }));
        }
        // Zero cancels before first poll; later values cover connect/handshake,
        // active requests, stream-capacity waits and already completed callers.
        for _ in 0..delay {
            tokio::time::sleep(Duration::from_millis(1)).await;
            assert!(pool.loads().into_iter().all(|load| load <= 8));
            assert!(requests.available_permits() <= request_limit);
        }
        for (index, task) in tasks.iter().enumerate() {
            if cancelled & (1_u64 << index) != 0 {
                task.abort();
            }
        }
        for (index, task) in tasks.into_iter().enumerate() {
            match task.await {
                Ok(()) => {}
                Err(error) => {
                    assert!(
                        cancelled & (1_u64 << index) != 0 && error.is_cancelled(),
                        "surviving caller failed: {error}"
                    );
                }
            }
        }
        // A successful next lookup is the liveness witness: usable capacity was
        // not stranded by a cancellation during connect/admission/active IO.
        forwarder.resolve(&query(round, 255)).await.unwrap();
        assert_eq!(requests.available_permits(), request_limit);
        assert!(pool.loads().into_iter().all(|load| load == 0));
        assert_eq!(forwarder.health()[0].snapshot().inflight, 0);
    }
    assert_eq!(Arc::strong_count(&forwarder), 1);
    drop(forwarder);
    drop(pool);
    fixture.closed().await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while physical.available_permits() != connections {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(requests.available_permits(), request_limit);
}
fn config() -> ProptestConfig {
    ProptestConfig {
        cases: std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(32),
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../target/review/property-tests/pool-regressions.txt"
        )))),
        ..Default::default()
    }
}
proptest! {
    #![proptest_config(config())]
    #[test]
    fn dot_pool_randomized_cancellation_model(
        connections in 1_usize..4,
        rounds in prop::collection::vec((1_u8..41,any::<u64>(),0_u8..17),1..7),
    ) {
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        runtime.block_on(run_model(false,connections,rounds));
    }
    #[test]
    fn doh_pool_randomized_cancellation_model(
        connections in 1_usize..4,
        rounds in prop::collection::vec((1_u8..41,any::<u64>(),0_u8..17),1..7),
    ) {
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        runtime.block_on(run_model(true,connections,rounds));
    }
}
