#![allow(clippy::unwrap_used, clippy::expect_used)]
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{Name, RecordType},
};
use rustwalld_dns::{
    api::{self, AppState},
    store::Store,
};
use rustwalld_dns_core::{Engine, Server, ServerConfig, telemetry::Telemetry};
use rustwalld_dns_filter::{Action, ListInput};
use rustwalld_dns_policy::{PolicyConfigSet, PolicySnapshot};
use serde_json::Value;
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::Semaphore,
    time::timeout,
};
use tokio_util::sync::CancellationToken;
const TOKEN: &str = "local-test-token-at-least-16";
#[path = "support/download_fixture.rs"]
mod download_fixture;

async fn refresh_state(harness: &Harness, outcome: &str) -> Value {
    timeout(Duration::from_secs(5), async {
        loop {
            let status: Value = harness
                .get("/api/v1/filter-refreshes")
                .await
                .json()
                .await
                .unwrap();
            if status["entries"][0]["outcome"] == outcome && status["running"].is_null() {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap()
}
async fn queue_check(harness: &Harness, tag: Option<&str>) -> reqwest::Response {
    let mut request = reqwest::Client::new()
        .post(format!("{}/api/v1/filter-refreshes/check", harness.base))
        .bearer_auth(TOKEN)
        .json(&serde_json::json!({"source":0}));
    if let Some(tag) = tag {
        request = request.header("If-Match", tag);
    }
    request.send().await.unwrap()
}
async fn current_etag(harness: &Harness) -> String {
    harness.get("/api/v1/config").await.headers()["etag"]
        .to_str()
        .unwrap()
        .to_owned()
}

async fn checked(
    harness: &Harness,
    fixture: &download_fixture::Fixture,
    outcome: &str,
    status: u16,
) -> Value {
    let before = fixture.requests.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        queue_check(harness, Some(&current_etag(harness).await))
            .await
            .status(),
        202
    );
    fixture.wait_requests(before + 1).await;
    let state = refresh_state(harness, outcome).await;
    assert_eq!(state["entries"][0]["last_http_status"], status);
    state
}
async fn shadow_action(harness: &Harness, promote: bool) {
    let client = reqwest::Client::new();
    let path = format!(
        "{}/api/v1/shadow{}",
        harness.base,
        if promote { "/promote" } else { "" }
    );
    let request = if promote {
        client.post(path)
    } else {
        client.delete(path)
    };
    let response = request
        .bearer_auth(TOKEN)
        .header("If-Match", current_etag(harness).await)
        .send()
        .await
        .unwrap();
    assert!(
        response.status().is_success(),
        "{}",
        response.text().await.unwrap()
    );
}

async fn preview(
    harness: &Harness,
    config: &PolicyConfigSet,
    etag: Option<&str>,
) -> reqwest::Response {
    let mut request = reqwest::Client::new()
        .post(format!("{}/api/v1/filter-sources/preview", harness.base))
        .bearer_auth(TOKEN)
        .json(&serde_json::json!({"config": config, "source": 0}));
    if let Some(etag) = etag {
        request = request.header("If-Match", etag);
    }
    request.send().await.unwrap()
}

async fn local_dns() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        loop {
            let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let query = Message::from_vec(&buffer[..len]).unwrap();
            let answer = rustwalld_dns_core::reply(&query, ResponseCode::NoError)
                .to_vec()
                .unwrap();
            socket.send_to(&answer, peer).await.unwrap();
        }
    });
    (address, task)
}

struct Harness {
    base: String,
    state: Arc<AppState>,
    path: std::path::PathBuf,
    _dir: tempfile::TempDir,
    stop: CancellationToken,
    db_stop: CancellationToken,
    dns_task: tokio::task::JoinHandle<std::io::Result<()>>,
    api_task: tokio::task::JoinHandle<std::io::Result<()>>,
    done: tokio::sync::oneshot::Receiver<()>,
    refresh_task: tokio::task::JoinHandle<()>,
}
impl Harness {
    async fn start() -> Self {
        let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let path = dir.path().join("dns.sqlite");
        let (telemetry, events) = Telemetry::channel(32);
        let db_stop = CancellationToken::new();
        let (store, done) = Store::start(path.clone(), 10, events, db_stop.clone())
            .await
            .unwrap();
        let mut config = PolicyConfigSet::default();
        config.policies[0].lists = vec![ListInput {
            name: "test".into(),
            action: Action::Block,
            rules: "ads.test".into(),
        }];
        let initial = serde_json::to_string(&config).unwrap();
        store.bootstrap(initial).await.unwrap();
        let (engine, controller) = Engine::controlled(
            PolicySnapshot::compile(config, 1).unwrap(),
            rustwalld_dns_core::EngineConfig {
                cache_entries: 100,
                decision_entries: 100,
                max_inflight: 32,
            },
            telemetry,
        );
        let engine = Arc::new(engine);
        let server = Server::bind(
            ServerConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                ..Default::default()
            },
            engine.clone(),
        )
        .await
        .unwrap();
        let listen = server.local_addr().unwrap();
        let stop = CancellationToken::new();
        let dns_task = tokio::spawn(server.run(stop.clone()));
        let control = Arc::new(
            rustwalld_dns_runtime::ControlService::new(engine, controller, store, listen, 2)
                .unwrap(),
        );
        let state = Arc::new(AppState {
            control: control.clone(),
            api_slots: Arc::new(Semaphore::new(32)),
            token: TOKEN.into(),
        });
        let refresh_task = tokio::spawn(rustwalld_dns::refreshes::run(control, stop.clone()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let router = api::router(state.clone());
        let cancel = stop.clone();
        let api_task = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(cancel.cancelled_owned())
                .await
        });
        Self {
            base,
            state,
            path,
            _dir: dir,
            stop,
            db_stop,
            dns_task,
            api_task,
            done,
            refresh_task,
        }
    }
    async fn get(&self, path: &str) -> reqwest::Response {
        reqwest::Client::new()
            .get(format!("{}{path}", self.base))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap()
    }
    async fn send(&self, path: &str, config: &PolicyConfigSet, put: bool) -> reqwest::Response {
        let client = reqwest::Client::new();
        let url = format!("{}{path}", self.base);
        let request = if put {
            client.put(url)
        } else {
            client.post(url)
        };
        request
            .bearer_auth(TOKEN)
            .json(config)
            .send()
            .await
            .unwrap()
    }
    async fn dns(&self, domain: &str) -> Message {
        let mut request = Message::query();
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(
            Name::from_ascii(domain).unwrap(),
            RecordType::A,
        ));
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket
            .send_to(&request.to_vec().unwrap(), self.state.control.listen)
            .await
            .unwrap();
        let mut bytes = [0; 1232];
        let len = timeout(Duration::from_secs(1), socket.recv(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        Message::from_vec(&bytes[..len]).unwrap()
    }
    async fn shutdown(self) {
        self.stop.cancel();
        self.refresh_task.await.unwrap();
        self.dns_task.await.unwrap().unwrap();
        self.api_task.await.unwrap().unwrap();
        self.db_stop.cancel();
        timeout(Duration::from_secs(2), self.done)
            .await
            .unwrap()
            .unwrap();
    }
}

#[path = "control_plane_cases/cache.rs"]
mod cache;

#[path = "control_plane_cases/downloads.rs"]
mod downloads;

#[path = "control_plane_cases/exceptions.rs"]
mod exceptions;

#[path = "control_plane_cases/management.rs"]
mod management;

#[path = "control_plane_cases/revisions.rs"]
mod revisions;
