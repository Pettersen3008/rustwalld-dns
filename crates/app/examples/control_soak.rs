//! Real-process management/scheduled-list recovery rehearsal. Linux, local DNS only.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "../tests/support/download_fixture.rs"]
mod download_fixture;
#[path = "support/histogram.rs"]
mod histogram;
#[path = "support/resources.rs"]
mod resources;
use clap::Parser;
use hickory_proto::{
    op::{Message, MessageType, Query, ResponseCode},
    rr::{Name, RData, Record, RecordType, rdata::A},
};
use histogram::Histogram;
use policy::{Assertion, DownloadStamp};
use rustwalld_dns::{config::Config, downloads::sha256};
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    net::{SocketAddr, TcpListener},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{net::UdpSocket, task::JoinHandle, time::timeout};
use tokio_util::sync::CancellationToken;
const TOKEN: &str = "control-soak-local-fixture-only";
#[derive(Parser)]
struct Args {
    #[arg(long)]
    binary: PathBuf,
    /// Minimum traffic duration per phase; control operations may extend it.
    #[arg(long, default_value_t = 1000)]
    phase_ms: u64,
    #[arg(long, default_value_t = 3)]
    cycles: usize,
    /// Clients per lane (permanently blocked and cache probe).
    #[arg(long, default_value_t = 2)]
    clients: usize,
    #[arg(long, default_value_t = 100000)]
    rules: usize,
    #[arg(long)]
    output: Option<PathBuf>,
    /// Deliberately corrupt mock A data to verify the correctness gate rejects it.
    #[arg(long)]
    inject_wrong_answer: bool,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Unchanged,
    ChangedAndPromoted,
    PersistenceFailure,
    Recovery,
}
impl Phase {
    fn label(self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::ChangedAndPromoted => "changed_and_promoted",
            Self::PersistenceFailure => "persistence_failure",
            Self::Recovery => "recovery",
        }
    }
}
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        if self.0.try_wait().unwrap().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
fn port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
fn packet(domain: &str, id: u16) -> Message {
    let mut query = Message::query();
    query.metadata.id = id;
    query.metadata.recursion_desired = true;
    let mut name = Name::from_ascii(domain).unwrap();
    name.set_fqdn(true);
    query.add_query(Query::query(name, RecordType::A));
    query
}
async fn socket(address: SocketAddr) -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(address).await.unwrap();
    socket
}
async fn probe(socket: &UdpSocket, query: &Message, code: ResponseCode) -> (u64, bool, bool) {
    let began = Instant::now();
    socket.send(&query.to_vec().unwrap()).await.unwrap();
    let mut bytes = [0; 1232];
    let response = match timeout(Duration::from_millis(250), socket.recv(&mut bytes)).await {
        Ok(Ok(length)) => Message::from_vec(&bytes[..length]).ok(),
        _ => return (began.elapsed().as_micros() as u64, true, false),
    };
    let valid = response.is_some_and(|r| {
        r.metadata.id == query.metadata.id
            && r.metadata.message_type == MessageType::Response
            && r.metadata.op_code == query.metadata.op_code
            && !r.metadata.truncation
            && r.queries == query.queries
            && r.metadata.response_code == code
            && if code == ResponseCode::NoError {
                r.answers.len() == 1
                    && r.answers[0].name == query.queries[0].name().clone()
                    && r.answers[0].data == RData::A(A("192.0.2.1".parse().unwrap()))
            } else {
                r.answers.is_empty()
            }
    });
    (began.elapsed().as_micros() as u64, false, !valid)
}
async fn dns(address: SocketAddr, domain: &str, code: ResponseCode) {
    let result = probe(&socket(address).await, &packet(domain, 123), code).await;
    assert!(
        !result.1 && !result.2,
        "{domain}: timeout={}, wrong={}",
        result.1,
        result.2
    );
}
async fn traffic(address: SocketAddr, clients: usize, stop: CancellationToken) -> Value {
    let began = Instant::now();
    let mut tasks = Vec::new();
    for lane in 0..2 {
        for _ in 0..clients {
            let stop = stop.clone();
            tasks.push((
                lane,
                tokio::spawn(async move {
                    let mut socket = socket(address).await;
                    let mut query = packet(
                        if lane == 0 {
                            "blocked.test"
                        } else {
                            "cached.test"
                        },
                        0,
                    );
                    let code = if lane == 0 {
                        ResponseCode::NXDomain
                    } else {
                        ResponseCode::NoError
                    };
                    let mut histogram = Histogram::new();
                    while !stop.is_cancelled() {
                        query.metadata.id = query.metadata.id.wrapping_add(1);
                        let result = probe(&socket, &query, code).await;
                        histogram.record(result);
                        if result.1 {
                            socket = self::socket(address).await;
                        } // Retire late replies after a timeout.
                    }
                    histogram
                }),
            ));
        }
    }
    let mut lanes = [Histogram::new(), Histogram::new()];
    for (lane, task) in tasks {
        lanes[lane].merge(task.await.unwrap());
    }
    let elapsed = began.elapsed().as_secs_f64();
    let blocked = lanes[0].report();
    let cached = lanes[1].report();
    for lane in [&blocked, &cached] {
        assert!(lane["replies"].as_u64().unwrap() > 0, "no replies: {lane}");
        assert_eq!(lane["timeouts"], 0, "{lane}");
        assert_eq!(lane["incorrect"], 0, "{lane}");
        assert_eq!(lane["latencies_clipped"], 0, "{lane}");
    }
    json!({"blocked":blocked,"cache_probe":cached,"elapsed_ms":began.elapsed().as_millis(),"replies_per_second":(blocked["replies"].as_u64().unwrap()+cached["replies"].as_u64().unwrap()) as f64/elapsed})
}
struct Run {
    client: reqwest::Client,
    base: String,
    address: SocketAddr,
}
impl Run {
    async fn get(&self, path: &str) -> Value {
        self.client
            .get(format!("{}{path}", self.base))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap()
    }
    async fn tag(&self) -> String {
        let response = self
            .client
            .get(format!("{}/api/v1/config", self.base))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        let tag = response.headers()["etag"].to_str().unwrap().to_owned();
        response.bytes().await.unwrap();
        tag
    }
    async fn post(&self, path: &str, body: Value) -> Value {
        self.client
            .post(format!("{}{path}", self.base))
            .bearer_auth(TOKEN)
            .header("If-Match", self.tag().await)
            .json(&body)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap()
    }
    async fn metrics(&self) -> Value {
        let text = self
            .client
            .get(format!("{}/metrics", self.base))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .text()
            .await
            .unwrap();
        let mut result = serde_json::Map::new();
        for line in text
            .lines()
            .filter(|line| line.starts_with("rustwalld_") && !line.contains('{'))
        {
            if let Some((name, value)) = line.split_once(' ') {
                result.insert(name.into(), json!(value.parse::<u64>().unwrap()));
            }
        }
        Value::Object(result)
    }
    async fn check(
        &self,
        publisher: &download_fixture::Fixture,
        outcome: &str,
        status: u16,
        conditional: bool,
    ) -> Value {
        let before = publisher.requests.load(Ordering::SeqCst);
        publisher.conditional_requests.lock().unwrap().clear(); // Keep last-attempt evidence bounded even on repeated runs.
        self.post("/api/v1/filter-refreshes/check", json!({"source":0}))
            .await;
        publisher.wait_requests(before + 1).await;
        let value = timeout(Duration::from_secs(15), async {
            loop {
                let status = self.get("/api/v1/filter-refreshes").await;
                if publisher.requests.load(Ordering::SeqCst) > before
                    && status["running"].is_null()
                    && status["queued"].is_null()
                    && status["entries"][0]["outcome"] == outcome
                {
                    break status;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("scheduled check did not reach expected outcome");
        assert_eq!(value["entries"][0]["last_http_status"], status, "{value}");
        assert_eq!(publisher.requests.load(Ordering::SeqCst), before + 1);
        let request = publisher
            .conditional_requests
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .to_lowercase();
        assert_eq!(request.contains("if-none-match:"), conditional, "{request}");
        publisher.wait_closed().await;
        if status == 304 {
            assert_eq!(value["entries"][0]["last_download_bytes"], 0);
        }
        value
    }
    async fn promote(&self, publisher: &download_fixture::Fixture, marker: &str) -> Value {
        let before = self.get("/api/v1/status").await["generation"]
            .as_u64()
            .unwrap();
        let shadow = self.get("/api/v1/shadow").await;
        assert!(shadow["generation"].as_u64().unwrap() > before);
        assert_eq!(
            self.get("/api/v1/filter-refreshes").await["paused"],
            "shadow_review"
        );
        let fingerprint = sha256(publisher.conditional.lock().unwrap().text.as_bytes());
        assert_eq!(
            shadow["config"]["filter_sources"][0]["download"]["sha256"],
            fingerprint
        );
        dns(self.address, marker, ResponseCode::NoError).await;
        assert_eq!(self.get("/api/v1/status").await["generation"], before);
        let promotion = self.post("/api/v1/shadow/promote", json!({})).await;
        assert!(promotion["generation"].as_u64().unwrap() > shadow["generation"].as_u64().unwrap());
        dns(self.address, marker, ResponseCode::NXDomain).await;
        assert!(self.get("/api/v1/shadow").await["generation"].is_null());
        let unchanged = self.check(publisher, "unchanged", 304, true).await;
        json!({"promoted":promotion,"unchanged":unchanged})
    }
}
async fn boot(args: &Args, config_path: &std::path::Path, run: &Run) -> Process {
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(config_path.with_extension("log"))
        .unwrap();
    let mut child = Process(
        Command::new(&args.binary)
            .args(["--config"])
            .arg(config_path)
            .env("RUSTWALLD_API_TOKEN", TOKEN)
            .env("RUST_LOG", "error")
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap(),
    );
    timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(response) = run.client.get(format!("{}/healthz", run.base)).send().await
                && response.status().is_success()
            {
                break;
            }
            assert!(child.0.try_wait().unwrap().is_none());
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    child
}
async fn shutdown(process: &mut Process) {
    assert!(
        Command::new("kill")
            .args(["-TERM", &process.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    timeout(Duration::from_secs(10), async {
        loop {
            if let Some(status) = process.0.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}
async fn observe(pid: u32, port: u16, run: Arc<Run>, stop: CancellationToken) -> Value {
    let ports = HashSet::from([port]);
    let mut first = None;
    let mut last = None;
    let mut peak = serde_json::Map::new();
    let mut polls = 0;
    while !stop.is_cancelled() {
        let mut value = resources::sample(pid, &ports);
        let status = run.get("/api/v1/status").await;
        value["cache_entries"] = status["cache_entries"].clone();
        value["inflight"] = status["inflight"].clone();
        let refresh = run.get("/api/v1/filter-refreshes").await;
        value["running_downloads"] = json!(usize::from(!refresh["running"].is_null()));
        value["queued_checks"] = json!(usize::from(!refresh["queued"].is_null()));
        assert!(value["cache_entries"].as_u64().unwrap() <= 16, "{value}");
        assert!(value["inflight"].as_u64().unwrap() <= 32, "{value}");
        assert!(value["upstream_sockets"].as_u64().unwrap() <= 2, "{value}");
        assert!(value["fds"].as_u64().unwrap() <= 96, "{value}");
        assert!(value["native_threads"].as_u64().unwrap() <= 32, "{value}");
        if first.is_none() {
            first = Some(value.clone());
        }
        for (key, current) in value.as_object().unwrap() {
            let entry = peak.entry(key.clone()).or_insert(json!(0));
            if current.as_u64() > entry.as_u64() {
                *entry = current.clone();
            }
        }
        last = Some(value);
        polls += 1;
        tokio::select! {_=stop.cancelled()=>{},_=tokio::time::sleep(Duration::from_millis(100))=>{}}
    }
    json!({"polls":polls,"initial":first,"last_sample":last,"peak":peak})
}
async fn phase(
    args: &Args,
    run: &Run,
    publisher: &download_fixture::Fixture,
    config: &Config,
    cycle: usize,
    kind: Phase,
    base_rules: &str,
) -> Value {
    let began = Instant::now();
    let before = run.metrics().await;
    let generation = run.get("/api/v1/status").await["generation"].clone();
    let stop = CancellationToken::new();
    let task: JoinHandle<Value> = tokio::spawn(traffic(run.address, args.clients, stop.clone()));
    let mut lock = None;
    let control;
    let mut marker_queries = 0;
    match kind {
        Phase::Unchanged => {
            let first = run.check(publisher, "unchanged", 304, true).await;
            let second = run.check(publisher, "unchanged", 304, true).await;
            assert_eq!(run.get("/api/v1/status").await["generation"], generation);
            assert!(run.get("/api/v1/shadow").await["generation"].is_null());
            control = json!({"first":first,"second":second});
        }
        Phase::ChangedAndPromoted => {
            let marker = format!("published-{cycle}.test");
            {
                let mut body = publisher.conditional.lock().unwrap();
                body.text = format!("{base_rules}\n={marker}");
                body.etag = Some(format!("\"published-{cycle}\""));
            }
            let check = run.check(publisher, "staged", 200, true).await;
            assert_eq!(run.get("/api/v1/status").await["generation"], generation);
            let promotion = run.promote(publisher, &marker).await;
            marker_queries = 2;
            control = json!({"check":check,"promotion":promotion});
        }
        Phase::PersistenceFailure => {
            let marker = format!("recovered-{cycle}.test");
            {
                let mut body = publisher.conditional.lock().unwrap();
                body.text = format!("{base_rules}\n={marker}");
                body.etag = Some(format!("\"recovered-{cycle}\""));
            }
            let connection = rusqlite::Connection::open(&config.database).unwrap();
            connection.busy_timeout(Duration::from_secs(3)).unwrap();
            connection.execute_batch("BEGIN IMMEDIATE").unwrap();
            lock = Some(connection);
            let check = run.check(publisher, "failed", 200, true).await;
            // A short run can otherwise release the lock before the separate
            // history batch has exhausted SQLite's busy timeout.
            timeout(Duration::from_secs(3), async {
                loop {
                    if run.metrics().await["rustwalld_history_write_failures_total"]
                        .as_u64()
                        .unwrap()
                        > before["rustwalld_history_write_failures_total"]
                            .as_u64()
                            .unwrap()
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            })
            .await
            .expect("history write failure was not observed while locked");

            assert_eq!(run.get("/api/v1/status").await["generation"], generation);
            assert!(run.get("/api/v1/shadow").await["generation"].is_null());
            dns(run.address, &marker, ResponseCode::NoError).await;
            marker_queries = 1;
            control = json!({"check":check});
        }
        Phase::Recovery => {
            let marker = format!("recovered-{cycle}.test");
            let check = run.check(publisher, "staged", 200, false).await;
            let promotion = run.promote(publisher, &marker).await;
            marker_queries = 2;
            control = json!({"check":check,"promotion":promotion});
        }
    }
    tokio::time::sleep_until(tokio::time::Instant::from_std(
        began + Duration::from_millis(args.phase_ms),
    ))
    .await;
    stop.cancel();
    let data = task.await.unwrap();
    if let Some(connection) = lock {
        connection.execute_batch("ROLLBACK").unwrap();
    }
    let after = run.metrics().await;
    let queries = after["rustwalld_requests_total"].as_u64().unwrap()
        - before["rustwalld_requests_total"].as_u64().unwrap();
    let replies = data["blocked"]["replies"].as_u64().unwrap()
        + data["cache_probe"]["replies"].as_u64().unwrap();
    assert_eq!(
        queries,
        replies + marker_queries,
        "query counter reconciliation: {}",
        kind.label()
    );
    assert_eq!(
        after["rustwalld_failures_total"],
        before["rustwalld_failures_total"],
        "DNS failed during {}",
        kind.label()
    );
    assert_eq!(
        after["rustwalld_inflight_overloads_total"],
        before["rustwalld_inflight_overloads_total"]
    );
    if kind == Phase::Recovery {
        assert!(
            after["rustwalld_history_events_total"].as_u64().unwrap()
                > before["rustwalld_history_events_total"].as_u64().unwrap(),
            "history did not resume"
        );
    }
    if kind == Phase::PersistenceFailure {
        assert!(
            after["rustwalld_history_write_failures_total"]
                .as_u64()
                .unwrap()
                > before["rustwalld_history_write_failures_total"]
                    .as_u64()
                    .unwrap()
        );
    }
    json!({"cycle":cycle,"kind":kind.label(),"control":control,"dns":data,"metrics_before":before,"metrics_after":after})
}
#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let args = Args::parse();
    assert!((100..=60000).contains(&args.phase_ms));
    assert!((1..=16).contains(&args.cycles));
    assert!((1..=16).contains(&args.clients));
    assert!((1..=500000).contains(&args.rules));
    let started = Instant::now();
    let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let publisher = download_fixture::Fixture::start().await;
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let exchanges = Arc::new(AtomicU64::new(0));
    let count = exchanges.clone();
    let wrong = args.inject_wrong_answer;
    let mock = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        loop {
            let (size, peer) = upstream.recv_from(&mut bytes).await.unwrap();
            let query = Message::from_vec(&bytes[..size]).unwrap();
            count.fetch_add(1, Ordering::Relaxed);
            let mut reply = dns_core::reply(&query, ResponseCode::NoError);
            reply.add_answer(Record::from_rdata(
                query.queries[0].name().clone(),
                3600,
                RData::A(A(if wrong { "192.0.2.99" } else { "192.0.2.1" }
                    .parse()
                    .unwrap())),
            ));
            upstream
                .send_to(&reply.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let mut config = Config {
        dns_listen: SocketAddr::from(([127, 0, 0, 1], port())),
        api_listen: SocketAddr::from(([127, 0, 0, 1], port())),
        database: dir.path().join("dns.sqlite"),
        dns_cache_entries: 16,
        decision_cache_entries: 16,
        max_inflight: 32,
        max_udp_queries: 64,
        event_queue: 16,
        history_rows: 1000,
        ..Default::default()
    };
    while config.api_listen == config.dns_listen
        || config.api_listen == upstream_addr
        || config.dns_listen == upstream_addr
        || config.api_listen == publisher.address
        || config.dns_listen == publisher.address
    {
        config.api_listen.set_port(port());
        config.dns_listen.set_port(port());
    }
    let base_rules = format!(
        "blocked.test\n{}",
        (0..args.rules)
            .map(|i| format!("=b{i}.test\n"))
            .collect::<String>()
    );
    config.policy.upstreams[0].addresses = vec![upstream_addr];
    config.policy.policies[0].lists = vec![filtering::ListInput {
        name: "base".into(),
        action: filtering::Action::Block,
        rules: base_rules.clone(),
    }];
    config.policy.assertions = vec![
        Assertion {
            client: "127.0.0.1".parse().unwrap(),
            domain: "blocked.test".into(),
            expected: filtering::Action::Block,
        },
        Assertion {
            client: "127.0.0.1".parse().unwrap(),
            domain: "cached.test".into(),
            expected: filtering::Action::Allow,
        },
    ];
    publisher.conditional.lock().unwrap().text = base_rules.clone();
    let mut source = publisher.source("/conditional");
    source.list = "base".into();
    source.refresh_interval_secs = Some(policy::MAX_REFRESH_INTERVAL);
    source.download = Some(DownloadStamp {
        retrieved_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        bytes: base_rules.len(),
        sha256: sha256(base_rules.as_bytes()),
    });
    config.policy.filter_sources = vec![source];
    let config_path = dir.path().join("config.toml");
    std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
    let run = Arc::new(Run {
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap(),
        base: format!("http://{}", config.api_listen),
        address: config.dns_listen,
    });
    let mut process = boot(&args, &config_path, &run).await;
    dns(run.address, "blocked.test", ResponseCode::NXDomain).await;
    dns(run.address, "cached.test", ResponseCode::NoError).await;
    run.check(&publisher, "unchanged", 200, false).await;
    let observing = CancellationToken::new();
    let observer = tokio::spawn(observe(
        process.0.id(),
        publisher.address.port(),
        run.clone(),
        observing.clone(),
    ));
    let mut phases = Vec::new();
    let mut settled = Vec::new();
    let ports = HashSet::from([publisher.address.port()]);
    for cycle in 0..args.cycles {
        for kind in [
            Phase::Unchanged,
            Phase::ChangedAndPromoted,
            Phase::PersistenceFailure,
            Phase::Recovery,
        ] {
            let result = phase(&args, &run, &publisher, &config, cycle, kind, &base_rules).await;
            eprintln!(
                "cycle {cycle} {}: blocked p99={} us, cache-probe p99={} us, replies={}",
                kind.label(),
                result["dns"]["blocked"]["p99_us"],
                result["dns"]["cache_probe"]["p99_us"],
                result["dns"]["blocked"]["replies"].as_u64().unwrap()
                    + result["dns"]["cache_probe"]["replies"].as_u64().unwrap()
            );
            phases.push(result);
            assert!(!observer.is_finished(), "resource observer stopped early");
        }
        publisher.wait_closed().await;
        let value = resources::sample(process.0.id(), &ports);
        assert_eq!(value["upstream_sockets"], 0);
        settled.push(value);
    }
    assert!(
        run.metrics().await["rustwalld_events_dropped_total"]
            .as_u64()
            .unwrap()
            > 0
    );
    let final_status = run.get("/api/v1/status").await;
    let active = final_status["generation"].as_u64().unwrap();
    let fingerprint = sha256(publisher.conditional.lock().unwrap().text.as_bytes());
    assert_eq!(
        run.get("/api/v1/filter-sources").await["sources"][0]["download"]["sha256"],
        fingerprint
    );
    observing.cancel();
    let observed = observer.await.unwrap();
    shutdown(&mut process).await;
    publisher.wait_closed().await;
    let connection = rusqlite::Connection::open(&config.database).unwrap();
    let durable: i64 = connection
        .query_row("SELECT value FROM runtime WHERE key='active'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(u64::try_from(durable).unwrap(), active);
    let history: i64 = connection
        .query_row("SELECT COUNT(*) FROM queries", [], |r| r.get(0))
        .unwrap();
    assert!((1..=1000).contains(&history));
    let revisions: i64 = connection
        .query_row("SELECT COUNT(*) FROM revisions", [], |r| r.get(0))
        .unwrap();
    assert!(revisions <= 34);
    drop(connection);
    let before = publisher.requests.load(Ordering::SeqCst);
    let mut restarted = boot(&args, &config_path, &run).await;
    assert_eq!(run.get("/api/v1/status").await["generation"], active);
    dns(
        run.address,
        &format!("recovered-{}.test", args.cycles - 1),
        ResponseCode::NXDomain,
    )
    .await;
    assert_eq!(publisher.requests.load(Ordering::SeqCst), before);
    let relearn = run.check(&publisher, "unchanged", 200, false).await;
    let reused = run.check(&publisher, "unchanged", 304, true).await;
    assert_eq!(run.get("/api/v1/status").await["generation"], active);
    shutdown(&mut restarted).await;
    publisher.wait_closed().await;
    mock.abort();
    let output = |cmd: &str, arg: &str| {
        String::from_utf8(Command::new(cmd).arg(arg).output().unwrap().stdout)
            .unwrap()
            .trim()
            .to_owned()
    };
    let report = json!({"hardware":std::fs::read_to_string("/proc/cpuinfo").unwrap().lines().find(|l|l.starts_with("model name")).unwrap_or("unknown"),"os":output("uname","-srmo"),"rustc":output("rustc","--version"),"binary":args.binary,"binary_sha256":sha256(&std::fs::read(&args.binary).unwrap()),"cycles":args.cycles,"clients_per_lane":args.clients,"rules":args.rules+1,"phase_minimum_ms":args.phase_ms,"elapsed_ms":started.elapsed().as_millis(),"histogram":"exact us through 1 ms, 100 us upper bounds thereafter, 1 s cap; fixed 11001 bins per client", "phases":phases,"sampled_resources":observed,"settled_after_cycles":settled,"final_status":final_status,"durable_generation":durable,"history_rows":history,"retained_revisions":revisions,"publisher_requests":publisher.requests.load(Ordering::SeqCst),"upstream_exchanges":exchanges.load(Ordering::Relaxed),"restart":{"relearn":relearn,"reuse":reused},"process_log":std::fs::read_to_string(config_path.with_extension("log")).unwrap()});
    if let Some(path) = args.output {
        std::fs::write(path, serde_json::to_string_pretty(&report).unwrap() + "\n").unwrap();
    }
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixture_questions_survive_dns_wire_round_trip() {
        for domain in ["blocked.test", "cached.test.", "recovered-15.test"] {
            let original = packet(domain, 123);
            let decoded = Message::from_vec(&original.to_vec().unwrap()).unwrap();
            assert_eq!(decoded.queries, original.queries);
        }
    }
}
