//! Real-process encrypted-upstream failure rehearsal. Linux /proc, local DNS only.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "support/histogram.rs"]
mod histogram;
#[path = "../../resolver/tests/support/https.rs"]
mod https;
#[path = "support/resources.rs"]
mod resources;
#[path = "../../resolver/tests/support/tls.rs"]
mod tls;
use clap::Parser;
use hickory_proto::{
    op::{Message, MessageType, Query, ResponseCode},
    rr::{Name, RData, RecordType, rdata::A},
};
use histogram::Histogram;
use policy::{Assertion, PolicyConfigSet, UpstreamTransport};
use rustwalld_dns::config::Config;
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    net::{SocketAddr, TcpListener},
    os::unix::process::ExitStatusExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, sync::Barrier, time::timeout};
const TOKEN: &str = "encrypted-resilience-local-fixture-only";
const DEADLINE: Duration = Duration::from_millis(500);
#[derive(Parser)]
struct Args {
    #[arg(long)]
    binary: PathBuf,
    /// Duration of each sustained phase, for each transport.
    #[arg(long, default_value_t = 1000)]
    duration_ms: u64,
    /// Clients per lane (blocked, cached, fresh-name).
    #[arg(long, default_value_t = 2)]
    clients: usize,
    #[arg(long)]
    output: Option<PathBuf>,
    /// Sample only the real daemon during each malformed-outage phase.
    #[arg(long)]
    profile_outage_dir: Option<PathBuf>,
    /// Local perf executable; only used with --profile-outage-dir.
    #[arg(long, default_value = "perf")]
    perf: PathBuf,
}
enum Endpoint {
    Tls(tls::Mock),
    Https(https::Mock),
}
impl Endpoint {
    async fn start(https: bool) -> Self {
        if https {
            Self::Https(https::Mock::start(0).await)
        } else {
            Self::Tls(tls::Mock::start(0).await)
        }
    }
    fn address(&self) -> SocketAddr {
        match self {
            Self::Tls(m) => m.address,
            Self::Https(m) => m.address,
        }
    }
    fn transport(&self) -> UpstreamTransport {
        match self {
            Self::Tls(m) => m.transport.clone(),
            Self::Https(m) => m.transport.clone(),
        }
    }
    fn mode(&self, value: u8) {
        match self {
            Self::Tls(m) => &m.mode,
            Self::Https(m) => &m.mode,
        }
        .store(value, Ordering::SeqCst);
    }
    fn queries(&self) -> usize {
        match self {
            Self::Tls(m) => &m.queries,
            Self::Https(m) => &m.queries,
        }
        .load(Ordering::SeqCst)
    }
    async fn closed(&self) {
        match self {
            Self::Tls(m) => m.wait_closed().await,
            Self::Https(m) => m.wait_closed().await,
        }
    }
    async fn pinned(&self, domain: &str) {
        let marker = match self {
            Self::Tls(m) => &m.pinned,
            Self::Https(m) => &m.pinned,
        };
        let reached = timeout(Duration::from_secs(2), async {
            while marker.borrow().as_deref() != Some(domain) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await;
        assert!(
            reached.is_ok(),
            "retired request {domain} did not reach fixture: {}",
            self.counters()
        );
    }
    fn release(&self, value: bool) {
        match self {
            Self::Tls(m) => &m.pin_release,
            Self::Https(m) => &m.pin_release,
        }
        .send_replace(value);
    }
    fn counters(&self) -> Value {
        let (accepted, active) = match self {
            Self::Tls(m) => (&m.accepted, &m.active),
            Self::Https(m) => (&m.accepted, &m.active),
        };
        json!({"address":self.address(),"accepted":accepted.load(Ordering::SeqCst),"active":active.load(Ordering::SeqCst),"queries":self.queries()})
    }
}
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
// Developer-only sampling: never part of the appliance or ordinary benchmark.
// Own-process user CPU only; no kernel permissions/configuration changes.
fn start_sampler(args: &Args, pid: u32, https: bool) -> Option<(Process, PathBuf)> {
    let directory = args.profile_outage_dir.as_ref()?;
    std::fs::create_dir_all(directory).unwrap();
    let transport = if https { "https" } else { "tls" };
    let output = directory.join(format!("{transport}-outage.data"));
    let log = std::fs::File::create(directory.join(format!("{transport}-outage.log"))).unwrap();
    let child = Command::new(&args.perf)
        .env("DEBUGINFOD_URLS", "")
        .args([
            "record",
            "--no-buildid-cache",
            "-e",
            "cpu-clock:u",
            "-F",
            "997",
            "--call-graph",
            "dwarf,16384",
            "--pid",
        ])
        .arg(pid.to_string())
        .arg("-o")
        .arg(&output)
        .stdout(Stdio::null())
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();
    Some((Process(child), output))
}
async fn stop_sampler(mut sampler: Process) {
    assert!(
        sampler.0.try_wait().unwrap().is_none(),
        "perf exited before profiling completed"
    );
    assert!(
        Command::new("kill")
            .arg("-INT")
            .arg(sampler.0.id().to_string())
            .status()
            .unwrap()
            .success()
    );
    timeout(Duration::from_secs(10), async {
        loop {
            if let Some(status) = sampler.0.try_wait().unwrap() {
                // perf flushes its recording, then propagates the explicit SIGINT.
                assert!(
                    status.success() || status.signal() == Some(2),
                    "perf recording failed: {status}"
                );
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}
fn port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
fn packet(domain: &str, id: u16) -> Message {
    let mut q = Message::query();
    q.metadata.id = id;
    q.metadata.recursion_desired = true;
    q.add_query(Query::query(
        Name::from_ascii(domain).unwrap(),
        RecordType::A,
    ));
    q
}
async fn probe(socket: &UdpSocket, domain: &str, id: u16, code: ResponseCode) -> (u64, bool, bool) {
    let query = packet(domain, id);
    let began = Instant::now();
    socket.send(&query.to_vec().unwrap()).await.unwrap();
    let mut buffer = [0; 1232];
    let received = timeout(DEADLINE, socket.recv(&mut buffer)).await;
    let response = match received {
        Ok(Ok(len)) => Message::from_vec(&buffer[..len]).ok(),
        _ => return (began.elapsed().as_micros() as u64, true, false),
    };
    let valid = response.is_some_and(|r| {
        r.metadata.id == id
            && r.metadata.message_type == MessageType::Response
            && r.metadata.op_code == query.metadata.op_code
            && r.queries == query.queries
            && r.metadata.response_code == code
            && !r.metadata.truncation
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
async fn socket(address: SocketAddr) -> UdpSocket {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.connect(address).await.unwrap();
    s
}
async fn samples(
    address: SocketAddr,
    name: &str,
    duration: Duration,
    clients: usize,
    outage: bool,
) -> Value {
    let until = Instant::now() + duration;
    let began = Instant::now();
    let mut tasks = Vec::new();
    for lane in 0..3 {
        for client in 0..clients {
            let name = name.to_owned();
            tasks.push(tokio::spawn(async move {
                let s = socket(address).await;
                let mut stats = Histogram::new();
                let mut n = 0_u64;
                while Instant::now() < until {
                    let domain = match lane {
                        0 => "blocked.test.".into(),
                        1 => format!("cached-{name}.test."),
                        _ => format!("miss-{name}-{client}-{n}.test."),
                    };
                    let code = if lane == 0 {
                        ResponseCode::NXDomain
                    } else if lane == 2 && outage {
                        ResponseCode::ServFail
                    } else {
                        ResponseCode::NoError
                    };
                    stats.record(probe(&s, &domain, n as u16, code).await);
                    n += 1;
                }
                (lane, stats)
            }));
        }
    }
    let mut lanes = [Histogram::new(), Histogram::new(), Histogram::new()];
    for t in tasks {
        let (lane, data) = t.await.unwrap();
        lanes[lane].merge(data);
    }
    json!({"elapsed_ms":began.elapsed().as_millis(),"blocked":lanes[0].report(),"cached":lanes[1].report(),"fresh":lanes[2].report(),"fresh_expected_code":if outage {"SERVFAIL"} else {"NOERROR"}})
}
// Called only when traffic has drained. Relaxed live API reads are otherwise
// deliberately not a coherent transactional accounting snapshot.
async fn diagnostics(client: &reqwest::Client, base: &str) -> Value {
    let profiles = get(client, base, "/api/v1/upstreams").await;
    for profile in profiles.as_array().unwrap() {
        for server in profile["servers"].as_array().unwrap() {
            assert_eq!(server["inflight"], 0, "{server}");
            let failures = server["failures"].as_object().unwrap();
            assert_eq!(failures.len(), resolver::FailureKind::ALL.len());
            for kind in resolver::FailureKind::ALL {
                assert!(failures.contains_key(json!(kind).as_str().unwrap()));
            }
            assert_eq!(
                server["attempts"].as_u64().unwrap(),
                server["successes"].as_u64().unwrap()
                    + failures
                        .values()
                        .map(|value| value.as_u64().unwrap())
                        .sum::<u64>(),
                "{server}"
            );
        }
    }
    profiles
}
fn diagnostic_delta(before: &Value, after: &Value) -> Value {
    assert_eq!(before[0]["generation"], after[0]["generation"]);
    let servers = before[0]["servers"].as_array().unwrap().iter()
        .zip(after[0]["servers"].as_array().unwrap()).map(|(before, after)| {
            assert_eq!(before["address"], after["address"]);
            let mut failures = serde_json::Map::new();
            for (kind, count) in after["failures"].as_object().unwrap() {
                failures.insert(kind.clone(), json!(count.as_u64().unwrap() - before["failures"][kind].as_u64().unwrap()));
            }
            json!({"address":after["address"],
                "attempts":after["attempts"].as_u64().unwrap() - before["attempts"].as_u64().unwrap(),
                "successes":after["successes"].as_u64().unwrap() - before["successes"].as_u64().unwrap(),
                "backoff_skips":after["backoff_skips"].as_u64().unwrap_or(0) - before["backoff_skips"].as_u64().unwrap_or(0),
                "recovery_probes":after["recovery_probes"].as_u64().unwrap_or(0) - before["recovery_probes"].as_u64().unwrap_or(0),
                "failures":failures})
        }).collect::<Vec<_>>();
    json!({"generation":after[0]["generation"],"servers":servers})
}
async fn get(client: &reqwest::Client, base: &str, path: &str) -> Value {
    client
        .get(format!("{base}{path}"))
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
async fn metric(client: &reqwest::Client, base: &str, key: &str) -> u64 {
    let text = client
        .get(format!("{base}/metrics"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    text.lines()
        .find_map(|line| {
            line.strip_prefix(&format!("rustwalld_{key}_total "))
                .map(|v| v.parse().unwrap())
        })
        .unwrap()
}
// Namespace TCP tables are filtered by this child's owned socket inodes.
async fn observe(
    pid: u32,
    ports: HashSet<u16>,
    client: reqwest::Client,
    base: String,
    running: Arc<AtomicBool>,
) -> Value {
    let mut peak = serde_json::Map::new();
    let mut polls = 0;
    let mut initial = None;
    let mut last = None;
    while running.load(Ordering::Relaxed) {
        let mut current = resources::sample(pid, &ports);
        let status = get(&client, &base, "/api/v1/status").await;
        current["inflight"] = status["inflight"].clone();
        current["cache_entries"] = status["cache_entries"].clone();
        if initial.is_none() {
            initial = Some(current.clone());
        }
        assert!(
            current["upstream_sockets"].as_u64().unwrap() <= 8,
            "{current}"
        );
        assert!(current["inflight"].as_u64().unwrap() <= 32, "{current}");
        assert!(
            current["cache_entries"].as_u64().unwrap() <= 64,
            "{current}"
        );
        for (k, v) in current.as_object().unwrap() {
            let entry = peak.entry(k.clone()).or_insert(json!(0));
            if v.as_u64() > entry.as_u64() {
                *entry = v.clone();
            }
        }
        polls += 1;
        last = Some(current);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    json!({"polls":polls,"initial":initial,"last_sample":last,"peak":peak})
}
async fn warm(address: SocketAddr, domain: &str) {
    let (_, lost, wrong) = probe(&socket(address).await, domain, 123, ResponseCode::NoError).await;
    assert!(
        !lost && !wrong,
        "cache warm-up failed for {domain}: timeout={lost}, unexpected_response={wrong}"
    );
}
async fn coalescing(
    address: SocketAddr,
    endpoints: &[Endpoint],
    client: &reqwest::Client,
    base: &str,
    https: bool,
) -> Value {
    endpoints[0].mode(if https { 9 } else { 2 });
    endpoints[1].mode(if https { 17 } else { 8 });
    let before = metric(client, base, "upstream_lookups").await;
    let follower = metric(client, base, "coalesced").await;
    let counts = [endpoints[0].queries(), endpoints[1].queries()];
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for id in 0..16 {
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            let s = socket(address).await;
            barrier.wait().await;
            probe(&s, "coalesced-burst.test.", id, ResponseCode::NoError).await
        }));
    }
    for t in tasks {
        let (_, lost, wrong) = t.await.unwrap();
        assert!(
            !lost && !wrong,
            "coalescing query failed: timeout={lost}, unexpected_response={wrong}, diagnostics={}",
            get(client, base, "/api/v1/upstreams").await
        );
    }
    let lookups = metric(client, base, "upstream_lookups").await - before;
    let followers = metric(client, base, "coalesced").await - follower;
    assert_eq!(lookups, 1);
    assert_eq!(followers, 15);
    let delta = [
        endpoints[0].queries() - counts[0],
        endpoints[1].queries() - counts[1],
    ];
    assert_eq!(delta, [1, 1]);
    json!({"client_queries":16,"lookups":lookups,"coalesced":followers,"endpoint_exchanges":delta})
}
async fn promote(client: &reqwest::Client, base: &str, policy: &PolicyConfigSet) -> Value {
    let revision = client
        .get(format!("{base}/api/v1/config"))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap();
    let tag = revision.headers()[http::header::ETAG].clone();
    client
        .put(format!("{base}/api/v1/config"))
        .bearer_auth(TOKEN)
        .header(http::header::IF_MATCH, tag)
        .json(policy)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}
async fn run(args: &Args, https: bool) -> Value {
    let mut endpoints = Vec::new();
    for _ in 0..4 {
        endpoints.push(Endpoint::start(https).await);
    }
    let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let mut config = Config {
        dns_listen: SocketAddr::from(([127, 0, 0, 1], port())),
        api_listen: SocketAddr::from(([127, 0, 0, 1], port())),
        database: dir.path().join("dns.sqlite"),
        dns_cache_entries: 64,
        decision_cache_entries: 64,
        max_inflight: 32,
        max_udp_queries: 128,
        event_queue: 64,
        history_rows: 256,
        ..Default::default()
    };
    while config.api_listen == config.dns_listen
        || endpoints
            .iter()
            .any(|e| e.address() == config.api_listen || e.address() == config.dns_listen)
    {
        config.api_listen.set_port(port());
        config.dns_listen.set_port(port());
    }
    let mut roots = String::new();
    for e in &endpoints {
        match e.transport() {
            UpstreamTransport::Tls { ca_pem, .. } | UpstreamTransport::Https { ca_pem, .. } => {
                roots.push_str(&ca_pem.unwrap())
            }
            _ => unreachable!(),
        }
    }
    config.policy.upstreams[0].transport = endpoints[0].transport();
    match &mut config.policy.upstreams[0].transport {
        UpstreamTransport::Tls { ca_pem, .. } | UpstreamTransport::Https { ca_pem, .. } => {
            *ca_pem = Some(roots)
        }
        _ => unreachable!(),
    }
    config.policy.upstreams[0].addresses = vec![endpoints[0].address(), endpoints[1].address()];
    config.policy.upstreams[0].timeout_ms = 80;
    config.policy.policies[0].lists = vec![filtering::ListInput {
        name: "base".into(),
        action: filtering::Action::Block,
        rules: "blocked.test".into(),
    }];
    config.policy.assertions = vec![Assertion {
        client: "127.0.0.1".parse().unwrap(),
        domain: "blocked.test".into(),
        expected: filtering::Action::Block,
    }];
    let path = dir.path().join("config.toml");
    std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
    let log_path = dir.path().join("process.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let mut process = Process(
        Command::new(&args.binary)
            .arg("--config")
            .arg(path)
            .env("RUSTWALLD_API_TOKEN", TOKEN)
            .env("RUST_LOG", "error")
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap(),
    );
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let base = format!("http://{}", config.api_listen);
    timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(r) = client.get(format!("{base}/healthz")).send().await
                && r.status().is_success()
            {
                break;
            }
            assert!(
                process.0.try_wait().unwrap().is_none(),
                "{}",
                std::fs::read_to_string(&log_path).unwrap()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let running = Arc::new(AtomicBool::new(true));
    let observer = tokio::spawn(observe(
        process.0.id(),
        endpoints.iter().map(|e| e.address().port()).collect(),
        client.clone(),
        base.clone(),
        running.clone(),
    ));
    let burst = coalescing(config.dns_listen, &endpoints, &client, &base, https).await;
    let cases: Vec<(&str, u8, u8, bool)> = if https {
        vec![
            ("baseline", 17, 17, false),
            ("stall", 9, 17, false),
            ("stall-body", 10, 17, false),
            ("invalid-dns", 12, 17, false),
            ("reset", 22, 17, false),
            ("invalid-http", 8, 17, false),
            ("outage", 12, 12, true),
            ("outage-stall", 9, 9, true),
            ("recovery", 17, 17, false),
        ]
    } else {
        vec![
            ("baseline", 8, 8, false),
            ("stall", 2, 8, false),
            ("invalid-dns", 3, 8, false),
            ("reset", 9, 8, false),
            ("outage", 3, 3, true),
            ("outage-stall", 2, 2, true),
            ("recovery", 8, 8, false),
        ]
    };
    let mut phases = serde_json::Map::new();
    for (name, bad, good, outage) in cases {
        endpoints[0].mode(0);
        endpoints[1].mode(0);
        // Restore primary admission outside the measured window. The same
        // harness accepts the pre-backoff binary, whose status field is absent.
        let recovery_deadline = Instant::now() + Duration::from_secs(4);
        let mut recovery_query = 0;
        loop {
            let health = diagnostics(&client, &base).await;
            assert!(
                Instant::now() < recovery_deadline,
                "primary did not recover: {health}"
            );
            if health[0]["servers"][0]["admission"]["retry_after_ms"]
                .as_u64()
                .unwrap_or(0)
                > 0
            {
                tokio::time::sleep(Duration::from_millis(25)).await;
                continue;
            }
            warm(
                config.dns_listen,
                &format!("recovery-{name}-{recovery_query}.test."),
            )
            .await;
            recovery_query += 1;
            let health = diagnostics(&client, &base).await;
            if health[0]["servers"][0]["admission"]["state"]
                .as_str()
                .is_none_or(|s| s == "ready")
            {
                break;
            }
            assert!(
                Instant::now() < recovery_deadline,
                "primary did not recover: {health}"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        warm(config.dns_listen, &format!("cached-{name}.test.")).await;
        endpoints[0].mode(bad);
        endpoints[1].mode(good);
        let mut sampler = if name == "outage" {
            start_sampler(args, process.0.id(), https)
        } else {
            None
        };
        if let Some((sampler, _)) = &mut sampler {
            // Attach before the timed lane starts; early profiler failures fail
            // explicitly instead of leaving an empty artifact described as proof.
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert!(
                sampler.0.try_wait().unwrap().is_none(),
                "perf could not attach; inspect its log"
            );
        }
        let diagnostic_before = diagnostics(&client, &base).await;
        let before = [endpoints[0].queries(), endpoints[1].queries()];
        let lookups_before = metric(&client, &base, "upstream_lookups").await;
        let hits_before = metric(&client, &base, "dns_cache_hits").await;
        let followers_before = metric(&client, &base, "coalesced").await;
        let blocked_before = metric(&client, &base, "blocked").await;
        let mut result = samples(
            config.dns_listen,
            name,
            Duration::from_millis(args.duration_ms),
            args.clients,
            outage,
        )
        .await;
        if let Some((sampler, output)) = sampler {
            stop_sampler(sampler).await;
            result["user_cpu_profile"] = json!(output);
        }
        let delta = [
            endpoints[0].queries() - before[0],
            endpoints[1].queries() - before[1],
        ];
        let lookups = metric(&client, &base, "upstream_lookups").await - lookups_before;
        let hits = metric(&client, &base, "dns_cache_hits").await - hits_before;
        let followers = metric(&client, &base, "coalesced").await - followers_before;
        let blocked = metric(&client, &base, "blocked").await - blocked_before;
        assert_eq!(
            blocked,
            result["blocked"]["replies"].as_u64().unwrap(),
            "{name}: {result}"
        );
        assert_eq!(
            hits + lookups + followers,
            result["cached"]["replies"].as_u64().unwrap()
                + result["fresh"]["replies"].as_u64().unwrap(),
            "blocked queries entered resolver or requests were lost: {name}: {result}"
        );
        if !outage {
            let fresh = result["fresh"]["replies"].as_u64().unwrap() as usize;
            assert!(lookups as usize >= fresh, "{name}: {result}");
            if matches!(name, "baseline" | "recovery") {
                assert_eq!(delta, [lookups as usize, 0], "{name}: {result}");
            } else {
                assert_eq!(
                    delta[1], lookups as usize,
                    "fallback did not complete every lookup: {name}: {result}"
                );
            }
        }
        assert!(hits > 0, "{name}: no DNS cache hits");
        let diagnostic_after = diagnostics(&client, &base).await;
        let diagnostic = diagnostic_delta(&diagnostic_before, &diagnostic_after);
        let servers = diagnostic["servers"].as_array().unwrap();
        assert_eq!(
            servers[0]["attempts"].as_u64().unwrap()
                + servers[0]["backoff_skips"].as_u64().unwrap(),
            lookups
        );
        let reason = match name {
            "stall" | "stall-body" | "outage-stall" => Some("deadline"),
            "invalid-dns" | "outage" => Some("dns_response"),
            "reset" if !https => Some("connection"),
            "reset" | "invalid-http" => Some("http_protocol"),
            _ => None,
        };
        if let Some(reason) = reason {
            assert_eq!(
                servers[0]["failures"][reason], servers[0]["attempts"],
                "{name}: {diagnostic}"
            );
            assert_eq!(servers[0]["successes"], 0);
            assert_eq!(
                servers[1]["attempts"].as_u64().unwrap()
                    + servers[1]["backoff_skips"].as_u64().unwrap(),
                lookups
            );
            if outage {
                assert_eq!(
                    servers[1]["failures"][reason], servers[1]["attempts"],
                    "{name}: {diagnostic}"
                );
                assert_eq!(servers[1]["successes"], 0);
            } else {
                assert_eq!(servers[1]["successes"], lookups);
            }
        } else {
            assert_eq!(servers[0]["successes"], lookups);
            assert_eq!(servers[1]["attempts"], 0);
        }
        result["diagnostics"] = diagnostic;
        result["endpoint_exchanges"] = json!(delta);
        result["upstream_lookups"] = json!(lookups);
        result["dns_cache_hits"] = json!(hits);
        result["coalesced"] = json!(followers);
        phases.insert(name.into(), result);
    }
    // Both endpoints must have completed a validated recovery before intentionally
    // pinning retirement work. Otherwise a half-open fallback probe would exclude
    // concurrent fresh traffic while held by the fixture itself.
    endpoints[0].mode(if https { 9 } else { 2 });
    endpoints[1].mode(if https { 17 } else { 8 });
    let health = diagnostics(&client, &base).await;
    let wait_ms = health[0]["servers"][1]["admission"]["retry_after_ms"]
        .as_u64()
        .unwrap_or(0);
    tokio::time::sleep(Duration::from_millis(wait_ms.saturating_add(1))).await;
    warm(
        config.dns_listen,
        "recover-fallback-before-retirement.test.",
    )
    .await;
    endpoints[0].mode(0);
    warm(config.dns_listen, "recover-primary-before-retirement.test.").await;
    endpoints[0].mode(if https { 9 } else { 2 });
    endpoints[1].mode(if https { 17 } else { 8 });
    let churn = async {
        let until = Instant::now() + Duration::from_millis(args.duration_ms);
        let mut policy = config.policy.clone();
        let mut pair = 0;
        let mut promotions = Vec::new();
        while Instant::now() < until || promotions.len() < 2 {
            let old = pair;
            let next = 1 - pair;
            let marker = format!("retired-{}.test.", promotions.len());
            endpoints[old * 2].mode(if https { 9 } else { 2 });
            endpoints[old * 2 + 1].mode(if https { 17 } else { 8 });
            endpoints[old * 2 + 1].release(false);
            let address = config.dns_listen;
            let domain = marker.clone();
            let pinned = tokio::spawn(async move {
                probe(&socket(address).await, &domain, 543, ResponseCode::NoError).await
            });
            endpoints[old * 2 + 1].pinned(&marker).await;
            let mode = match promotions.len() % 3 {
                0 => {
                    if https {
                        22
                    } else {
                        9
                    }
                }
                1 => {
                    if https {
                        12
                    } else {
                        3
                    }
                }
                _ => {
                    if https {
                        9
                    } else {
                        2
                    }
                }
            };
            endpoints[next * 2].mode(mode);
            endpoints[next * 2 + 1].mode(if https { 17 } else { 8 });
            policy.upstreams[0].addresses = vec![
                endpoints[next * 2].address(),
                endpoints[next * 2 + 1].address(),
            ];
            policy.policies[0].lists[0].rules =
                format!("blocked.test\nrevision-{}.test", promotions.len());
            let began = Instant::now();
            let revision = promote(&client, &base, &policy).await;
            assert!(!pinned.is_finished(), "probe must span publication");
            endpoints[old * 2 + 1].release(true);
            let (_, lost, wrong) = pinned.await.unwrap();
            assert!(!lost && !wrong, "old-generation lookup failed");
            tokio::join!(endpoints[old * 2].closed(), endpoints[old * 2 + 1].closed());
            promotions.push(json!({"generation":revision["generation"],"pair":next,"primary_mode":mode,"promotion_through_retirement_ms":began.elapsed().as_millis(),"pinned_old_request_completed":true}));
            pair = next;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        (promotions, pair, policy)
    };
    let ((promotions, pair, mut policy), traffic) = tokio::join!(
        churn,
        samples(
            config.dns_listen,
            "promotion",
            Duration::from_millis(args.duration_ms),
            args.clients,
            false
        )
    );
    phases.insert("promotion".into(), traffic);
    // Stop churn, publish known-good endpoints, drain the retired pair, then recover.
    let final_pair = 1 - pair;
    endpoints[final_pair * 2].mode(if https { 17 } else { 8 });
    endpoints[final_pair * 2 + 1].mode(if https { 17 } else { 8 });
    policy.upstreams[0].addresses = vec![
        endpoints[final_pair * 2].address(),
        endpoints[final_pair * 2 + 1].address(),
    ];
    let recovery_revision = promote(&client, &base, &policy).await;
    tokio::join!(
        endpoints[pair * 2].closed(),
        endpoints[pair * 2 + 1].closed()
    );
    warm(config.dns_listen, "cached-final-recovery.test.").await;
    phases.insert(
        "post-promotion-recovery".into(),
        samples(
            config.dns_listen,
            "final-recovery",
            Duration::from_millis(args.duration_ms),
            args.clients,
            false,
        )
        .await,
    );
    let status = get(&client, &base, "/api/v1/status").await;
    assert_eq!(status["inflight"], 0);
    let recovered_health = diagnostics(&client, &base).await;
    assert_eq!(recovered_health[0]["generation"], status["generation"]);
    for server in recovered_health[0]["servers"].as_array().unwrap() {
        assert!(
            server["failures"]
                .as_object()
                .unwrap()
                .values()
                .all(|count| count == 0)
        );
    }
    phases.get_mut("post-promotion-recovery").unwrap()["diagnostics"] = recovered_health;
    let retained = get(&client, &base, "/api/v1/config").await;
    assert_eq!(retained, json!(policy));
    running.store(false, Ordering::Relaxed);
    let mut resources = observer.await.unwrap();
    let ports = endpoints.iter().map(|e| e.address().port()).collect();
    let mut quiescent = resources::sample(process.0.id(), &ports);
    quiescent["inflight"] = status["inflight"].clone();
    quiescent["cache_entries"] = status["cache_entries"].clone();
    resources["quiescent"] = quiescent;
    assert_eq!(metric(&client, &base, "inflight_overloads").await, 0);
    let before_exit = endpoints.iter().map(Endpoint::counters).collect::<Vec<_>>();
    assert!(
        Command::new("kill")
            .arg("-TERM")
            .arg(process.0.id().to_string())
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
    for e in &endpoints {
        e.closed().await;
    }
    let db = rusqlite::Connection::open_with_flags(
        &config.database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let (durable_generation, durable_config): (i64, String) = db.query_row("SELECT runtime.value,revisions.config FROM runtime JOIN revisions ON revisions.id=runtime.value WHERE runtime.key='active'", [], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
    assert_eq!(json!(durable_generation), status["generation"]);
    assert_eq!(
        serde_json::from_str::<Value>(&durable_config).unwrap(),
        json!(policy)
    );
    let history: i64 = db
        .query_row("SELECT COUNT(*) FROM queries", [], |r| r.get(0))
        .unwrap();
    let revisions: i64 = db
        .query_row("SELECT COUNT(*) FROM revisions", [], |r| r.get(0))
        .unwrap();
    assert!((0..=i64::try_from(config.history_rows).unwrap()).contains(&history));
    assert!((0..=32).contains(&revisions));
    json!({"transport":if https {"https"}else{"tls"},"coalescing":burst,"phases":phases,"promotions":promotions,"recovery_revision":recovery_revision,"final_status":status,"durable_generation":durable_generation,"history_rows":history,"retained_revisions":revisions,"resources":resources,"endpoints_before_exit":before_exit,"endpoints_after_exit":endpoints.iter().map(Endpoint::counters).collect::<Vec<_>>(),"process_log":std::fs::read_to_string(log_path).unwrap()})
}
#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let args = Args::parse();
    assert!((100..=30000).contains(&args.duration_ms));
    assert!((1..=8).contains(&args.clients));
    assert!(
        std::path::Path::new("/proc/self/fd").is_dir(),
        "Linux /proc is required"
    );
    let tls = run(&args, false).await;
    let https = run(&args, true).await;
    let output = |command: &str, arg: &str| {
        Command::new(command)
            .arg(arg)
            .output()
            .map(|r| String::from_utf8_lossy(&r.stdout).trim().to_owned())
            .unwrap_or_default()
    };
    let hash = Command::new("sha256sum")
        .arg("--")
        .arg(&args.binary)
        .output()
        .map(|r| {
            String::from_utf8_lossy(&r.stdout)
                .split_whitespace()
                .next()
                .unwrap_or("unknown")
                .to_owned()
        })
        .unwrap_or_default();
    let report = json!({"hardware":std::fs::read_to_string("/proc/cpuinfo").unwrap().lines().find(|l|l.starts_with("model name")).unwrap_or("unknown"),"os":output("uname","-srmo"),"rustc":output("rustc","--version"),"binary":args.binary,"binary_sha256":hash,"duration_ms_per_phase":args.duration_ms,"clients_per_lane":args.clients,"upstream_timeout_ms":80,"connections_per_address":2,"histogram":"exact us through 1 ms; 100 us upper-bound buckets thereafter; 1 s cap","tls":tls,"https":https});
    let text = serde_json::to_string_pretty(&report).unwrap() + "\n";
    if let Some(path) = &args.output {
        std::fs::write(path, &text).unwrap();
    }
    print!("{text}");
    for transport in ["tls", "https"] {
        for (name, phase) in report[transport]["phases"].as_object().unwrap() {
            for lane in ["blocked", "cached", "fresh"] {
                assert!(
                    phase[lane]["replies"].as_u64().unwrap() > 0,
                    "{transport}/{name}/{lane}: {phase}"
                );
                assert_eq!(
                    phase[lane]["timeouts"], 0,
                    "{transport}/{name}/{lane}: {phase}"
                );
                assert_eq!(
                    phase[lane]["incorrect"], 0,
                    "{transport}/{name}/{lane}: {phase}"
                );
                assert_eq!(
                    phase[lane]["latencies_clipped"], 0,
                    "{transport}/{name}/{lane}: {phase}"
                );
            }
        }
    }
}
