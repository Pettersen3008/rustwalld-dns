//! A real-process loopback failure benchmark; no public DNS, no strict latency gate.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "../tests/support/download_fixture.rs"]
mod download_fixture;
#[path = "support/histogram.rs"]
mod histogram;
use clap::Parser;
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{Name, RData, Record, RecordType, rdata::A},
};
use histogram::Histogram;
use rustwalld_dns::config::Config;
use serde_json::{Value, json};
use std::{
    net::{SocketAddr, TcpListener},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpStream, UdpSocket},
    time::timeout,
};
const TOKEN: &str = "resilience-local-test-token-only";
#[derive(Parser)]
struct Args {
    #[arg(long)]
    binary: PathBuf,
    #[arg(long, default_value_t = 1000)]
    duration_ms: u64,
    #[arg(long, default_value_t = 200000)]
    rules: usize,
    #[arg(long, default_value_t = 4)]
    clients: usize,
    #[arg(long)]
    output: Option<PathBuf>,
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
fn port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
fn packet(domain: &str) -> Vec<u8> {
    let mut message = Message::query();
    message.metadata.id = 123;
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(
        Name::from_ascii(domain).unwrap(),
        RecordType::A,
    ));
    message.to_vec().unwrap()
}
async fn samples(addr: SocketAddr, duration: Duration, clients: usize) -> Value {
    let start = Instant::now();
    let until = start + duration;
    let mut tasks = Vec::new();
    for _ in 0..clients {
        tasks.push(tokio::spawn(async move {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            socket.connect(addr).await.unwrap();
            let blocked = packet("blocked.test.");
            let cached = packet("cached.test.");
            let mut buffer = [0; 1232];
            let mut histogram = Histogram::new();
            let mut count = 0usize;
            while Instant::now() < until {
                let is_blocked = count.is_multiple_of(2);
                count += 1;
                let query = if is_blocked { &blocked } else { &cached };
                let began = Instant::now();
                socket.send(query).await.unwrap();
                match timeout(Duration::from_millis(250), socket.recv(&mut buffer)).await {
                    Ok(Ok(len)) => {
                        let response = Message::from_vec(&buffer[..len]).unwrap();
                        let code = if is_blocked {
                            ResponseCode::NXDomain
                        } else {
                            ResponseCode::NoError
                        };
                        let expected = if is_blocked {
                            "blocked.test."
                        } else {
                            "cached.test."
                        };
                        let wrong = response.metadata.id != 123
                            || response.metadata.response_code != code
                            || response.queries.len() != 1
                            || response.queries[0].name().to_ascii() != expected
                            || (!is_blocked
                                && (response.answers.len() != 1
                                    || response.answers[0].data
                                        != RData::A(A("192.0.2.1".parse().unwrap()))));
                        histogram.record((began.elapsed().as_micros() as u64, false, wrong));
                    }
                    _ => histogram.record((began.elapsed().as_micros() as u64, true, false)),
                }
            }
            histogram
        }));
    }
    let mut histogram = Histogram::new();
    for task in tasks {
        histogram.merge(task.await.unwrap());
    }
    let mut report = histogram.report();
    let responses = report.as_object_mut().unwrap().remove("replies").unwrap();
    assert!(responses.as_u64().unwrap() > 0);
    report["responses"] = responses;
    report["elapsed_ms"] = json!(start.elapsed().as_millis());
    report["requests_per_second"] =
        json!(report["responses"].as_u64().unwrap() as f64 / start.elapsed().as_secs_f64());
    report
}
async fn metrics(client: &reqwest::Client, base: &str) -> Value {
    let text = client
        .get(format!("{base}/metrics"))
        .send()
        .await
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
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let args = Args::parse();
    assert!((100..=60000).contains(&args.duration_ms));
    assert!((1..=32).contains(&args.clients));
    assert!((1..=500000).contains(&args.rules));
    let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let exchanges = Arc::new(AtomicU64::new(0));
    let count = exchanges.clone();
    let mock = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        loop {
            let (len, peer) = upstream.recv_from(&mut bytes).await.unwrap();
            let request = Message::from_vec(&bytes[..len]).unwrap();
            count.fetch_add(1, Ordering::Relaxed);
            let mut response = rustwalld_dns_core::reply(&request, ResponseCode::NoError);
            response.add_answer(Record::from_rdata(
                request.queries[0].name().clone(),
                3600,
                RData::A(A("192.0.2.1".parse().unwrap())),
            ));
            upstream
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let mut config = Config {
        dns_listen: SocketAddr::from(([127, 0, 0, 1], port())),
        api_listen: SocketAddr::from(([127, 0, 0, 1], port())),
        database: dir.path().join("dns.sqlite"),
        event_queue: 16,
        ..Default::default()
    };
    while config.api_listen.port() == config.dns_listen.port()
        || config.api_listen == upstream_addr
        || config.dns_listen == upstream_addr
    {
        config.api_listen.set_port(port());
        config.dns_listen.set_port(port());
    }
    config.policy.upstreams[0].addresses = vec![upstream_addr];
    config.policy.policies[0].lists = vec![rustwalld_dns_filter::ListInput {
        name: "base".into(),
        action: rustwalld_dns_filter::Action::Block,
        rules: "blocked.test".into(),
    }];
    let config_path = dir.path().join("config.toml");
    std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
    let log = std::fs::File::create(dir.path().join("process.log")).unwrap();
    let mut process = Process(
        Command::new(&args.binary)
            .arg("--config")
            .arg(&config_path)
            .env("RUSTWALLD_API_TOKEN", TOKEN)
            .env("RUST_LOG", "error")
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap(),
    );
    let base = format!("http://{}", config.api_listen);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();
    timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(response) = client.get(format!("{base}/healthz")).send().await
                && response.status().is_success()
            {
                break;
            }
            assert!(process.0.try_wait().unwrap().is_none());
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    // Warm the cache before measuring the local paths.
    samples(config.dns_listen, Duration::from_millis(100), 1).await;
    let duration = Duration::from_millis(args.duration_ms);
    let baseline = samples(config.dns_listen, duration, args.clients).await;
    // Partial authenticated bodies occupy request admission without invoking compilation.
    let mut stalled = Vec::new();
    for _ in 0..48 {
        let mut stream = TcpStream::connect(config.api_listen).await.unwrap();
        stream.write_all(format!("POST /api/v1/shadow HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\nContent-Length: 1048576\r\n\r\n{{").as_bytes()).await.unwrap();
        stalled.push(stream);
    }
    tokio::time::sleep(Duration::from_millis(30)).await;
    let admission = client
        .get(format!("{base}/healthz"))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    assert_eq!(admission, 429);
    let stalled_http = samples(config.dns_listen, duration, args.clients).await;
    drop(stalled);
    timeout(Duration::from_secs(5), async {
        loop {
            if client
                .get(format!("{base}/healthz"))
                .send()
                .await
                .unwrap()
                .status()
                .is_success()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let mut candidate = config.policy.clone();
    for i in 0..args.rules {
        candidate.policies[0].lists[0]
            .rules
            .push_str(&format!("\nr{i}.compile.test"));
    }
    let compile = async {
        let began = Instant::now();
        let response = client
            .post(format!("{base}/api/v1/shadow"))
            .bearer_auth(TOKEN)
            .json(&candidate)
            .send()
            .await;
        (response, began.elapsed().as_millis())
    };
    let ((compile_result, compile_wall), compilation) =
        tokio::join!(compile, samples(config.dns_listen, duration, args.clients));
    assert!(compile_result.unwrap().status().is_success());
    // An external write lock forces telemetry loss and rejects publication.
    let locked = rusqlite::Connection::open(&config.database).unwrap();
    locked.execute_batch("BEGIN IMMEDIATE").unwrap();
    let before = metrics(&client, &base).await;
    let rejected = client
        .put(format!("{base}/api/v1/config"))
        .bearer_auth(TOKEN)
        .json(&config.policy)
        .send();
    let (rejected, persistence_failure) =
        tokio::join!(rejected, samples(config.dns_listen, duration, args.clients));
    let rejection = rejected.unwrap().status().as_u16();
    assert_eq!(rejection, 503);
    locked.execute_batch("ROLLBACK").unwrap();
    drop(locked);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let after = metrics(&client, &base).await;
    let status = client
        .get(format!("{base}/api/v1/status"))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(status["generation"], 1);
    for data in [&baseline, &stalled_http, &compilation, &persistence_failure] {
        assert_eq!(data["timeouts"], 0);
        assert_eq!(data["incorrect"], 0);
    }
    assert_eq!(exchanges.load(Ordering::Relaxed), 1);
    assert!(after["rustwalld_events_dropped_total"].as_u64().unwrap() > 0);
    assert!(
        after["rustwalld_history_write_failures_total"]
            .as_u64()
            .unwrap()
            > before["rustwalld_history_write_failures_total"]
                .as_u64()
                .unwrap()
    );
    // Measure a real scheduled HTTPS body stalled after successful authentication.
    // Activate a new generation, warm its cache, then keep the download pending.
    let publisher = download_fixture::Fixture::start().await;
    let mut source = publisher.source("/stall");
    source.list = "base".into();
    source.refresh_interval_secs = Some(300);
    config.policy.filter_sources = vec![source];
    assert!(
        client
            .put(format!("{base}/api/v1/config"))
            .bearer_auth(TOKEN)
            .json(&config.policy)
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
    publisher.wait_requests(1).await;
    samples(config.dns_listen, Duration::from_millis(100), 1).await;
    let stalled_refresh = samples(
        config.dns_listen,
        duration.min(Duration::from_secs(5)),
        args.clients,
    )
    .await;
    assert_eq!(stalled_refresh["timeouts"], 0);
    assert_eq!(stalled_refresh["incorrect"], 0);
    let refresh_status = client
        .get(format!("{base}/api/v1/filter-refreshes"))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert!(!refresh_status["running"].is_null());
    assert_eq!(publisher.requests.load(Ordering::SeqCst), 1);
    assert_eq!(exchanges.load(Ordering::Relaxed), 2);
    let report = json!({"hardware":std::fs::read_to_string("/proc/cpuinfo").unwrap().lines().find(|line|line.starts_with("model name")).unwrap_or("unknown"),"os":Command::new("uname").arg("-srmo").output().map(|result|String::from_utf8_lossy(&result.stdout).trim().to_owned()).unwrap_or_default(),"rustc":Command::new("rustc").arg("--version").output().map(|result|String::from_utf8_lossy(&result.stdout).trim().to_owned()).unwrap_or_default(),"binary":args.binary,"binary_sha256":Command::new("sha256sum").arg("--").arg(&args.binary).output().map(|result|String::from_utf8_lossy(&result.stdout).split_whitespace().next().unwrap_or("unknown").to_owned()).unwrap_or_default(),"clients":args.clients,"duration_ms":args.duration_ms,"candidate_rules":args.rules+1,"compiler_request_ms":compile_wall,"http_admission_status":admission,"publication_failure_status":rejection,"upstream_exchanges":exchanges.load(Ordering::Relaxed),"baseline":baseline,"stalled_http":stalled_http,"compilation":compilation,"persistence_failure":persistence_failure,"stalled_refresh":stalled_refresh,"refresh_status":refresh_status,"metrics_before_lock":before,"metrics_after_lock":after,"status_before_refresh":status});
    if let Some(output) = args.output {
        std::fs::write(
            output,
            serde_json::to_string_pretty(&report).unwrap() + "\n",
        )
        .unwrap();
    }
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
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
    publisher.wait_closed().await;
    mock.abort();
}
