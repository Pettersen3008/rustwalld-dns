//! Actual-process DNS latency and memory during bounded password verification.
#![allow(clippy::unwrap_used)]
#[path = "support/histogram.rs"]
mod histogram;
#[path = "support/resources.rs"]
mod resources;
use clap::Parser;
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{Name, RecordType},
};
use rustwalld_dns::{config::Config, tls::Certificate};
use rustwalld_dns_filter::{Action, ListInput};
use rustwalld_dns_policy::Rewrite;
use std::{
    collections::HashSet,
    net::{SocketAddr, TcpListener},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, time::timeout};
use tokio_util::sync::CancellationToken;
const TOKEN: &str = "auth-resilience-public-local-fixture";
#[derive(Parser)]
struct Args {
    #[arg(long)]
    binary: PathBuf,
    #[arg(long, default_value_t = 100000)]
    rules: usize,
    #[arg(long)]
    output: PathBuf,
}
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}
fn packet(domain: &str) -> Vec<u8> {
    let mut query = Message::query();
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(
        Name::from_ascii(domain).unwrap(),
        RecordType::A,
    ));
    query.to_vec().unwrap()
}
async fn lane(
    address: SocketAddr,
    domain: &str,
    rcode: ResponseCode,
    cancel: CancellationToken,
) -> histogram::Histogram {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(address).await.unwrap();
    let request = packet(domain);
    let expected = Name::from_ascii(format!("{domain}.")).unwrap();
    let mut histogram = histogram::Histogram::new();
    let mut buffer = [0u8; 1232];
    while !cancel.is_cancelled() {
        let now = Instant::now();
        socket.send(&request).await.unwrap();
        let reply = timeout(Duration::from_millis(500), socket.recv(&mut buffer)).await;
        let (lost, wrong) = match reply {
            Ok(Ok(len)) => (
                false,
                Message::from_vec(&buffer[..len]).map_or(true, |message| {
                    message.response_code != rcode || message.queries[0].name() != &expected
                }),
            ),
            _ => (true, false),
        };
        histogram.record((now.elapsed().as_micros() as u64, lost, wrong));
    }
    histogram
}
async fn traffic(address: SocketAddr, cancel: CancellationToken) -> histogram::Histogram {
    let (mut block, local) = tokio::join!(
        lane(
            address,
            "blocked.test",
            ResponseCode::NXDomain,
            cancel.clone()
        ),
        lane(address, "nas.home.arpa", ResponseCode::NoError, cancel)
    );
    block.merge(local);
    block
}
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let args = Args::parse();
    assert!(args.rules <= 1000000);
    let directory = tempfile::tempdir().unwrap();
    let auth = directory.path().join("auth.json");
    rustwalld_dns::auth::initialize(auth.clone(), "admin".into(), b"fixture-password-16", false)
        .unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["auth.test".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let certificate = Certificate {
        cert_file: directory.path().join("cert.pem"),
        key_file: directory.path().join("key.pem"),
        hostnames: vec!["auth.test".into()],
    };
    std::fs::write(&certificate.cert_file, cert.pem()).unwrap();
    std::fs::write(&certificate.key_file, key.serialize_pem()).unwrap();
    std::fs::set_permissions(
        &certificate.key_file,
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let mut config = Config {
        dns_listen: address(),
        api_listen: address(),
        database: directory.path().join("state.sqlite"),
        api_tls: Some(certificate),
        auth_file: Some(auth),
        history_rows: 1000,
        ..Default::default()
    };
    config.policy.upstreams[0].addresses = vec!["127.0.0.1:9".parse().unwrap()];
    let mut rules = String::from("blocked.test\n");
    for i in 0..args.rules {
        use std::fmt::Write;
        writeln!(rules, "ad{i}.fixture.test").unwrap();
    }
    config.policy.policies[0].lists = vec![ListInput {
        syntax: Default::default(),
        name: "fixture".into(),
        action: Action::Block,
        rules,
    }];
    config.policy.policies[0].rewrites = vec![Rewrite {
        domain: "nas.home.arpa".into(),
        addresses: vec!["192.0.2.10".parse().unwrap()],
        ttl: 60,
    }];
    let file = directory.path().join("config.toml");
    std::fs::write(&file, toml::to_string(&config).unwrap()).unwrap();
    let child = Process(
        Command::new(&args.binary)
            .arg("--config")
            .arg(&file)
            .env("RUSTWALLD_API_TOKEN", TOKEN)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let pid = child.0.id();
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let client = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_pem(cert.pem().as_bytes()).unwrap())
        .resolve("auth.test", config.api_listen)
        .build()
        .unwrap();
    let base = format!("https://auth.test:{}", config.api_listen.port());
    timeout(Duration::from_secs(10), async {
        loop {
            if client
                .get(format!("{base}/healthz"))
                .send()
                .await
                .is_ok_and(|response| response.status() == 200)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let ports = HashSet::new();
    let steady = resources::sample(pid, &ports);
    let cancel = CancellationToken::new();
    let phase = tokio::spawn(traffic(config.dns_listen, cancel.clone()));
    tokio::time::sleep(Duration::from_secs(1)).await;
    cancel.cancel();
    let baseline = phase.await.unwrap().report();
    let cancel = CancellationToken::new();
    let phase = tokio::spawn(traffic(config.dns_listen, cancel.clone()));
    let mut peak_rss = steady["rss_kib"].as_u64().unwrap();
    let done = CancellationToken::new();
    let login_done = done.clone();
    let login_client = client.clone();
    let login_base = base.clone();
    let logins = tokio::spawn(async move {
        let run = |client: reqwest::Client, base: String| async move {
            for _ in 0..4 {
                let response = client
                    .post(format!("{base}/api/v1/auth/login"))
                    .json(&serde_json::json!({"username":"admin","password":"fixture-password-16"}))
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status(), 200);
                let _: serde_json::Value = response.json().await.unwrap();
            }
        };
        tokio::join!(
            run(login_client.clone(), login_base.clone()),
            run(login_client, login_base)
        );
        login_done.cancel();
    });
    timeout(Duration::from_secs(20), async {
        while !done.is_cancelled() {
            peak_rss = peak_rss.max(resources::sample(pid, &ports)["rss_kib"].as_u64().unwrap());
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    logins.await.unwrap();
    cancel.cancel();
    let contended = phase.await.unwrap().report();
    assert_eq!(baseline["timeouts"], 0);
    assert_eq!(baseline["incorrect"], 0);
    assert_eq!(contended["timeouts"], 0);
    assert_eq!(contended["incorrect"], 0);
    let report = serde_json::json!({"binary":args.binary,"binary_sha256":rustwalld_dns::downloads::sha256(&std::fs::read(&args.binary).unwrap()),"rules":args.rules,"password_jobs":8,"parallel_jobs":2,"argon2_memory_kib_per_job":32768,"baseline":baseline,"concurrent_logins":contended,"steady":steady,"peak_child_rss_kib":peak_rss,"after":resources::sample(pid,&ports),"cpu":std::fs::read_to_string("/proc/cpuinfo").unwrap().lines().find(|line|line.starts_with("model name")).unwrap_or("unknown")});
    std::fs::write(&args.output, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    println!("{}", report);
}
