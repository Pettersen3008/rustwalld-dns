#![cfg(unix)]
#![allow(clippy::unwrap_used)]
use serde_json::Value;
use std::{
    net::{SocketAddr, TcpListener},
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::time::timeout;

#[tokio::test]
async fn binary_restart_keeps_absolute_exception_expiry_and_permanent_assertions() {
    use hickory_proto::{
        op::{Message, Query, ResponseCode},
        rr::{Name, RData, Record, RecordType, rdata::A},
    };
    let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let mock = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        loop {
            let (len, peer) = upstream.recv_from(&mut buffer).await.unwrap();
            let request = Message::from_vec(&buffer[..len]).unwrap();
            let mut response = rustwalld_dns_core::reply(&request, ResponseCode::NoError);
            response.add_answer(Record::from_rdata(
                request.queries[0].name().clone(),
                60,
                RData::A(A("192.0.2.1".parse().unwrap())),
            ));
            upstream
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let mut config = rustwalld_dns::config::Config {
        dns_listen: SocketAddr::from(([127, 0, 0, 1], port())),
        api_listen: SocketAddr::from(([127, 0, 0, 1], port())),
        database: dir.path().join("state.sqlite"),
        ..Default::default()
    };
    while config.api_listen == config.dns_listen {
        config.api_listen.set_port(port());
    }
    config.policy.upstreams[0].addresses = vec![upstream_addr];
    config.policy.policies[0].lists = vec![rustwalld_dns_filter::ListInput {
        name: "deny".into(),
        action: rustwalld_dns_filter::Action::Block,
        rules: "repair.test".into(),
    }];
    config.policy.assertions = vec![rustwalld_dns_policy::Assertion {
        client: "127.0.0.1".parse().unwrap(),
        domain: "repair.test".into(),
        expected: rustwalld_dns_filter::Action::Block,
    }];
    let path = dir.path().join("config.toml");
    std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
    let base = format!("http://{}", config.api_listen);
    let token = "temporary-process-token-at-least-16";
    let client = reqwest::Client::new();
    let mut expires_at = 0;
    for round in 0..2 {
        let mut process = Process(
            Command::new(env!("CARGO_BIN_EXE_rustwalld-dns"))
                .arg("--config")
                .arg(&path)
                .env("RUSTWALLD_API_TOKEN", token)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let status = timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(response) = client.get(format!("{base}/api/v1/status")).send().await
                    && response.status().is_success()
                {
                    break response.json::<Value>().await.unwrap();
                }
                assert!(process.0.try_wait().unwrap().is_none());
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        if round == 0 {
            expires_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3;
            let mut candidate = config.policy.clone();
            candidate.policies[0].temporary_exceptions.push(
                rustwalld_dns_policy::TemporaryException {
                    name: "repair".into(),
                    domain: "repair.test".into(),
                    expires_at,
                },
            );
            assert!(
                client
                    .put(format!("{base}/api/v1/config"))
                    .bearer_auth(token)
                    .json(&candidate)
                    .send()
                    .await
                    .unwrap()
                    .status()
                    .is_success()
            );
        } else {
            assert_eq!(status["generation"], 2);
            let live: Value = client
                .get(format!("{base}/api/v1/temporary-exceptions"))
                .bearer_auth(token)
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(live["exceptions"][0]["expires_at"], expires_at);
            assert_eq!(live["exceptions"][0]["active"], false);
        }
        let mut query = Message::query();
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(
            Name::from_ascii("repair.test.").unwrap(),
            RecordType::A,
        ));
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket
            .send_to(&query.to_vec().unwrap(), config.dns_listen)
            .await
            .unwrap();
        let mut buffer = [0; 1232];
        let len = timeout(Duration::from_secs(1), socket.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        let response = Message::from_vec(&buffer[..len]).unwrap();
        assert_eq!(
            response.metadata.response_code,
            if round == 0 {
                ResponseCode::NoError
            } else {
                ResponseCode::NXDomain
            }
        );
        if round == 0 {
            assert!(response.answers[0].ttl <= 3);
        }
        Command::new("kill")
            .args(["-TERM", &process.0.id().to_string()])
            .status()
            .unwrap();
        timeout(Duration::from_secs(3), async {
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
        if round == 0 {
            let remaining = (std::time::UNIX_EPOCH + Duration::from_secs(expires_at))
                .duration_since(std::time::SystemTime::now())
                .unwrap_or_default();
            tokio::time::sleep(remaining + Duration::from_millis(20)).await;
        }
    }
    mock.abort();
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
#[tokio::test]
async fn binary_restores_revision_and_handles_sigterm() {
    let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let mut config = rustwalld_dns::config::Config {
        dns_listen: SocketAddr::from(([127, 0, 0, 1], port())),
        api_listen: SocketAddr::from(([127, 0, 0, 1], port())),
        database: dir.path().join("dns.sqlite"),
        ..Default::default()
    };
    while config.dns_listen.port() == config.api_listen.port() {
        config.api_listen.set_port(port());
    }
    let path = dir.path().join("config.toml");
    std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
    let base = format!("http://{}", config.api_listen);
    let client = reqwest::Client::new();
    let token = "process-test-token-with-16-bytes";
    for round in 0..2 {
        let mut process = Process(
            Command::new(env!("CARGO_BIN_EXE_rustwalld-dns"))
                .arg("--config")
                .arg(&path)
                .env("RUSTWALLD_API_TOKEN", token)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let status = timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(response) = client.get(format!("{base}/api/v1/status")).send().await
                    && response.status().is_success()
                {
                    break response.json::<Value>().await.unwrap();
                }
                assert!(
                    process.0.try_wait().unwrap().is_none(),
                    "process exited before ready"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        if round == 0 {
            let mut policy = config.policy.clone();
            policy.policies[0]
                .lists
                .push(rustwalld_dns_filter::ListInput {
                    name: "lifecycle".into(),
                    action: rustwalld_dns_filter::Action::Block,
                    rules: "lifecycle.test".into(),
                });
            let response = client
                .put(format!("{base}/api/v1/config"))
                .bearer_auth(token)
                .json(&policy)
                .send()
                .await
                .unwrap();
            assert!(response.status().is_success());
        } else {
            assert_eq!(status["generation"], 2);
        }
        // A real packet must hit the restored/updated filter, without upstream I/O.
        let mut request = hickory_proto::op::Message::query();
        request.metadata.recursion_desired = true;
        request.add_query(hickory_proto::op::Query::query(
            hickory_proto::rr::Name::from_ascii("lifecycle.test.").unwrap(),
            hickory_proto::rr::RecordType::A,
        ));
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket
            .send_to(&request.to_vec().unwrap(), config.dns_listen)
            .await
            .unwrap();
        let mut buffer = [0; 1232];
        let len = timeout(Duration::from_secs(1), socket.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            hickory_proto::op::Message::from_vec(&buffer[..len])
                .unwrap()
                .metadata
                .response_code,
            hickory_proto::op::ResponseCode::NXDomain
        );
        assert!(
            Command::new("kill")
                .arg("-TERM")
                .arg(process.0.id().to_string())
                .status()
                .unwrap()
                .success()
        );
        let status = timeout(Duration::from_secs(3), async {
            loop {
                if let Some(status) = process.0.try_wait().unwrap() {
                    break status;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(status.success());
    }
}
