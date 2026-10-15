#![cfg(unix)]
#![allow(clippy::unwrap_used)]
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    response::IntoResponse,
    routing::get,
};
use rustwalld_dns::{
    config::Config,
    integrations::{Integration, Remote, Source},
    listener::Activity,
    tls::{Certificate, SecureListener},
};
use std::{
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;
const TOKEN: &str = "fixture-master-token-at-least16";
fn address() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}
struct Process(std::process::Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[tokio::test]
async fn real_process_inventory_and_peer_preview_are_bounded_authenticated_and_draft_only() {
    let directory = tempfile::tempdir().unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let certificate = rcgen::CertificateParams::new(vec!["integration.test".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let tls = Certificate {
        cert_file: directory.path().join("cert.pem"),
        key_file: directory.path().join("key.pem"),
        hostnames: vec!["integration.test".into()],
    };
    std::fs::write(&tls.cert_file, certificate.pem()).unwrap();
    std::fs::write(&tls.key_file, key.serialize_pem()).unwrap();
    std::fs::set_permissions(&tls.key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let token = directory.path().join("connector.secret");
    std::fs::write(&token, "fixture_key:fixture_secret").unwrap();
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    let lease = directory.path().join("dnsmasq.leases");
    std::fs::write(
        &lease,
        "0 aa:bb:cc:dd:ee:ff 192.0.2.10 nas *\n1 aa:bb:cc:dd:ee:02 192.0.2.11 old *\n",
    )
    .unwrap();
    let mode = Arc::new(AtomicU8::new(0));
    let observed = mode.clone();
    let mut peer = rustwalld_dns_policy::PolicyConfigSet::default();
    peer.policies[0].lists = vec![rustwalld_dns_filter::ListInput {
        syntax: Default::default(),
        name: "peer-block".into(),
        action: rustwalld_dns_filter::Action::Block,
        rules: "ads.fixture".into(),
    }];
    let router=Router::new().fallback(get(move |request:Request<Body>| {let mode=observed.clone();let peer=peer.clone();async move {
        if mode.load(Ordering::SeqCst)==1 {return StatusCode::FOUND.into_response();}
        if mode.load(Ordering::SeqCst)==2 {return ([("Content-Type","application/json")],"x".repeat(1024*1024+1)).into_response();}
        let path=request.uri().path();
        let value=if path.starts_with("/proxy/network/integration/") {
            assert_eq!(request.headers()["X-API-Key"],"fixture_key:fixture_secret");
            if request.uri().query().unwrap().contains("offset=0&") {serde_json::json!({"totalCount":2,"data":[{"ipAddress":"192.0.2.12","name":"phone","macAddress":"aa:bb:cc:dd:ee:03"}]})}
            else {serde_json::json!({"totalCount":2,"data":[{"ipAddress":"192.0.2.13","name":"laptop"}]})}
        } else if path=="/api/kea/leases4/search" {
            assert_eq!(request.headers()["Authorization"],"Basic Zml4dHVyZV9rZXk6Zml4dHVyZV9zZWNyZXQ=");
            serde_json::json!({"total":2,"rows":[{"address":"192.0.2.14","hostname":"desktop","hwaddr":"aa:bb:cc:dd:ee:04","state":0},{"address":"192.0.2.15","hostname":"expired","state":1}]})
        } else if path=="/api/v1/config" {
            assert_eq!(request.headers()["Authorization"],"Bearer fixture_key:fixture_secret");
            let mut peer=peer;
            if mode.load(Ordering::SeqCst)==3 {peer.policies[0].temporary_exceptions.push(rustwalld_dns_policy::TemporaryException {name:"too-long".into(),domain:"temporary.fixture".into(),expires_at:rustwalld_dns::integrations::now().unwrap()+8*86400,clients:vec![],include_subdomains:false});}
            serde_json::to_value(peer).unwrap()
        }
        else {return StatusCode::NOT_FOUND.into_response();};
        ([("Content-Type","application/json")],serde_json::to_vec(&value).unwrap()).into_response()
    }}));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let remote = listener.local_addr().unwrap();
    let stop = CancellationToken::new();
    let cancel = stop.clone();
    let server = tokio::spawn(async move {
        axum::serve(
            SecureListener::new(listener, tls.load(true).unwrap(), 8),
            router.into_make_service_with_connect_info::<Activity>(),
        )
        .with_graceful_shutdown(cancel.cancelled_owned())
        .await
        .unwrap()
    });
    let endpoint = Remote {
        url: format!("https://integration.test:{}", remote.port()),
        bootstrap_ips: vec![remote.ip()],
        token_file: token,
        ca_pem: Some(certificate.pem()),
    };
    let mut config = Config {
        dns_listen: address(),
        api_listen: address(),
        database: directory.path().join("state.sqlite"),
        integrations: vec![
            Integration {
                name: "leases".into(),
                source: Source::Dnsmasq {
                    lease_file: lease.clone(),
                },
            },
            Integration {
                name: "unifi".into(),
                source: Source::Unifi {
                    endpoint: endpoint.clone(),
                    site: "site-1".into(),
                    controller: false,
                },
            },
            Integration {
                name: "opnsense".into(),
                source: Source::Opnsense {
                    endpoint: endpoint.clone(),
                },
            },
            Integration {
                name: "peer".into(),
                source: Source::Peer {
                    endpoint: endpoint.clone(),
                },
            },
        ],
        ..Default::default()
    };
    config.policy.upstreams[0].addresses = vec![address()];
    let path = directory.path().join("config.toml");
    std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
    let process = Process(
        Command::new(env!("CARGO_BIN_EXE_rustwalld-dns"))
            .arg("--config")
            .arg(path)
            .env("RUSTWALLD_API_TOKEN", TOKEN)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let client = reqwest::Client::new();
    let base = format!("http://{}", config.api_listen);
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if client
                .get(format!("{base}/healthz"))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        client
            .get(format!("{base}/api/v1/integrations"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let setup: serde_json::Value = client
        .get(format!("{base}/api/v1/setup"))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(setup["process"]["https"], false);
    assert_eq!(setup["process"]["dns"], config.dns_listen.to_string());
    for (name, count) in [("leases", 1), ("unifi", 2), ("opnsense", 1)] {
        let response = client
            .post(format!("{base}/api/v1/integrations/{name}/refresh"))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let value: serde_json::Value = response.json().await.unwrap();
        assert_eq!(value["devices"].as_array().unwrap().len(), count);
        assert!(value["error"].is_null());
    }
    mode.store(1, Ordering::SeqCst);
    let value: serde_json::Value = client
        .post(format!("{base}/api/v1/integrations/unifi/refresh"))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(value["error"].as_str().unwrap().contains("302"));
    assert_eq!(value["devices"].as_array().unwrap().len(), 2);
    mode.store(2, Ordering::SeqCst);
    let value: serde_json::Value = client
        .post(format!("{base}/api/v1/integrations/unifi/refresh"))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(value["error"].as_str().unwrap().contains("bounds"));
    mode.store(0, Ordering::SeqCst);
    let before = client
        .get(format!("{base}/api/v1/config"))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap();
    let etag = before.headers()["ETag"].to_str().unwrap().to_owned();
    let original = before.text().await.unwrap();
    let url = format!("{base}/api/v1/integrations/peer/preview");
    assert_eq!(
        client
            .post(&url)
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap()
            .status(),
        428
    );
    let response = client
        .post(&url)
        .bearer_auth(TOKEN)
        .header("If-Match", &etag)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["ETag"], etag);
    let value: serde_json::Value = response.json().await.unwrap();
    assert_eq!(
        value["config"]["policies"][0]["lists"][0]["name"],
        "peer-block"
    );
    assert!(
        !serde_json::to_string(&value)
            .unwrap()
            .contains("fixture_secret")
    );
    assert_eq!(
        client
            .post(&url)
            .bearer_auth(TOKEN)
            .header("If-Match", "\"g0-s0\"")
            .send()
            .await
            .unwrap()
            .status(),
        412
    );
    mode.store(3, Ordering::SeqCst);
    assert_eq!(
        client
            .post(&url)
            .bearer_auth(TOKEN)
            .header("If-Match", &etag)
            .send()
            .await
            .unwrap()
            .status(),
        422
    );
    mode.store(0, Ordering::SeqCst);
    let after = client
        .get(format!("{base}/api/v1/config"))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(after, original);
    std::fs::write(&lease, "bad lease content").unwrap();
    let value: serde_json::Value = client
        .post(format!("{base}/api/v1/integrations/leases/refresh"))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(value["devices"].as_array().unwrap().len(), 1);
    assert!(value["error"].is_string());
    let mut wrong = endpoint;
    wrong.ca_pem = None;
    let adapter = rustwalld_dns::integrations::Adapter::load(Integration {
        name: "wrong".into(),
        source: Source::Peer { endpoint: wrong },
    })
    .unwrap();
    assert!(adapter.peer_config().await.is_err());
    drop(process);
    stop.cancel();
    server.await.unwrap();
}
