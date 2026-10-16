#![cfg(unix)]
#![allow(clippy::unwrap_used)]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{Name, RecordType},
};
use rustwalld_dns::{
    config::Config,
    tls::{Certificate, DnsListener},
};
use std::{
    net::{SocketAddr, TcpListener},
    os::unix::fs::PermissionsExt,
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};
use tokio_rustls::{
    TlsConnector,
    rustls::{self, pki_types::ServerName},
};
fn address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn query(domain: &str) -> Vec<u8> {
    let mut query = Message::query();
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(
        Name::from_ascii(domain).unwrap(),
        RecordType::A,
    ));
    query.to_vec().unwrap()
}
#[tokio::test]
async fn real_process_https_management_and_dot_doh_enforce_identity_policy_and_protocol() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let directory = tempfile::tempdir().unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["dns.test".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let certificate = Certificate {
        cert_file: directory.path().join("cert.pem"),
        key_file: directory.path().join("key.pem"),
        hostnames: vec!["dns.test".into()],
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
        api_tls: Some(certificate.clone()),
        dot: Some(DnsListener {
            listen: address(),
            certificate: certificate.clone(),
            max_connections: 4,
        }),
        doh: Some(DnsListener {
            listen: address(),
            certificate: certificate.clone(),
            max_connections: 4,
        }),
        ..Default::default()
    };
    let auth_path = directory.path().join("auth.json");
    rustwalld_dns::auth::initialize(
        auth_path.clone(),
        "admin".into(),
        b"fixture-password-16",
        false,
    )
    .unwrap();
    config.auth_file = Some(auth_path);
    // Purely local answers: this test never needs any upstream DNS.
    config.policy.upstreams[0].addresses = vec!["127.0.0.1:9".parse().unwrap()];
    config.policy.policies[0].lists = vec![rustwalld_dns_filter::ListInput {
        syntax: Default::default(),
        name: "deny".into(),
        action: rustwalld_dns_filter::Action::Block,
        rules: "ads.test".into(),
    }];
    config.policy.policies[0].rewrites = vec![rustwalld_dns_policy::Rewrite {
        domain: "nas.home.arpa".into(),
        addresses: vec!["192.0.2.10".parse().unwrap()],
        ttl: 60,
    }];
    let path = directory.path().join("config.toml");
    std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
    let mut child = Process(
        Command::new(env!("CARGO_BIN_EXE_rustwalld-dns"))
            .arg("--config")
            .arg(&path)
            .env("RUSTWALLD_API_TOKEN", "encrypted-ingress-test-token-16")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let dot = config.dot.as_ref().unwrap().listen;
    let doh = config.doh.as_ref().unwrap().listen;
    let client = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_pem(cert.pem().as_bytes()).unwrap())
        .resolve("dns.test", config.api_listen)
        .build()
        .unwrap();
    let base = format!("https://dns.test:{}", config.api_listen.port());
    timeout(Duration::from_secs(10), async {
        loop {
            if client
                .get(format!("{base}/healthz"))
                .send()
                .await
                .is_ok_and(|r| r.status() == 200)
            {
                break;
            }
            assert!(child.0.try_wait().unwrap().is_none());
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        client
            .get(format!("{base}/api/v1/config"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        client
            .get(format!("{base}/api/v1/config"))
            .bearer_auth("encrypted-ingress-test-token-16")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        client
            .get(format!("{base}/healthz"))
            .header("Host", "attacker.test")
            .send()
            .await
            .unwrap()
            .status(),
        421
    );
    // Neither an untrusted certificate nor a plaintext downgrade is accepted.
    assert!(
        reqwest::Client::builder()
            .no_proxy()
            .resolve("dns.test", config.api_listen)
            .build()
            .unwrap()
            .get(format!("{base}/healthz"))
            .send()
            .await
            .is_err()
    );
    assert!(
        reqwest::get(format!("http://{}/healthz", config.api_listen))
            .await
            .is_err()
    );
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls));
    // A stalled handshake occupies one bounded slot, while another peer works.
    let _stalled = tokio::net::TcpStream::connect(dot).await.unwrap();
    let mut stream = timeout(
        Duration::from_secs(1),
        connector.connect(
            ServerName::try_from("dns.test").unwrap(),
            tokio::net::TcpStream::connect(dot).await.unwrap(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    for (domain, rcode) in [
        ("ads.test", ResponseCode::NXDomain),
        ("nas.home.arpa", ResponseCode::NoError),
    ] {
        let query = query(domain);
        stream.write_u16(query.len() as u16).await.unwrap();
        stream.write_all(&query).await.unwrap();
        let length = stream.read_u16().await.unwrap();
        let mut bytes = vec![0; usize::from(length)];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(Message::from_vec(&bytes).unwrap().response_code, rcode);
    }
    drop(stream);
    let client = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_pem(cert.pem().as_bytes()).unwrap())
        .resolve("dns.test", doh)
        .build()
        .unwrap();
    let endpoint = format!("https://dns.test:{}/dns-query", doh.port());
    let response = client
        .post(&endpoint)
        .header("Content-Type", "application/dns-message")
        .body(query("ads.test"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["content-type"],
        "application/dns-message"
    );
    assert_eq!(response.version(), http::Version::HTTP_2);
    assert_eq!(
        Message::from_vec(&response.bytes().await.unwrap())
            .unwrap()
            .response_code,
        ResponseCode::NXDomain
    );
    let response = client
        .get(format!(
            "{endpoint}?dns={}",
            URL_SAFE_NO_PAD.encode(query("nas.home.arpa"))
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let answer = Message::from_vec(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(answer.answers.len(), 1);
    assert_eq!(answer.answers[0].ttl, 60);
    assert_eq!(
        client
            .post(&endpoint)
            .body(query("ads.test"))
            .send()
            .await
            .unwrap()
            .status(),
        415
    );
    assert_eq!(
        client
            .post(&endpoint)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/json")
            .body(query("ads.test"))
            .send()
            .await
            .unwrap()
            .status(),
        406
    );
    assert_eq!(
        client
            .post(&endpoint)
            .header("Content-Type", "application/dns-message")
            .body(vec![0u8; 65536])
            .send()
            .await
            .unwrap()
            .status(),
        413
    );
    assert_eq!(
        client
            .get(format!("{endpoint}?dns=not_base64!&extra=x"))
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(
        client
            .post(&endpoint)
            .header("Content-Type", "application/dns-message")
            .body(vec![0u8; 2])
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(
        client
            .post(&endpoint)
            .header("Host", "attacker.test")
            .header("Content-Type", "application/dns-message")
            .body(query("ads.test"))
            .send()
            .await
            .unwrap()
            .status(),
        421
    );
    // Forged proxy identity never changes source admission.
    assert_eq!(
        client
            .post(&endpoint)
            .header("X-Real-IP", "192.0.2.1")
            .header("Content-Type", "application/dns-message")
            .body(query("ads.test"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let admin = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_pem(cert.pem().as_bytes()).unwrap())
        .resolve("dns.test", config.api_listen)
        .build()
        .unwrap();
    let info: serde_json::Value = admin
        .get(format!("{base}/api/v1/auth/info"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info["password_enabled"], true);
    assert_eq!(info["totp_enabled"], false);
    let login = admin
        .post(format!("{base}/api/v1/auth/login"))
        .json(&serde_json::json!({"username":"admin","password":"fixture-password-16"}))
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), 200);
    let cookie = login.headers()["set-cookie"].to_str().unwrap().to_owned();
    assert!(cookie.contains("Secure; HttpOnly; SameSite=Strict"));
    assert!(!cookie.contains("Domain="));
    let cookie = cookie.split(';').next().unwrap();
    let accepted: serde_json::Value = login.json().await.unwrap();
    let csrf = accepted["csrf_token"].as_str().unwrap();
    assert_eq!(
        admin
            .get(format!("{base}/api/v1/config"))
            .header("Cookie", cookie)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        admin
            .get(format!("{base}/api/v1/config"))
            .header("Cookie", cookie)
            .bearer_auth("wrong")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        admin
            .post(format!("{base}/api/v1/auth/logout"))
            .header("Cookie", cookie)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        admin
            .post(format!("{base}/api/v1/auth/logout"))
            .header("Cookie", cookie)
            .header("X-CSRF-Token", csrf)
            .header("Origin", "https://attacker.test")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let created = admin
        .post(format!("{base}/api/v1/auth/tokens"))
        .header("Cookie", cookie)
        .header("X-CSRF-Token", csrf)
        .json(&serde_json::json!({"name":"read","role":"read_only","duration_secs":60}))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let created: serde_json::Value = created.json().await.unwrap();
    let token = created["token"].as_str().unwrap();
    assert_eq!(
        admin
            .get(format!("{base}/api/v1/config"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        admin
            .post(format!("{base}/api/v1/policy/test"))
            .bearer_auth(token)
            .json(&config.policy)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        admin
            .get(format!("{base}/api/v1/auth/tokens"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let tokens: Vec<serde_json::Value> = admin
        .get(format!("{base}/api/v1/auth/tokens"))
        .header("Cookie", cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(tokens[0].get("digest").is_none());
    assert!(tokens[0].get("token").is_none());
    assert_eq!(
        admin
            .delete(format!(
                "{base}/api/v1/auth/tokens/{}",
                tokens[0]["id"].as_str().unwrap()
            ))
            .header("Cookie", cookie)
            .header("X-CSRF-Token", csrf)
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    assert_eq!(
        admin
            .get(format!("{base}/api/v1/config"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        admin
            .post(format!("{base}/api/v1/auth/logout"))
            .header("Cookie", cookie)
            .header("X-CSRF-Token", csrf)
            .send()
            .await
            .unwrap()
            .status(),
        204
    );
    assert_eq!(
        admin
            .get(format!("{base}/api/v1/config"))
            .header("Cookie", cookie)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let response = admin
        .get(format!("{base}/api/v1/config"))
        .bearer_auth("encrypted-ingress-test-token-16")
        .send()
        .await
        .unwrap();
    let tag = response.headers()["etag"].to_str().unwrap().to_owned();
    let mut policy: rustwalld_dns_policy::PolicyConfigSet = response.json().await.unwrap();
    let mut looping = policy.clone();
    looping.upstreams[0].addresses = vec![dot];
    looping.upstreams[0].transport = rustwalld_dns_policy::UpstreamTransport::Tls {
        server_name: "dns.test".into(),
        ca_pem: None,
        max_connections: 2,
    };
    assert_eq!(
        admin
            .post(format!("{base}/api/v1/policy/test"))
            .bearer_auth("encrypted-ingress-test-token-16")
            .json(&looping)
            .send()
            .await
            .unwrap()
            .status(),
        422
    );
    assert_eq!(
        admin
            .put(format!("{base}/api/v1/config"))
            .bearer_auth("encrypted-ingress-test-token-16")
            .header("If-Match", &tag)
            .json(&looping)
            .send()
            .await
            .unwrap()
            .status(),
        422
    );
    policy.allowed_clients = vec!["::1/128".parse().unwrap()];
    // `client` deliberately reuses its pooled DoH connection opened before this
    // change: open connections get per-request 403, new ones close before TLS.
    assert_eq!(
        admin
            .put(format!("{base}/api/v1/config"))
            .bearer_auth("encrypted-ingress-test-token-16")
            .header("If-Match", tag)
            .json(&policy)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        client
            .post(&endpoint)
            .header("X-Real-IP", "::1")
            .header("Content-Type", "application/dns-message")
            .body(query("ads.test"))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    // Fresh encrypted DNS connections from the now non-admitted source close
    // before a handshake; the management API is never filtered by DNS admission.
    let fresh = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_pem(cert.pem().as_bytes()).unwrap())
        .resolve("dns.test", doh)
        .build()
        .unwrap();
    assert!(
        fresh
            .post(&endpoint)
            .header("Content-Type", "application/dns-message")
            .body(query("ads.test"))
            .send()
            .await
            .is_err()
    );
    let mut closed = tokio::net::TcpStream::connect(dot).await.unwrap();
    let mut byte = [0; 1];
    let read = tokio::time::timeout(Duration::from_secs(2), closed.read(&mut byte))
        .await
        .unwrap(); // Elapsed means the non-admitted DoT peer was held open.
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
    let management = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_pem(cert.pem().as_bytes()).unwrap())
        .resolve("dns.test", config.api_listen)
        .build()
        .unwrap();
    assert_eq!(
        management
            .get(format!("{base}/api/v1/auth/info"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
}
#[test]
fn insecure_keys_invalid_hosts_missing_or_mismatched_certificates_are_rejected() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let directory = tempfile::tempdir().unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let wrong = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["dns.test".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let mut certificate = Certificate {
        cert_file: directory.path().join("cert.pem"),
        key_file: directory.path().join("key.pem"),
        hostnames: vec!["*.test".into()],
    };
    assert!(certificate.validate().is_err());
    certificate.hostnames = vec!["dns.test".into()];
    assert!(certificate.load(true).is_err());
    std::fs::write(&certificate.cert_file, cert.pem()).unwrap();
    std::fs::write(&certificate.key_file, wrong.serialize_pem()).unwrap();
    std::fs::set_permissions(
        &certificate.key_file,
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(certificate.load(true).is_err());
    std::fs::write(&certificate.key_file, key.serialize_pem()).unwrap();
    assert!(certificate.load(true).is_ok());
    std::fs::set_permissions(
        &certificate.key_file,
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(certificate.load(true).is_err());
    let mut config = Config {
        api_listen: "0.0.0.0:8080".parse().unwrap(),
        ..Default::default()
    };
    assert!(config.validate_settings().is_err());
    config.api_tls = Some(certificate);
    assert!(config.validate_settings().is_ok());
    config.dot = Some(DnsListener {
        listen: config.dns_listen,
        certificate: config.api_tls.clone().unwrap(),
        max_connections: 4,
    });
    assert!(config.validate_settings().is_err());
}
