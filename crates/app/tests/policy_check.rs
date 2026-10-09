#![allow(clippy::unwrap_used)]
use rustwalld_dns::config::{Config, FilterFile};
use rustwalld_dns_filter::{Action, ListInput};
use rustwalld_dns_policy::{Assertion, UpstreamTransport};
use serde_json::Value;
use std::{
    net::{TcpListener, UdpSocket},
    path::Path,
    process::{Command, Output},
};

fn invoke(path: &Path, format: &str, cwd: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rustwalld-dns"))
        .args(["policy", "test", "--config"])
        .arg(path)
        .args(["--format", format])
        .env_remove("RUSTWALLD_API_TOKEN")
        .env("RUST_LOG", "trace")
        .current_dir(cwd)
        .output()
        .unwrap()
}
fn assertion(domain: &str, expected: Action) -> Assertion {
    Assertion {
        client: "127.0.0.1".parse().unwrap(),
        domain: domain.into(),
        expected,
    }
}

#[test]
fn offline_text_json_and_exit_status_report_all_cases_without_runtime_io() {
    let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let cwd = dir.path().join("elsewhere");
    std::fs::create_dir(&cwd).unwrap();
    let dns_tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let dns_udp = UdpSocket::bind(dns_tcp.local_addr().unwrap()).unwrap();
    let api = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_udp = UdpSocket::bind(upstream_tcp.local_addr().unwrap()).unwrap();
    upstream_tcp.set_nonblocking(true).unwrap();
    upstream_udp.set_nonblocking(true).unwrap();
    let database = dir.path().join("state.sqlite");
    let before = b"offline checks must never open or modify this database";
    std::fs::write(&database, before).unwrap();
    std::fs::write(dir.path().join("hosts.txt"), "ads.test\n".repeat(20)).unwrap();
    let mut config = Config {
        database: database.clone(),
        dns_listen: dns_tcp.local_addr().unwrap(),
        api_listen: api.local_addr().unwrap(),
        filter_files: vec![FilterFile {
            policy: "default".into(),
            name: "hosts\u{1b}[31m".into(),
            action: Action::Block,
            path: "hosts.txt".into(),
        }],
        ..Default::default()
    };
    config.policy.upstreams[0].addresses = vec![upstream_tcp.local_addr().unwrap()];
    config.policy.bindings = vec![rustwalld_dns_policy::Binding {
        name: "Work – 内部".into(),
        network: "127.0.0.1/32".parse().unwrap(),
        policy: "default".into(),
        metadata: Some(rustwalld_dns_policy::BindingMetadata {
            group: Some("Work".into()),
            owner: Some("Operator".into()),
            vlan: Some(20),
            tags: vec!["managed".into()],
            note: Some("DHCP reservation".into()),
        }),
    }];
    config.policy.assertions = vec![
        assertion("x.ads.test", Action::Allow),
        assertion("allowed.test", Action::Block),
        assertion("ads.test", Action::Block),
    ];
    let path = dir.path().join("config.toml");
    std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
    let output = invoke(&path, "json", &cwd);
    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["valid"], false);
    assert_eq!(report["assertions"], 3);
    assert_eq!(report["failed"], 2);
    assert_eq!(
        report["results"][0]["trace"]["binding_metadata"]["vlan"],
        20
    );
    assert_eq!(report["results"].as_array().unwrap().len(), 3);
    assert_eq!(report["results"][0]["trace"]["rule"]["total_sources"], 20);
    assert_eq!(
        report["results"][0]["trace"]["rule"]["sources"]
            .as_array()
            .unwrap()
            .len(),
        16
    );
    assert_eq!(
        report["results"][0]["trace"]["rule"]["sources"][0]["list"],
        "hosts\u{1b}[31m"
    );
    let output = invoke(&path, "text", &cwd);
    assert_eq!(output.status.code(), Some(1));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Policy assertions: 1/3 passed"));
    assert!(text.contains("FAIL [1]"));
    assert!(text.contains("FAIL [2]"));
    assert!(text.contains("PASS [3]"));
    assert!(text.contains("Matcher: Suffix"));
    assert!(text.contains("Sources shown: 16 of 20"));
    assert!(text.contains("VLAN label: Some(20)"));
    assert!(text.contains("Operator"));
    assert!(text.contains("hosts\\u{1b}[31m"));
    assert!(!text.contains('\u{1b}'));
    // Correct all failures and check both encrypted profile compilers offline.
    config.policy.assertions[0].expected = Action::Block;
    config.policy.assertions[1].expected = Action::Allow;
    for transport in [
        UpstreamTransport::Udp,
        UpstreamTransport::Tls {
            server_name: "resolver.test".into(),
            ca_pem: None,
            max_connections: 2,
        },
        UpstreamTransport::Https {
            server_name: "resolver.test".into(),
            ca_pem: None,
            max_connections: 2,
            path: "/dns-query".into(),
        },
    ] {
        config.policy.upstreams[0].transport = transport;
        std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
        let output = invoke(&path, "json", &cwd);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["valid"], true);
        assert_eq!(report["failed"], 0);
    }
    assert_eq!(std::fs::read(&database).unwrap(), before);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 4);
    assert_eq!(std::fs::read_dir(&cwd).unwrap().count(), 0);
    assert_eq!(
        upstream_tcp.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let mut packet = [0; 512];
    assert_eq!(
        upstream_udp.recv(&mut packet).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    drop(dns_udp);
}

#[test]
fn invalid_config_and_invalid_cases_have_distinct_machine_readable_outcomes() {
    let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let path = dir.path().join("config.toml");
    for content in ["not toml", "api_listen = '0.0.0.0:8080'"] {
        std::fs::write(&path, content).unwrap();
        let result = invoke(&path, "json", dir.path());
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
        assert!(String::from_utf8_lossy(&result.stderr).contains("policy check could not run"));
    }
    let mut config = Config::default();
    config.policy.upstreams[0].addresses = vec!["127.0.0.1:15354".parse().unwrap()];
    config.policy.assertions = vec![
        assertion("bad..domain", Action::Allow),
        Assertion {
            client: "192.0.2.1".parse().unwrap(),
            domain: "safe.test".into(),
            expected: Action::Allow,
        },
    ];
    std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
    let result = invoke(&path, "json", dir.path());
    assert_eq!(result.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["results"][0]["failure"]["kind"], "invalid_domain");
    assert_eq!(report["results"][0]["trace"], Value::Null);
    assert_eq!(
        report["results"][1]["failure"]["kind"],
        "client_not_permitted"
    );
    assert_eq!(report["results"][1]["permitted"], false);
    config.policy.assertions.clear();
    config.policy.policies[0].lists.push(ListInput {
        name: "malformed".into(),
        action: Action::Block,
        rules: "https://unsupported.test/path".into(),
    });
    std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
    let result = invoke(&path, "json", dir.path());
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn empty_assertions_are_explicit_and_cli_rejects_ambiguous_arguments() {
    let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let path = dir.path().join("config.toml");
    let mut config = Config::default();
    config.policy.upstreams[0].addresses = vec!["127.0.0.1:15354".parse().unwrap()];
    std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
    let result = invoke(&path, "text", dir.path());
    assert_eq!(result.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&result.stdout).contains("No required assertions configured"));
    let result = invoke(&dir.path().join("absent.toml"), "json", dir.path());
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
    for args in [
        vec!["policy", "test"],
        vec![
            "policy",
            "test",
            "--config",
            "config.toml",
            "--format",
            "yaml",
        ],
        vec![
            "--check-config",
            "policy",
            "test",
            "--config",
            "config.toml",
        ],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_rustwalld-dns"))
            .args(args)
            .current_dir(dir.path())
            .env_remove("RUSTWALLD_API_TOKEN")
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
    }
}

#[test]
fn serving_reads_settings_without_requiring_a_valid_seed_policy() {
    let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let path = dir.path().join("config.toml");
    let mut config = Config::default();
    // A self-forwarding upstream: invalid policy, valid listener settings.
    config.policy.upstreams[0].addresses = vec![config.dns_listen];
    std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
    let read = Config::read(&path).unwrap();
    assert!(read.validate_settings().is_ok());
    assert_eq!(
        read.validate().unwrap_err(),
        "upstream points at DNS listener"
    );
    let result = Command::new(env!("CARGO_BIN_EXE_rustwalld-dns"))
        .args(["--check-config", "--config"])
        .arg(&path)
        .env_remove("RUSTWALLD_API_TOKEN")
        .output()
        .unwrap();
    assert!(!result.status.success());
}

#[test]
fn check_config_treats_file_exceptions_as_new_intake() {
    let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let path = dir.path().join("config.toml");
    let mut config = Config::default();
    config.policy.upstreams[0].addresses = vec!["127.0.0.1:15354".parse().unwrap()];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for (days, accepted) in [(6, true), (8, false)] {
        config.policy.policies[0].temporary_exceptions =
            vec![rustwalld_dns_policy::TemporaryException {
                name: "repair".into(),
                domain: "ads.test".into(),
                expires_at: now + days * 86400,
            }];
        std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_rustwalld-dns"))
            .args(["--check-config", "--config"])
            .arg(&path)
            .env_remove("RUSTWALLD_API_TOKEN")
            .output()
            .unwrap();
        assert_eq!(result.status.success(), accepted, "{days} days");
        if !accepted {
            assert!(String::from_utf8_lossy(&result.stderr).contains("more than seven days"));
        }
    }
}
