#![no_main]
use rustwalld_dns_filter::{Action, ListInput};
use libfuzzer_sys::fuzz_target;
use rustwalld_dns_policy::{DownloadStamp, FilterSource, PolicyConfigSet, PolicySnapshot};
use rustwalld_dns_runtime::downloads::{Validators, sha256, validate_config};

fuzz_target!(|input: &str| {
    if input.len() > 4096 {
        return;
    }
    // Pure parser coverage: never open connections or resolve names.
    if let Ok(value) = http::HeaderValue::from_bytes(input.as_bytes()) {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::ETAG, value.clone());
        headers.insert(http::header::LAST_MODIFIED, value.clone());
        let _ = Validators::from_headers(&headers);
        headers.append(http::header::ETAG, value);
        let _ = Validators::from_headers(&headers);
    }
    let mut lines = input.split('\n');
    let url = lines.next().unwrap_or("");
    let ip = lines
        .next()
        .unwrap_or("")
        .parse()
        .unwrap_or_else(|_| "127.0.0.1".parse().unwrap());
    let ca = lines
        .next()
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let mut config = PolicyConfigSet::default();
    config.upstreams[0].addresses = vec!["127.0.0.1:9".parse().unwrap()];
    config.policies[0].lists = vec![ListInput { syntax: Default::default(),
        name: "remote".into(),
        action: Action::Block,
        rules: "ads.test\n".into(),
    }];
    config.filter_sources = vec![FilterSource {
        policy: "default".into(),
        list: "remote".into(),
        url: url.into(),
        bootstrap_ips: vec![ip],
        ca_pem: ca,
        refresh_interval_secs: match input.as_bytes().first().copied().unwrap_or(0) % 6 {
            0 => None,
            1 => Some(299),
            2 => Some(300),
            3 => Some(86400),
            4 => Some(rustwalld_dns_policy::MAX_REFRESH_INTERVAL),
            _ => Some(u64::MAX),
        },
        download: Some(DownloadStamp {
            retrieved_at: 1,
            sha256: sha256(b"ads.test\n"),
            bytes: 9,
        }),
    }];
    if validate_config(&config).is_ok() {
        assert!(PolicySnapshot::compile(config.clone(), 1).is_ok());
        config.policies[0].lists[0].rules.push_str("edited.test\n");
        assert!(validate_config(&config).is_err());
    }
});
