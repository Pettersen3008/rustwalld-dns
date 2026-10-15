#![no_main]
use libfuzzer_sys::fuzz_target;
use rustwalld_dns_filter::{Action, ListInput};
use rustwalld_dns_policy::{BlockedServices, PolicyConfigSet, PolicySnapshot};
fuzz_target!(|input: &[u8]| {
    if input.len() > 8192 {
        return;
    }
    let Some((&flags, body)) = input.split_first() else {
        return;
    };
    let settings = if body.starts_with(b"{") {
        let Ok(value) = serde_json::from_slice::<BlockedServices>(body) else {
            return;
        };
        value
    } else {
        BlockedServices {
            catalog_version: if flags & 128 == 0 {
                1
            } else if flags & 16 == 0 {
                2
            } else {
                3
            },
            ids: ["youtube", "tiktok", "reddit", "discord"]
                .into_iter()
                .enumerate()
                .filter(|(i, _)| flags & (1 << i) != 0)
                .map(|(_, s)| s.to_owned())
                .collect(),
            schedule: None,
        }
    };
    let mut config = PolicyConfigSet::default();
    config.upstreams[0].addresses = vec!["127.0.0.1:9".parse().unwrap()];
    config.policies[0].blocked_services = Some(settings);
    let text = std::str::from_utf8(body).unwrap_or("");
    if flags & 32 != 0 {
        config.policies[0].lists = vec![ListInput {
            name: if flags & 64 != 0 {
                "@service/forged"
            } else {
                "custom"
            }
            .into(),
            action: Action::Allow,
            rules: text.into(),
            syntax: Default::default(),
        }];
    }
    let Ok(snapshot) = PolicySnapshot::compile(config, 1) else {
        return;
    };
    let inputs = snapshot.config().policies[0].filter_inputs().unwrap();
    let rebuilt = rustwalld_dns_filter::FilterSnapshot::compile(&inputs, 10000, 16384).unwrap();
    for domain in [
        text,
        "www.youtube.com",
        "youtubei.googleapis.com",
        "sub.youtubei.googleapis.com",
        "www.tiktok.com",
        "google.com",
        "discord.gg",
        "www.netflix.com",
        "web.whatsapp.com",
        "api.steampowered.com",
        "api.signal.org",
    ] {
        if let Ok(explanation) = snapshot.explain("127.0.0.1".parse().unwrap(), domain) {
            if let Some(rule) = explanation.decision.rule {
                assert_eq!(
                    rebuilt.rule(rule).unwrap().domain,
                    explanation.rule.unwrap().domain
                );
            }
        }
    }
});
