use super::*;
#[tokio::test]
async fn rewrite_import_activation_dns_recovery_and_rollback_preserve_disabled_state() {
    let harness = Harness::start().await;
    let (address, upstream) = local_dns().await;
    let mut base = harness.state.control.engine().active().config().clone();
    base.upstreams[0].addresses = vec![address];
    let report=rustwalld_dns::migration::preview(rustwalld_dns::migration::Source::Adguard,b"filtering: {rewrites: [{domain: active.home.arpa, answer: 192.0.2.10, enabled: true}, {domain: disabled.home.arpa, answer: 192.0.2.11, enabled: false}]}\n",base).unwrap();
    assert!(report.ready);
    let config = report.config;
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        200
    );
    let generation = harness.state.control.engine().active().generation();
    assert_eq!(harness.dns("active.home.arpa").await.answers.len(), 1);
    assert!(harness.dns("disabled.home.arpa").await.answers.is_empty());
    let explanation: Value = harness
        .get("/api/v1/explain?client=127.0.0.1&domain=disabled.home.arpa")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(explanation["rewrite"], false);
    let boot = harness
        .state
        .control
        .store()
        .bootstrap("ignored".into())
        .await
        .unwrap();
    let recovered =
        PolicySnapshot::compile(serde_json::from_str(&boot.config).unwrap(), boot.active).unwrap();
    let policy = recovered.select("127.0.0.1".parse().unwrap()).policy;
    assert!(policy.has_rewrite("active.home.arpa"));
    assert!(!policy.has_rewrite("disabled.home.arpa"));
    let mut next = config.clone();
    let mut active = next.policies[0].dns_records[0].clone();
    active.domain = "disabled.home.arpa".into();
    next.policies[0].dns_records.push(active);
    assert_eq!(
        harness.send("/api/v1/config", &next, true).await.status(),
        200
    );
    assert_eq!(harness.dns("disabled.home.arpa").await.answers.len(), 1);
    let rollback = reqwest::Client::new()
        .post(format!(
            "{}/api/v1/revisions/{generation}/rollback",
            harness.base
        ))
        .bearer_auth(TOKEN)
        .header("If-Match", current_etag(&harness).await)
        .send()
        .await
        .unwrap();
    assert_eq!(rollback.status(), 200);
    assert!(harness.dns("disabled.home.arpa").await.answers.is_empty());
    upstream.abort();
    harness.shutdown().await;
}

#[tokio::test]
async fn legacy_family_passthrough_survives_durable_recovery_and_rollback() {
    let harness = Harness::start().await;
    let (address, upstream) = local_dns().await;
    let mut base = harness.state.control.engine().active().config().clone();
    base.upstreams[0].addresses = vec![address];
    let report=rustwalld_dns::migration::preview(rustwalld_dns::migration::Source::Adguard,b"schema_version: 25\ndns: {rewrites: [{domain: ads.test, answer: 192.0.2.10}, {domain: ads.test, answer: AAAA}]}\nuser_rules: [ads.test]\n",base).unwrap();
    assert!(report.ready, "{:?}", report.issues);
    let config = report.config;
    assert_eq!(
        harness.send("/api/v1/config", &config, true).await.status(),
        200
    );
    let generation = harness.state.control.engine().active().generation();
    assert_eq!(harness.dns("ads.test").await.answers.len(), 1);
    assert_eq!(
        harness
            .dns_query("ads.test", RecordType::AAAA)
            .await
            .response_code,
        ResponseCode::NXDomain
    );
    let explanation: Value = harness
        .get("/api/v1/explain?client=127.0.0.1&domain=ads.test&qtype=28")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(explanation["rewrite"], false);
    assert_eq!(explanation["decision"]["action"], "block");
    let boot = harness
        .state
        .control
        .store()
        .bootstrap("ignored".into())
        .await
        .unwrap();
    let recovered =
        PolicySnapshot::compile(serde_json::from_str(&boot.config).unwrap(), boot.active).unwrap();
    assert!(recovered.policies()[0].has_rewrite_for("ads.test", RecordType::A));
    assert!(!recovered.policies()[0].has_rewrite_for("ads.test", RecordType::AAAA));
    let mut next = config.clone();
    next.policies[0].dns_records.retain(|record| {
        !matches!(
            record.data,
            rustwalld_dns_policy::LocalData::Passthrough { .. }
        )
    });
    assert_eq!(
        harness.send("/api/v1/config", &next, true).await.status(),
        200
    );
    let empty = harness.dns_query("ads.test", RecordType::AAAA).await;
    assert_eq!(empty.response_code, ResponseCode::NoError);
    assert!(empty.answers.is_empty());
    let rollback = reqwest::Client::new()
        .post(format!(
            "{}/api/v1/revisions/{generation}/rollback",
            harness.base
        ))
        .bearer_auth(TOKEN)
        .header("If-Match", current_etag(&harness).await)
        .send()
        .await
        .unwrap();
    assert_eq!(rollback.status(), 200);
    assert!(harness.state.control.engine().active().generation() > generation);
    assert_eq!(
        harness
            .dns_query("ads.test", RecordType::AAAA)
            .await
            .response_code,
        ResponseCode::NXDomain
    );
    upstream.abort();
    harness.shutdown().await;
}

#[tokio::test]
async fn globally_disabled_rewrite_import_remains_inactive_through_recovery_and_rollback() {
    let harness = Harness::start().await;
    let (address, upstream) = local_dns().await;
    let mut base = harness.state.control.engine().active().config().clone();
    base.upstreams[0].addresses = vec![address];
    let source=b"schema_version: 34\nfiltering: {rewrites_enabled: false, rewrites: [{domain: globally-off.home.arpa, answer: 192.0.2.10, enabled: true}, {domain: ads.test, answer: 192.0.2.11}, {domain: ads.test, answer: AAAA}]}\nuser_rules: [ads.test]\n";
    let report = rustwalld_dns::migration::preview(
        rustwalld_dns::migration::Source::Adguard,
        source,
        base.clone(),
    )
    .unwrap();
    assert!(report.ready, "{:?}", report.issues);
    assert!(
        report
            .config
            .policies
            .iter()
            .all(|policy| policy.dns_records.is_empty())
    );
    assert_eq!(
        harness
            .send("/api/v1/config", &report.config, true)
            .await
            .status(),
        200
    );
    let generation = harness.state.control.engine().active().generation();
    assert!(
        harness
            .dns("globally-off.home.arpa")
            .await
            .answers
            .is_empty()
    );
    for kind in [RecordType::A, RecordType::AAAA] {
        assert_eq!(
            harness.dns_query("ads.test", kind).await.response_code,
            ResponseCode::NXDomain
        );
    }
    let boot = harness
        .state
        .control
        .store()
        .bootstrap("ignored".into())
        .await
        .unwrap();
    let recovered =
        PolicySnapshot::compile(serde_json::from_str(&boot.config).unwrap(), boot.active).unwrap();
    assert!(!recovered.policies()[0].has_rewrite("globally-off.home.arpa"));
    let active_source = std::str::from_utf8(source)
        .unwrap()
        .replace("rewrites_enabled: false", "rewrites_enabled: true");
    let active = rustwalld_dns::migration::preview(
        rustwalld_dns::migration::Source::Adguard,
        active_source.as_bytes(),
        base,
    )
    .unwrap();
    assert!(active.ready);
    assert_eq!(
        harness
            .send("/api/v1/config", &active.config, true)
            .await
            .status(),
        200
    );
    assert_eq!(harness.dns("globally-off.home.arpa").await.answers.len(), 1);
    let rollback = reqwest::Client::new()
        .post(format!(
            "{}/api/v1/revisions/{generation}/rollback",
            harness.base
        ))
        .bearer_auth(TOKEN)
        .header("If-Match", current_etag(&harness).await)
        .send()
        .await
        .unwrap();
    assert_eq!(rollback.status(), 200);
    assert!(
        harness
            .dns("globally-off.home.arpa")
            .await
            .answers
            .is_empty()
    );
    assert_eq!(
        harness.dns("ads.test").await.response_code,
        ResponseCode::NXDomain
    );
    upstream.abort();
    harness.shutdown().await;
}

#[tokio::test]
async fn wildcard_import_real_dns_recovery_and_rollback_keep_concrete_answers() {
    let harness = Harness::start().await;
    let (address, upstream) = local_dns().await;
    let mut base = harness.state.control.engine().active().config().clone();
    base.upstreams[0].addresses = vec![address];
    let report=rustwalld_dns::migration::preview(rustwalld_dns::migration::Source::Adguard,b"schema_version: 34\nfiltering: {rewrites: [{domain: '*.home.arpa', answer: 192.0.2.10}, {domain: '*.deep.home.arpa', answer: 192.0.2.20}]}\n",base).unwrap();
    assert!(report.ready, "{:?}", report.issues);
    assert_eq!(
        harness
            .send("/api/v1/config", &report.config, true)
            .await
            .status(),
        200
    );
    let generation = harness.state.control.engine().active().generation();
    for (domain, last) in [("nas.home.arpa", 10), ("nas.deep.home.arpa", 20)] {
        let reply = harness.dns(domain).await;
        assert_eq!(reply.answers.len(), 1);
        assert_eq!(reply.answers[0].name, reply.queries[0].name().clone());
        assert!(
            matches!(&reply.answers[0].data,hickory_proto::rr::RData::A(ip) if ip.0.octets()[3]==last)
        );
    }
    assert!(harness.dns("home.arpa").await.answers.is_empty());
    assert!(
        harness
            .dns_query("nas.home.arpa", RecordType::AAAA)
            .await
            .answers
            .is_empty()
    );
    let boot = harness
        .state
        .control
        .store()
        .bootstrap("ignored".into())
        .await
        .unwrap();
    let recovered =
        PolicySnapshot::compile(serde_json::from_str(&boot.config).unwrap(), boot.active).unwrap();
    assert!(recovered.policies()[0].has_rewrite("nas.deep.home.arpa"));
    assert!(!recovered.policies()[0].has_rewrite("home.arpa"));
    let mut next = report.config.clone();
    next.policies[0].dns_records[1].data = rustwalld_dns_policy::LocalData::A {
        address: "192.0.2.30".parse().unwrap(),
    };
    assert_eq!(
        harness.send("/api/v1/config", &next, true).await.status(),
        200
    );
    assert!(
        matches!(&harness.dns("nas.deep.home.arpa").await.answers[0].data,hickory_proto::rr::RData::A(ip) if ip.0.octets()[3]==30)
    );
    let rollback = reqwest::Client::new()
        .post(format!(
            "{}/api/v1/revisions/{generation}/rollback",
            harness.base
        ))
        .bearer_auth(TOKEN)
        .header("If-Match", current_etag(&harness).await)
        .send()
        .await
        .unwrap();
    assert_eq!(rollback.status(), 200);
    assert!(harness.state.control.engine().active().generation() > generation);
    assert!(
        matches!(&harness.dns("nas.deep.home.arpa").await.answers[0].data,hickory_proto::rr::RData::A(ip) if ip.0.octets()[3]==20)
    );
    upstream.abort();
    harness.shutdown().await;
}

#[tokio::test]
async fn literal_pattern_addresses_keep_ttl_shadow_answers_and_durable_rollback() {
    let harness = Harness::start().await;
    let (address, upstream) = local_dns().await;
    let mut base = harness.state.control.engine().active().config().clone();
    base.upstreams[0].addresses = vec![address];
    let report=rustwalld_dns::migration::preview(rustwalld_dns::migration::Source::Adguard,b"filtering: {blocked_response_ttl: 17, rewrites_enabled: false}\nuser_rules: ['||private.home.arpa^$dnsrewrite=192.0.2.10', '||private.home.arpa^$dnsrewrite=NOERROR;AAAA;2001:db8::a']\n",base).unwrap();
    assert!(report.ready, "{:?}", report.issues);
    assert_eq!(
        harness
            .send("/api/v1/config", &report.config, true)
            .await
            .status(),
        200
    );
    let generation = harness.state.control.engine().active().generation();
    for domain in [
        "private.home.arpa",
        "nas.private.home.arpa",
        "apps.nas.private.home.arpa",
    ] {
        for kind in [RecordType::A, RecordType::AAAA] {
            let wire = harness.dns_query(domain, kind).await;
            assert_eq!(wire.response_code, ResponseCode::NoError);
            assert_eq!(wire.answers.len(), 1);
            assert_eq!(wire.answers[0].name, wire.queries[0].name().clone());
            assert_eq!(wire.answers[0].ttl, 17);
        }
        assert!(
            harness
                .dns_query(domain, RecordType::TXT)
                .await
                .answers
                .is_empty()
        );
    }
    let boot = harness
        .state
        .control
        .store()
        .bootstrap("ignored".into())
        .await
        .unwrap();
    let recovered =
        PolicySnapshot::compile(serde_json::from_str(&boot.config).unwrap(), boot.active).unwrap();
    assert_eq!(
        recovered.policies()[0]
            .rewrite("nas.private.home.arpa", RecordType::A)
            .unwrap()[0]
            .ttl,
        17
    );
    let mut next = report.config.clone();
    next.policies[0].dns_records[1].data = rustwalld_dns_policy::LocalData::A {
        address: "192.0.2.30".parse().unwrap(),
    };
    assert_eq!(
        harness.send("/api/v1/shadow", &next, false).await.status(),
        200
    );
    assert!(
        matches!(&harness.dns("nas.private.home.arpa").await.answers[0].data,hickory_proto::rr::RData::A(ip) if ip.0.octets()[3]==10)
    );
    assert_eq!(
        harness.send("/api/v1/config", &next, true).await.status(),
        200
    );
    assert!(
        matches!(&harness.dns("nas.private.home.arpa").await.answers[0].data,hickory_proto::rr::RData::A(ip) if ip.0.octets()[3]==30)
    );
    let rollback = reqwest::Client::new()
        .post(format!(
            "{}/api/v1/revisions/{generation}/rollback",
            harness.base
        ))
        .bearer_auth(TOKEN)
        .header("If-Match", current_etag(&harness).await)
        .send()
        .await
        .unwrap();
    assert_eq!(rollback.status(), 200);
    assert!(harness.state.control.engine().active().generation() > generation);
    assert!(
        matches!(&harness.dns("nas.private.home.arpa").await.answers[0].data,hickory_proto::rr::RData::A(ip) if ip.0.octets()[3]==10)
    );
    upstream.abort();
    harness.shutdown().await;
}

#[tokio::test]
async fn imported_address_sets_and_exceptions_keep_dns_shadow_and_durable_rollback() {
    let harness = Harness::start().await;
    let (address, upstream) = local_dns().await;
    let mut base = harness.state.control.engine().active().config().clone();
    base.upstreams[0].addresses = vec![address];
    let source = b"filtering: {blocked_response_ttl: 19}\nuser_rules: ['|pool.home.arpa^$dnsrewrite=192.0.2.10', '|pool.home.arpa|$dnsrewrite=192.0.2.20', '|pool.home.arpa^$dnsrewrite=192.0.2.30', '|pool.home.arpa^$dnsrewrite=2001:db8::10', '@@|pool.home.arpa|$dnsrewrite=NOERROR;A;192.0.2.10', '|cancelled.test^$dnsrewrite=192.0.2.10', '@@|cancelled.test|$dnsrewrite', 'cancelled.test']\n";
    let report =
        rustwalld_dns::migration::preview(rustwalld_dns::migration::Source::Adguard, source, base)
            .unwrap();
    assert!(report.ready, "{:?}", report.issues);
    assert_eq!(
        harness
            .send("/api/v1/config", &report.config, true)
            .await
            .status(),
        200
    );
    let generation = harness.state.control.engine().active().generation();
    let wire = harness.dns("pool.home.arpa").await;
    assert_eq!(wire.response_code, ResponseCode::NoError);
    assert_eq!(wire.answers.len(), 2);
    let addresses: std::collections::BTreeSet<_> = wire
        .answers
        .iter()
        .map(|record| {
            assert_eq!(record.name, wire.queries[0].name().clone());
            assert_eq!(record.ttl, 19);
            match &record.data {
                hickory_proto::rr::RData::A(ip) => ip.0,
                _ => panic!("expected IPv4"),
            }
        })
        .collect();
    assert_eq!(
        addresses,
        ["192.0.2.20".parse().unwrap(), "192.0.2.30".parse().unwrap()]
            .into_iter()
            .collect()
    );
    let v6 = harness.dns_query("pool.home.arpa", RecordType::AAAA).await;
    assert_eq!(v6.answers.len(), 1);
    assert_eq!(v6.answers[0].ttl, 19);
    assert!(
        harness
            .dns_query("pool.home.arpa", RecordType::TXT)
            .await
            .answers
            .is_empty()
    );
    assert_eq!(
        harness.dns("cancelled.test").await.response_code,
        ResponseCode::NXDomain
    );
    let boot = harness
        .state
        .control
        .store()
        .bootstrap("ignored".into())
        .await
        .unwrap();
    let recovered =
        PolicySnapshot::compile(serde_json::from_str(&boot.config).unwrap(), boot.active).unwrap();
    assert_eq!(
        recovered.policies()[0]
            .rewrite("pool.home.arpa", RecordType::A)
            .unwrap()
            .len(),
        2
    );
    assert!(!recovered.policies()[0].has_rewrite("cancelled.test"));
    let mut next = report.config.clone();
    next.policies[0].dns_records[0].data = rustwalld_dns_policy::LocalData::A {
        address: "192.0.2.40".parse().unwrap(),
    };
    assert_eq!(
        harness.send("/api/v1/shadow", &next, false).await.status(),
        200
    );
    assert_eq!(harness.dns("pool.home.arpa").await.answers, wire.answers);
    assert_eq!(
        harness.send("/api/v1/config", &next, true).await.status(),
        200
    );
    let promoted = harness.dns("pool.home.arpa").await;
    assert!(
        matches!(&promoted.answers[0].data,hickory_proto::rr::RData::A(ip) if ip.0.octets()[3]==40)
    );
    let rollback = reqwest::Client::new()
        .post(format!(
            "{}/api/v1/revisions/{generation}/rollback",
            harness.base
        ))
        .bearer_auth(TOKEN)
        .header("If-Match", current_etag(&harness).await)
        .send()
        .await
        .unwrap();
    assert_eq!(rollback.status(), 200);
    assert!(harness.state.control.engine().active().generation() > generation);
    assert_eq!(harness.dns("pool.home.arpa").await.answers, wire.answers);
    assert_eq!(
        harness.dns("cancelled.test").await.response_code,
        ResponseCode::NXDomain
    );
    upstream.abort();
    harness.shutdown().await;
}

#[tokio::test]
async fn bundled_feed_rewrites_preserve_wire_sets_and_durable_rollback() {
    use std::io::{Cursor, Write};
    let harness = Harness::start().await;
    let (address, upstream) = local_dns().await;
    let mut base = harness.state.control.engine().active().config().clone();
    base.upstreams[0].addresses = vec![address];
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("AdGuardHome.yaml", options).unwrap();
    zip.write_all(b"filtering: {blocked_response_ttl: 29}\nfilters: [{id: 7, enabled: true}]\nuser_rules: ['|pool.test^$dnsrewrite=192.0.2.10', '|cancelled.test^$dnsrewrite=192.0.2.10']\n").unwrap();
    zip.start_file("data/filters/7.txt", options).unwrap();
    zip.write_all(b"|pool.test^$dnsrewrite=192.0.2.20\n|pool.test^$dnsrewrite=192.0.2.30\n|pool.test^$dnsrewrite=2001:db8::20\n@@|pool.test|$dnsrewrite=192.0.2.10\n@@|cancelled.test^$dnsrewrite\ncancelled.test\n").unwrap();
    let input = zip.finish().unwrap().into_inner();
    let report =
        rustwalld_dns::migration::preview(rustwalld_dns::migration::Source::Adguard, &input, base)
            .unwrap();
    assert!(report.ready, "{:?}", report.issues);
    assert!(report.config.filter_sources.is_empty());
    assert_eq!(
        harness
            .send("/api/v1/config", &report.config, true)
            .await
            .status(),
        200
    );
    let generation = harness.state.control.engine().active().generation();
    let wire = harness.dns("pool.test").await;
    assert_eq!(wire.response_code, ResponseCode::NoError);
    assert_eq!(wire.answers.len(), 2);
    for record in &wire.answers {
        assert_eq!(record.ttl, 29);
        assert_eq!(record.name, wire.queries[0].name().clone());
    }
    assert!(
        matches!(&wire.answers[0].data,hickory_proto::rr::RData::A(ip) if ip.0.octets()[3]==20)
    );
    assert!(
        matches!(&wire.answers[1].data,hickory_proto::rr::RData::A(ip) if ip.0.octets()[3]==30)
    );
    let v6 = harness.dns_query("pool.test", RecordType::AAAA).await;
    assert!(
        matches!(&v6.answers[0].data,hickory_proto::rr::RData::AAAA(ip) if ip.0.segments()[7]==0x20)
    );
    assert_eq!(v6.answers[0].ttl, 29);
    assert!(
        harness
            .dns_query("pool.test", RecordType::TXT)
            .await
            .answers
            .is_empty()
    );
    assert_eq!(
        harness.dns("cancelled.test").await.response_code,
        ResponseCode::NXDomain
    );
    let boot = harness
        .state
        .control
        .store()
        .bootstrap("ignored".into())
        .await
        .unwrap();
    let recovered =
        PolicySnapshot::compile(serde_json::from_str(&boot.config).unwrap(), boot.active).unwrap();
    assert_eq!(
        recovered.policies()[0]
            .rewrite("pool.test", RecordType::A)
            .unwrap()
            .len(),
        2
    );
    assert!(!recovered.policies()[0].has_rewrite("cancelled.test"));
    let mut next = report.config.clone();
    next.policies[0].dns_records[0].data = rustwalld_dns_policy::LocalData::A {
        address: "192.0.2.40".parse().unwrap(),
    };
    assert_eq!(
        harness.send("/api/v1/shadow", &next, false).await.status(),
        200
    );
    assert_eq!(harness.dns("pool.test").await.answers, wire.answers);
    assert_eq!(
        harness.send("/api/v1/config", &next, true).await.status(),
        200
    );
    assert!(
        matches!(&harness.dns("pool.test").await.answers[0].data,hickory_proto::rr::RData::A(ip) if ip.0.octets()[3]==40)
    );
    let rollback = reqwest::Client::new()
        .post(format!(
            "{}/api/v1/revisions/{generation}/rollback",
            harness.base
        ))
        .bearer_auth(TOKEN)
        .header("If-Match", current_etag(&harness).await)
        .send()
        .await
        .unwrap();
    assert_eq!(rollback.status(), 200);
    assert!(harness.state.control.engine().active().generation() > generation);
    assert_eq!(harness.dns("pool.test").await.answers, wire.answers);
    assert_eq!(
        harness.dns("cancelled.test").await.response_code,
        ResponseCode::NXDomain
    );
    upstream.abort();
    harness.shutdown().await;
}

#[tokio::test]
async fn typed_pattern_import_keeps_wire_values_ttl_shadow_and_durable_rollback() {
    use std::io::{Cursor, Write};
    let harness = Harness::start().await;
    let (address, upstream) = local_dns().await;
    let mut base = harness.state.control.engine().active().config().clone();
    base.upstreams[0].addresses = vec![address];
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("AdGuardHome.yaml", options).unwrap();
    zip.write_all(b"filtering: {blocked_response_ttl: 31}\nfilters: [{id: 8, enabled: true}]\nuser_rules: ['|typed.test^$dnsrewrite=NOERROR;TXT;removed', '|cancelled.test^$dnsrewrite=NOERROR;TXT;removed']\n").unwrap();
    zip.start_file("data/filters/8.txt", options).unwrap();
    zip.write_all(b"|typed.test^$dnsrewrite=NOERROR;TXT;v=spf1 -all;fixture\n|typed.test^$dnsrewrite=NOERROR;PTR;NAS.home.arpa.\n|typed.test^$dnsrewrite=NOERROR;MX;10 MAIL.home.arpa\n|typed.test^$dnsrewrite=NOERROR;SRV;1 2 8443 SERVICE.home.arpa\n@@|typed.test|$dnsrewrite=NOERROR;TXT;removed\n@@|cancelled.test|$dnsrewrite\ncancelled.test\ntyped.test\n").unwrap();
    let report = rustwalld_dns::migration::preview(
        rustwalld_dns::migration::Source::Adguard,
        &zip.finish().unwrap().into_inner(),
        base,
    )
    .unwrap();
    assert!(report.ready, "{:?}", report.issues);
    assert_eq!(report.config.policies[0].dns_records.len(), 4);
    assert_eq!(
        harness
            .send("/api/v1/config", &report.config, true)
            .await
            .status(),
        200
    );
    let generation = harness.state.control.engine().active().generation();
    for kind in [
        RecordType::TXT,
        RecordType::PTR,
        RecordType::MX,
        RecordType::SRV,
    ] {
        let wire = harness.dns_query("typed.test", kind).await;
        assert_eq!(wire.response_code, ResponseCode::NoError);
        assert_eq!(wire.answers.len(), 1);
        assert_eq!(wire.answers[0].ttl, 31);
        assert_eq!(wire.answers[0].name, wire.queries[0].name().clone());
        match &wire.answers[0].data {
            hickory_proto::rr::RData::TXT(text) => {
                assert_eq!(text.txt_data.len(), 1);
                assert_eq!(text.txt_data[0].as_ref(), b"v=spf1 -all;fixture");
            }
            hickory_proto::rr::RData::PTR(target) => {
                assert_eq!(target.0.to_ascii(), "nas.home.arpa.")
            }
            hickory_proto::rr::RData::MX(mx) => {
                assert_eq!(mx.preference, 10);
                assert_eq!(mx.exchange.to_ascii(), "mail.home.arpa.");
            }
            hickory_proto::rr::RData::SRV(srv) => {
                assert_eq!((srv.priority, srv.weight, srv.port), (1, 2, 8443));
                assert_eq!(srv.target.to_ascii(), "service.home.arpa.");
            }
            _ => panic!("unexpected record"),
        }
    }
    for kind in [RecordType::A, RecordType::AAAA, RecordType::CNAME] {
        let wire = harness.dns_query("typed.test", kind).await;
        assert_eq!(wire.response_code, ResponseCode::NoError);
        assert!(wire.answers.is_empty());
    }
    assert_eq!(
        harness.dns("cancelled.test").await.response_code,
        ResponseCode::NXDomain
    );
    let boot = harness
        .state
        .control
        .store()
        .bootstrap("ignored".into())
        .await
        .unwrap();
    let recovered =
        PolicySnapshot::compile(serde_json::from_str(&boot.config).unwrap(), boot.active).unwrap();
    for kind in [
        RecordType::TXT,
        RecordType::PTR,
        RecordType::MX,
        RecordType::SRV,
    ] {
        assert_eq!(
            recovered.policies()[0]
                .rewrite("typed.test", kind)
                .unwrap()
                .len(),
            1
        );
    }
    let original = harness
        .dns_query("typed.test", RecordType::TXT)
        .await
        .answers;
    let mut next = report.config.clone();
    next.policies[0].dns_records[0].data = rustwalld_dns_policy::LocalData::Txt {
        text: "edited".into(),
    };
    assert_eq!(
        harness.send("/api/v1/shadow", &next, false).await.status(),
        200
    );
    assert_eq!(
        harness
            .dns_query("typed.test", RecordType::TXT)
            .await
            .answers,
        original
    );
    assert_eq!(
        harness.send("/api/v1/config", &next, true).await.status(),
        200
    );
    assert!(
        matches!(&harness.dns_query("typed.test",RecordType::TXT).await.answers[0].data,hickory_proto::rr::RData::TXT(txt) if txt.txt_data[0].as_ref()==b"edited")
    );
    let rollback = reqwest::Client::new()
        .post(format!(
            "{}/api/v1/revisions/{generation}/rollback",
            harness.base
        ))
        .bearer_auth(TOKEN)
        .header("If-Match", current_etag(&harness).await)
        .send()
        .await
        .unwrap();
    assert_eq!(rollback.status(), 200);
    assert!(harness.state.control.engine().active().generation() > generation);
    assert_eq!(
        harness
            .dns_query("typed.test", RecordType::TXT)
            .await
            .answers,
        original
    );
    assert_eq!(
        harness.dns("cancelled.test").await.response_code,
        ResponseCode::NXDomain
    );
    upstream.abort();
    harness.shutdown().await;
}

#[tokio::test]
async fn typed_suffix_import_returns_concrete_wire_names_and_recovers_independent_edits() {
    use hickory_proto::rr::RData;
    use std::io::{Cursor, Write};
    let harness = Harness::start().await;
    let (address, upstream) = local_dns().await;
    let mut base = harness.state.control.engine().active().config().clone();
    base.upstreams[0].addresses = vec![address];
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("AdGuardHome.yaml", options).unwrap();
    zip.write_all(b"filtering: {blocked_response_ttl: 31}\nfilters: [{id: 8, enabled: true}]\nuser_rules: ['||typed.test^$dnsrewrite=NOERROR;TXT;removed', '||cancelled.test^$dnsrewrite=NOERROR;TXT;removed']\n").unwrap();
    zip.start_file("data/filters/8.txt", options).unwrap();
    zip.write_all(b"||typed.test^$dnsrewrite=NOERROR;TXT;fixture\n||typed.test^$dnsrewrite=NOERROR;PTR;NAS.home.arpa.\n||typed.test^$dnsrewrite=NOERROR;MX;10 MAIL.home.arpa\n||typed.test^$dnsrewrite=NOERROR;SRV;1 2 8443 SERVICE.home.arpa\n@@||typed.test^$dnsrewrite=NOERROR;TXT;removed\n@@||cancelled.test^$dnsrewrite\n||cancelled.test^\n||typed.test^\n").unwrap();
    let report = rustwalld_dns::migration::preview(
        rustwalld_dns::migration::Source::Adguard,
        &zip.finish().unwrap().into_inner(),
        base,
    )
    .unwrap();
    assert!(report.ready, "{:?}", report.issues);
    assert_eq!(report.config.policies[0].dns_records.len(), 8);
    assert_eq!(
        harness
            .send("/api/v1/config", &report.config, true)
            .await
            .status(),
        200
    );
    let generation = harness.state.control.engine().active().generation();
    // Repeat concrete names to cover warmed decision/cache state too.
    for name in [
        "typed.test",
        "x.typed.test",
        "a.b.typed.test",
        "x.typed.test",
    ] {
        for kind in [
            RecordType::TXT,
            RecordType::PTR,
            RecordType::MX,
            RecordType::SRV,
        ] {
            let wire = harness.dns_query(name, kind).await;
            assert_eq!(wire.response_code, ResponseCode::NoError);
            assert_eq!(wire.answers.len(), 1);
            assert_eq!(wire.answers[0].ttl, 31);
            assert_eq!(wire.answers[0].name, wire.queries[0].name().clone());
            match &wire.answers[0].data {
                RData::TXT(text) => assert_eq!(text.txt_data[0].as_ref(), b"fixture"),
                RData::PTR(target) => assert_eq!(target.0.to_ascii(), "nas.home.arpa."),
                RData::MX(mx) => {
                    assert_eq!(mx.preference, 10);
                    assert_eq!(mx.exchange.to_ascii(), "mail.home.arpa.");
                }
                RData::SRV(srv) => {
                    assert_eq!((srv.priority, srv.weight, srv.port), (1, 2, 8443));
                    assert_eq!(srv.target.to_ascii(), "service.home.arpa.");
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        for kind in [RecordType::A, RecordType::AAAA, RecordType::CNAME] {
            let wire = harness.dns_query(name, kind).await;
            assert_eq!(wire.response_code, ResponseCode::NoError);
            assert!(wire.answers.is_empty());
        }
    }
    assert_eq!(
        harness.dns("child.cancelled.test").await.response_code,
        ResponseCode::NXDomain
    );
    let outside =
        harness.state.control.engine().active().policies()[0].has_rewrite("badtyped.test");
    assert!(!outside);
    let boot = harness
        .state
        .control
        .store()
        .bootstrap("ignored".into())
        .await
        .unwrap();
    let recovered =
        PolicySnapshot::compile(serde_json::from_str(&boot.config).unwrap(), boot.active).unwrap();
    assert_eq!(
        recovered.policies()[0]
            .rewrite("a.b.typed.test", RecordType::TXT)
            .unwrap()
            .len(),
        1
    );
    let original = harness
        .dns_query("x.typed.test", RecordType::TXT)
        .await
        .answers;
    let mut next = report.config.clone();
    // The converted apex and suffix are separate native records.
    next.policies[0].dns_records[1].data = rustwalld_dns_policy::LocalData::Txt {
        text: "edited descendants".into(),
    };
    assert_eq!(
        harness.send("/api/v1/shadow", &next, false).await.status(),
        200
    );
    assert_eq!(
        harness
            .dns_query("x.typed.test", RecordType::TXT)
            .await
            .answers,
        original
    );
    assert_eq!(
        harness.send("/api/v1/config", &next, true).await.status(),
        200
    );
    assert!(
        matches!(&harness.dns_query("x.typed.test", RecordType::TXT).await.answers[0].data, RData::TXT(text) if text.txt_data[0].as_ref()==b"edited descendants")
    );
    assert!(
        matches!(&harness.dns_query("typed.test", RecordType::TXT).await.answers[0].data, RData::TXT(text) if text.txt_data[0].as_ref()==b"fixture")
    );
    let rollback = reqwest::Client::new()
        .post(format!(
            "{}/api/v1/revisions/{generation}/rollback",
            harness.base
        ))
        .bearer_auth(TOKEN)
        .header("If-Match", current_etag(&harness).await)
        .send()
        .await
        .unwrap();
    assert_eq!(rollback.status(), 200);
    assert!(harness.state.control.engine().active().generation() > generation);
    assert_eq!(
        harness
            .dns_query("x.typed.test", RecordType::TXT)
            .await
            .answers,
        original
    );
    upstream.abort();
    harness.shutdown().await;
}

#[tokio::test]
async fn service_binding_alias_import_keeps_root_wire_values_and_durable_descendant_rollback() {
    use hickory_proto::rr::RData;
    use std::io::{Cursor, Write};
    let harness = Harness::start().await;
    let (address, upstream) = local_dns().await;
    let mut base = harness.state.control.engine().active().config().clone();
    base.upstreams[0].addresses = vec![address];
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("AdGuardHome.yaml", options).unwrap();
    zip.write_all(b"filtering: {blocked_response_ttl: 31}\nfilters: [{id: 7, enabled: true}]\nuser_rules: ['||cancelled.test^$dnsrewrite=NOERROR;HTTPS;0 .']\n").unwrap();
    zip.start_file("data/filters/7.txt", options).unwrap();
    zip.write_all(b"||binding.test^$dnsrewrite=NOERROR;HTTPS;0 .\n||binding.test^$dnsrewrite=NOERROR;SVCB;0 ENDPOINT.home.arpa\n@@||cancelled.test^$dnsrewrite\n||cancelled.test^\n").unwrap();
    let report = rustwalld_dns::migration::preview(
        rustwalld_dns::migration::Source::Adguard,
        &zip.finish().unwrap().into_inner(),
        base,
    )
    .unwrap();
    assert!(report.ready, "{:?}", report.issues);
    assert_eq!(report.config.policies[0].dns_records.len(), 4);
    assert_eq!(
        harness
            .send("/api/v1/config", &report.config, true)
            .await
            .status(),
        200
    );
    let generation = harness.state.control.engine().active().generation();
    for name in [
        "binding.test",
        "child.binding.test",
        "a.b.binding.test",
        "child.binding.test",
    ] {
        for kind in [RecordType::HTTPS, RecordType::SVCB] {
            let wire = harness.dns_query(name, kind).await;
            assert_eq!(wire.response_code, ResponseCode::NoError);
            assert_eq!(wire.answers.len(), 1);
            assert_eq!(wire.answers[0].name, wire.queries[0].name().clone());
            assert_eq!(wire.answers[0].ttl, 31);
            let binding = match &wire.answers[0].data {
                RData::HTTPS(value) => &value.0,
                RData::SVCB(value) => value,
                other => panic!("unexpected {other:?}"),
            };
            assert!(binding.svc_params.is_empty());
            assert_eq!(binding.svc_priority, 0);
            if kind == RecordType::HTTPS {
                assert!(binding.target_name.is_root());
            } else {
                assert_eq!(binding.target_name.to_ascii(), "endpoint.home.arpa.");
            }
        }
        for kind in [RecordType::A, RecordType::AAAA, RecordType::CNAME] {
            let wire = harness.dns_query(name, kind).await;
            assert_eq!(wire.response_code, ResponseCode::NoError);
            assert!(wire.answers.is_empty());
        }
    }
    assert_eq!(
        harness.dns("child.cancelled.test").await.response_code,
        ResponseCode::NXDomain
    );
    let boot = harness
        .state
        .control
        .store()
        .bootstrap("ignored".into())
        .await
        .unwrap();
    let recovered =
        PolicySnapshot::compile(serde_json::from_str(&boot.config).unwrap(), boot.active).unwrap();
    assert_eq!(
        recovered.policies()[0]
            .rewrite("a.b.binding.test", RecordType::HTTPS)
            .unwrap()
            .len(),
        1
    );
    let original = harness
        .dns_query("child.binding.test", RecordType::HTTPS)
        .await
        .answers;
    let mut next = report.config.clone();
    next.policies[0].dns_records[1].data = rustwalld_dns_policy::LocalData::Https {
        priority: 2,
        target: "edited.home.arpa".into(),
        params: Default::default(),
    };
    assert_eq!(
        harness.send("/api/v1/shadow", &next, false).await.status(),
        200
    );
    assert_eq!(
        harness
            .dns_query("child.binding.test", RecordType::HTTPS)
            .await
            .answers,
        original
    );
    assert_eq!(
        harness.send("/api/v1/config", &next, true).await.status(),
        200
    );
    assert!(
        matches!(&harness.dns_query("child.binding.test",RecordType::HTTPS).await.answers[0].data,RData::HTTPS(value) if value.svc_priority==2 && value.target_name.to_ascii()=="edited.home.arpa.")
    );
    assert!(
        matches!(&harness.dns_query("binding.test",RecordType::HTTPS).await.answers[0].data,RData::HTTPS(value) if value.svc_priority==0 && value.target_name.is_root())
    );
    let rollback = reqwest::Client::new()
        .post(format!(
            "{}/api/v1/revisions/{generation}/rollback",
            harness.base
        ))
        .bearer_auth(TOKEN)
        .header("If-Match", current_etag(&harness).await)
        .send()
        .await
        .unwrap();
    assert_eq!(rollback.status(), 200);
    assert!(harness.state.control.engine().active().generation() > generation);
    assert_eq!(
        harness
            .dns_query("child.binding.test", RecordType::HTTPS)
            .await
            .answers,
        original
    );
    upstream.abort();
    harness.shutdown().await;
}
#[tokio::test]
async fn service_port_import_survives_edit_removal_and_durable_rollback() {
    use hickory_proto::rr::RData;
    use std::io::{Cursor, Write};
    let harness = Harness::start().await;
    let (address, upstream) = local_dns().await;
    let mut base = harness.state.control.engine().active().config().clone();
    base.upstreams[0].addresses = vec![address];
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("AdGuardHome.yaml", options).unwrap();
    zip.write_all(b"filtering: {blocked_response_ttl: 31}\nfilters: [{id: 7, enabled: true}]\nuser_rules: ['||cancelled.test^$dnsrewrite=NOERROR;HTTPS;1 . port=0']\n").unwrap();
    zip.start_file("data/filters/7.txt", options).unwrap();
    zip.write_all(b"||binding.test^$dnsrewrite=NOERROR;HTTPS;1 . port=0\n||binding.test^$dnsrewrite=NOERROR;SVCB;1 ENDPOINT.home.arpa port=65535\n@@||cancelled.test^$dnsrewrite\n||cancelled.test^\n").unwrap();
    let report = rustwalld_dns::migration::preview(
        rustwalld_dns::migration::Source::Adguard,
        &zip.finish().unwrap().into_inner(),
        base,
    )
    .unwrap();
    assert!(report.ready, "{:?}", report.issues);
    assert_eq!(report.config.policies[0].dns_records.len(), 4);
    assert_eq!(
        harness
            .send("/api/v1/config", &report.config, true)
            .await
            .status(),
        200
    );
    let generation = harness.state.control.engine().active().generation();
    for name in [
        "binding.test",
        "child.binding.test",
        "a.b.binding.test",
        "child.binding.test",
    ] {
        for kind in [RecordType::HTTPS, RecordType::SVCB] {
            let wire = harness.dns_query(name, kind).await;
            assert_eq!(wire.response_code, ResponseCode::NoError);
            assert_eq!(wire.answers.len(), 1);
            assert_eq!(wire.answers[0].name, wire.queries[0].name().clone());
            assert_eq!(wire.answers[0].ttl, 31);
            let binding = match &wire.answers[0].data {
                RData::HTTPS(value) => &value.0,
                RData::SVCB(value) => value,
                other => panic!("unexpected {other:?}"),
            };
            assert_eq!(
                binding.svc_params,
                vec![(
                    hickory_proto::rr::rdata::svcb::SvcParamKey::Port,
                    hickory_proto::rr::rdata::svcb::SvcParamValue::Port(
                        if kind == RecordType::HTTPS { 0 } else { 65535 }
                    )
                )]
            );
            assert_eq!(binding.svc_priority, 1);
            if kind == RecordType::HTTPS {
                assert!(binding.target_name.is_root());
            } else {
                assert_eq!(binding.target_name.to_ascii(), "endpoint.home.arpa.");
            }
        }
        for kind in [RecordType::A, RecordType::AAAA, RecordType::CNAME] {
            let wire = harness.dns_query(name, kind).await;
            assert_eq!(wire.response_code, ResponseCode::NoError);
            assert!(wire.answers.is_empty());
        }
    }
    assert_eq!(
        harness.dns("child.cancelled.test").await.response_code,
        ResponseCode::NXDomain
    );
    let boot = harness
        .state
        .control
        .store()
        .bootstrap("ignored".into())
        .await
        .unwrap();
    let recovered =
        PolicySnapshot::compile(serde_json::from_str(&boot.config).unwrap(), boot.active).unwrap();
    assert_eq!(
        recovered.policies()[0]
            .rewrite("a.b.binding.test", RecordType::HTTPS)
            .unwrap()
            .len(),
        1
    );
    let original = harness
        .dns_query("child.binding.test", RecordType::HTTPS)
        .await
        .answers;
    let mut next = report.config.clone();
    next.policies[0].dns_records[1].data = rustwalld_dns_policy::LocalData::Https {
        priority: 1,
        target: ".".into(),
        params: rustwalld_dns_policy::ServiceParams { port: Some(8443) },
    };
    assert_eq!(
        harness.send("/api/v1/shadow", &next, false).await.status(),
        200
    );
    assert_eq!(
        harness
            .dns_query("child.binding.test", RecordType::HTTPS)
            .await
            .answers,
        original
    );
    assert_eq!(
        harness.send("/api/v1/config", &next, true).await.status(),
        200
    );
    assert!(
        matches!(&harness.dns_query("child.binding.test",RecordType::HTTPS).await.answers[0].data,RData::HTTPS(value) if value.svc_priority==1 && value.svc_params==vec![(hickory_proto::rr::rdata::svcb::SvcParamKey::Port,hickory_proto::rr::rdata::svcb::SvcParamValue::Port(8443))])
    );
    assert!(
        matches!(&harness.dns_query("binding.test",RecordType::HTTPS).await.answers[0].data,RData::HTTPS(value) if value.svc_priority==1 && value.target_name.is_root() && value.svc_params==vec![(hickory_proto::rr::rdata::svcb::SvcParamKey::Port,hickory_proto::rr::rdata::svcb::SvcParamValue::Port(0))])
    );
    if let rustwalld_dns_policy::LocalData::Https { params, .. } =
        &mut next.policies[0].dns_records[1].data
    {
        params.port = None;
    }
    assert_eq!(
        harness.send("/api/v1/config", &next, true).await.status(),
        200
    );
    assert!(
        matches!(&harness.dns_query("child.binding.test",RecordType::HTTPS).await.answers[0].data,RData::HTTPS(value) if value.svc_params.is_empty())
    );
    let rollback = reqwest::Client::new()
        .post(format!(
            "{}/api/v1/revisions/{generation}/rollback",
            harness.base
        ))
        .bearer_auth(TOKEN)
        .header("If-Match", current_etag(&harness).await)
        .send()
        .await
        .unwrap();
    assert_eq!(rollback.status(), 200);
    assert!(harness.state.control.engine().active().generation() > generation);
    assert_eq!(
        harness
            .dns_query("child.binding.test", RecordType::HTTPS)
            .await
            .answers,
        original
    );
    upstream.abort();
    harness.shutdown().await;
}
