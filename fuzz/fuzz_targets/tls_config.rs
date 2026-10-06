#![no_main]
use libfuzzer_sys::fuzz_target;
use rustwalld_dns_resolver::{Forwarder, UpstreamTransport};
use std::{net::SocketAddr, time::Duration};
fuzz_target!(|data: &[u8]| {
    if data.len() > 65536 {
        return;
    }
    if let Ok(pem) = std::str::from_utf8(data) {
        let transport = UpstreamTransport::Tls {
            server_name: "resolver.test".into(),
            ca_pem: Some(pem.into()),
            max_connections: 1,
        };
        let _ = Forwarder::with_transport(
            vec![SocketAddr::from(([127, 0, 0, 1], 853))],
            Duration::from_secs(1),
            &transport,
        );
    }
});
