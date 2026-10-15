//! Public synthetic corpus replay for the pure lease parser; no file intake or IO.
#![allow(clippy::unwrap_used)]

use rustwalld_dns::integrations::{Device, parse_leases};
use std::net::IpAddr;

macro_rules! seed {
    ($name:literal) => {
        include_str!(concat!("../../../fuzz/seeds/lease_inventory/", $name))
    };
}

fn assert_device(
    device: &Device,
    address: &str,
    name: Option<&str>,
    mac: Option<&str>,
    expires_at: Option<u64>,
) {
    assert_eq!(device.address, address.parse::<IpAddr>().unwrap());
    assert_eq!(device.name.as_deref(), name);
    assert_eq!(device.mac.as_deref(), mac);
    assert_eq!(device.expires_at, expires_at);
}

#[test]
fn mixed_seed_filters_expired_and_preserves_live_fields() {
    let devices = parse_leases(seed!("valid-mixed.leases"), 100).unwrap();
    assert_eq!(devices.len(), 2);
    assert_device(
        &devices[0],
        "192.0.2.3",
        None,
        Some("02:00:00:00:00:03"),
        None,
    );
    assert_device(
        &devices[1],
        "192.0.2.4",
        Some("live"),
        Some("02:00:00:00:00:04"),
        Some(101),
    );
}

#[test]
fn whitespace_and_multibyte_boundary_seeds_preserve_labels() {
    let devices = parse_leases(seed!("valid-whitespace.leases"), 100).unwrap();
    assert_eq!(devices.len(), 1);
    assert_device(&devices[0], "198.51.100.4", Some("appliance"), None, None);

    let devices = parse_leases(seed!("valid-label-256.leases"), 100).unwrap();
    let name = "é".repeat(128);
    assert_eq!(name.len(), 256);
    assert_eq!(devices.len(), 1);
    assert_device(
        &devices[0],
        "203.0.113.5",
        Some(&name),
        Some("02:00:00:00:00:05"),
        Some(101),
    );
}

#[test]
fn invalid_seeds_reach_the_intended_guards() {
    for (text, error) in [
        (
            seed!("invalid-field-count.leases"),
            "unsupported dnsmasq lease format (DHCPv4 only)",
        ),
        (
            seed!("invalid-expiry-overflow.leases"),
            "invalid lease expiry",
        ),
        (seed!("invalid-ipv6.leases"), "invalid DHCPv4 address"),
        (
            seed!("invalid-name-257.leases"),
            "inventory label outside bounds",
        ),
        (
            seed!("invalid-control-label.leases"),
            "inventory label outside bounds",
        ),
        (
            seed!("invalid-expired-address.leases"),
            "invalid DHCPv4 address",
        ),
        (
            seed!("invalid-mac-257.leases"),
            "inventory label outside bounds",
        ),
    ] {
        assert!(text.len() <= 4096);
        assert_eq!(parse_leases(text, 100).err().as_deref(), Some(error));
    }
    // DEL is not ASCII whitespace: the five-field record reaches label validation.
    assert_eq!(
        seed!("invalid-control-label.leases")
            .split_ascii_whitespace()
            .count(),
        5
    );
}

#[test]
fn exact_byte_limit_accepts_a_valid_record_before_refusing_one_extra_byte() {
    let mut text = "0 02:00:00:00:00:01 192.0.2.1 padded *".to_owned();
    text.extend(std::iter::repeat_n(' ', 1024 * 1024 - text.len()));
    assert_eq!(text.len(), 1024 * 1024);
    let devices = parse_leases(&text, 100).unwrap();
    assert_eq!(devices.len(), 1);
    assert_device(
        &devices[0],
        "192.0.2.1",
        Some("padded"),
        Some("02:00:00:00:00:01"),
        None,
    );
    text.push(' ');
    assert_eq!(
        parse_leases(&text, 100).err().as_deref(),
        Some("lease file exceeds 1 MiB")
    );
}

#[test]
fn exact_line_limit_accepts_all_records_before_refusing_one_more() {
    let line = "101 02:00:00:00:00:01 192.0.2.1 bounded *\n";
    let mut text = line.repeat(4096);
    let devices = parse_leases(&text, 100).unwrap();
    assert_eq!(devices.len(), 4096);
    for device in &devices {
        assert_device(
            device,
            "192.0.2.1",
            Some("bounded"),
            Some("02:00:00:00:00:01"),
            Some(101),
        );
    }
    text.push_str(line);
    assert_eq!(
        parse_leases(&text, 100).err().as_deref(),
        Some("lease file exceeds 4096 lines")
    );
}
