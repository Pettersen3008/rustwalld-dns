use rustwalld_dns_policy::PolicyConfigSet;
use std::{io, net::SocketAddr};
/// Host-specific policy checks: download sources, direct self-forwarding to
/// `listen`, and explicit client access for non-loopback listeners.
///
/// # Errors
///
/// A description of the first violated rule.
pub fn validate_policy(config: &PolicyConfigSet, listen: SocketAddr) -> Result<(), String> {
    crate::downloads::validate_config(config)?;
    for profile in &config.upstreams {
        for upstream in &profile.addresses {
            if targets_listener(*upstream, listen) {
                return Err("upstream points at DNS listener".into());
            }
        }
    }
    // Broad client access must be explicit in PolicyConfigSet. Bindings do not grant access.
    if !listen.ip().to_canonical().is_loopback()
        && config
            .allowed_clients
            .iter()
            .all(|n| n.addr().to_canonical().is_loopback())
    {
        return Err("non-loopback DNS requires explicit allowed client CIDRs".into());
    }
    Ok(())
}
/// Direct self-forwarding check. Addresses are compared canonically, so
/// `[::ffff:127.0.0.1]:53` is the IPv4 loopback listener it reaches.
fn targets_listener(upstream: SocketAddr, listen: SocketAddr) -> bool {
    if upstream.port() != listen.port() {
        return false;
    }
    let upstream = upstream.ip().to_canonical();
    let listen = listen.ip().to_canonical();
    if listen.is_unspecified() {
        // A wildcard listener (`0.0.0.0`, or dual-stack `[::]`) serves every
        // local address. Remote resolvers on the same port (1.1.1.1:53) are the
        // normal LAN setup; loopback/unspecified destinations always reach this
        // host. Other local interface addresses cannot be detected here and
        // remain an operator responsibility (indirect loops are also bounded).
        upstream.is_loopback() || upstream.is_unspecified()
    } else {
        upstream == listen || (listen.is_loopback() && upstream.is_loopback())
    }
}
/// Wrap a validation message as an `InvalidInput` I/O error.
pub fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn check(listen: &str, upstream: &str) -> Result<(), String> {
        let mut config = PolicyConfigSet {
            allowed_clients: vec!["192.0.2.0/24".parse().unwrap()],
            ..Default::default()
        };
        config.upstreams[0].addresses = vec![upstream.parse().unwrap()];
        validate_policy(&config, listen.parse().unwrap())
    }

    #[test]
    fn wildcard_listeners_accept_remote_same_port_upstreams() {
        for (listen, upstream) in [
            ("0.0.0.0:53", "1.1.1.1:53"),
            ("0.0.0.0:53", "[2606:4700:4700::1111]:53"),
            ("[::]:53", "9.9.9.9:53"),
            ("[::]:53", "[2620:fe::fe]:53"),
            ("0.0.0.0:53", "127.0.0.1:5353"),
            ("127.0.0.1:53", "192.0.2.53:53"),
            ("192.0.2.1:53", "192.0.2.2:53"),
        ] {
            assert_eq!(check(listen, upstream), Ok(()), "{listen} -> {upstream}");
        }
    }

    #[test]
    fn direct_self_forwarding_is_rejected_canonically() {
        for (listen, upstream) in [
            ("0.0.0.0:53", "127.0.0.1:53"),
            ("0.0.0.0:53", "127.0.0.53:53"),
            ("0.0.0.0:53", "[::1]:53"),
            ("0.0.0.0:53", "[::ffff:127.0.0.1]:53"),
            ("[::]:53", "127.0.0.1:53"),
            ("[::]:53", "[::1]:53"),
            ("127.0.0.1:53", "[::ffff:127.0.0.1]:53"),
            ("127.0.0.1:53", "127.0.0.2:53"),
            ("[::1]:53", "127.0.0.1:53"),
            ("192.0.2.1:53", "192.0.2.1:53"),
            ("192.0.2.1:53", "[::ffff:192.0.2.1]:53"),
            ("[::ffff:192.0.2.1]:53", "192.0.2.1:53"),
        ] {
            assert_eq!(
                check(listen, upstream),
                Err("upstream points at DNS listener".into()),
                "{listen} -> {upstream}"
            );
        }
    }

    #[test]
    fn mapped_loopback_allowed_clients_do_not_count_as_explicit_access() {
        let mut config = PolicyConfigSet {
            allowed_clients: vec!["::ffff:127.0.0.1/128".parse().unwrap()],
            ..Default::default()
        };
        config.upstreams[0].addresses = vec!["192.0.2.53:53".parse().unwrap()];
        assert!(validate_policy(&config, "0.0.0.0:53".parse().unwrap()).is_err());
    }
}
