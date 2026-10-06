use rustwalld_dns_policy::PolicyConfigSet;
use std::{io, net::SocketAddr};
pub fn validate_policy(config: &PolicyConfigSet, listen: SocketAddr) -> Result<(), String> {
    crate::downloads::validate_config(config)?;
    for profile in &config.upstreams {
        for upstream in &profile.addresses {
            if upstream.port() == listen.port()
                && (listen.ip().is_unspecified()
                    || upstream.ip() == listen.ip()
                    || (listen.ip().is_loopback() && upstream.ip().is_loopback()))
            {
                return Err("upstream points at DNS listener".into());
            }
        }
    }
    // Broad client access must be explicit in PolicyConfigSet. Bindings do not grant access.
    if !listen.ip().is_loopback()
        && config
            .allowed_clients
            .iter()
            .all(|n| n.addr().is_loopback())
    {
        return Err("non-loopback DNS requires explicit allowed client CIDRs".into());
    }
    Ok(())
}
pub fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
