//! Serializable policy input; compilation produces immutable snapshots.
use crate::{BindingMetadata, FilterSource, TemporaryException};
use ipnet::IpNet;
use rustwalld_dns_filter::{Action, ListInput};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamProfile {
    pub name: String,
    pub addresses: Vec<SocketAddr>,
    pub timeout_ms: u64,
    #[serde(
        default,
        skip_serializing_if = "rustwalld_dns_resolver::UpstreamTransport::is_udp"
    )]
    pub transport: rustwalld_dns_resolver::UpstreamTransport,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    pub name: String,
    pub upstream: String,
    #[serde(default)]
    pub lists: Vec<ListInput>,
    #[serde(default)]
    pub rewrites: Vec<Rewrite>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub temporary_exceptions: Vec<TemporaryException>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rewrite {
    pub domain: String,
    pub addresses: Vec<IpAddr>,
    #[serde(default = "rewrite_ttl")]
    pub ttl: u32,
}
fn rewrite_ttl() -> u32 {
    60
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub network: IpNet,
    pub policy: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<BindingMetadata>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assertion {
    pub client: IpAddr,
    pub domain: String,
    pub expected: Action,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfigSet {
    pub default_policy: String,
    pub policies: Vec<PolicyConfig>,
    pub upstreams: Vec<UpstreamProfile>,
    #[serde(default)]
    pub bindings: Vec<Binding>,
    pub allowed_clients: Vec<IpNet>,
    #[serde(default)]
    pub assertions: Vec<Assertion>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filter_sources: Vec<FilterSource>,
}
impl Default for PolicyConfigSet {
    fn default() -> Self {
        Self {
            default_policy: "default".into(),
            policies: vec![PolicyConfig {
                name: "default".into(),
                upstream: "default".into(),
                lists: vec![],
                rewrites: vec![],
                temporary_exceptions: vec![],
            }],
            upstreams: vec![UpstreamProfile {
                name: "default".into(),
                addresses: vec![
                    SocketAddr::from(([1, 1, 1, 1], 53)),
                    SocketAddr::from(([9, 9, 9, 9], 53)),
                ],
                timeout_ms: 1500,
                transport: rustwalld_dns_resolver::UpstreamTransport::Udp,
            }],
            bindings: vec![],
            allowed_clients: vec![
                IpNet::from(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
                IpNet::from(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
            ],
            assertions: vec![],
            filter_sources: vec![],
        }
    }
}
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid configuration: {0}")]
    Invalid(String),
    #[error(transparent)]
    Filter(#[from] rustwalld_dns_filter::CompileError),
    #[error("required policy assertion failed: {0}")]
    Assertion(String),
}
